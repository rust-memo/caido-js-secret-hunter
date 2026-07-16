import { Buffer } from "buffer";
import { createHash } from "crypto";

import bundledRules from "./default-rules.json";
import {
  describeEndpoint,
  extractEndpointReferences,
} from "./endpoint-extractor";
import type {
  DetectedFinding,
  FindingKind,
  RuleDefinition,
  RulePack,
} from "./types";

const MAX_MATCHES_PER_RULE = 100;
const MAX_DECODED_VIEWS = 500;
const QUOTED = /(['"])(.{8,4096}?)\1/gs;
const BASE64 =
  /(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{20,4092}={0,2})(?=$|[^A-Za-z0-9+/=])/g;

type ContentView = {
  text: string;
  sourceOffset: number;
  sourceLine: number;
  label: string;
};
type CompiledRule = {
  definition: RuleDefinition;
  regex: RegExp;
  allowlist?: RegExp;
  keywords: string[];
};

export const rulePack = bundledRules as RulePack;
const compiledRules = rulePack.rules
  .filter((rule) => rule.enabled !== false && rule.engine !== "LINK_REFERENCE")
  .map(compileRule);
const linkReferenceRule = rulePack.rules.find(
  (rule) => rule.engine === "LINK_REFERENCE" && rule.enabled !== false,
);
const sensitiveConfigurationRules = new Set(
  rulePack.rules
    .filter((rule) => rule.sensitiveValue === true)
    .map((rule) => rule.id),
);

export function scanText(text: string, assetUrl: string): DetectedFinding[] {
  if (text.trim().length === 0) return [];
  const output = new Map<string, DetectedFinding>();
  const views = decodedViews(text);
  for (const rule of compiledRules)
    for (const view of views) scanRule(rule, view, assetUrl, output);
  if (linkReferenceRule !== undefined)
    for (const view of views)
      scanLinkReferences(linkReferenceRule, view, assetUrl, output);
  const findings = suppressGenericEndpointDuplicates([...output.values()]);
  const sensitiveValues = findings
    .filter(
      (finding) =>
        (finding.kind !== "ENDPOINT" && finding.kind !== "CONFIGURATION") ||
        sensitiveConfigurationRules.has(finding.ruleId),
    )
    .map((finding) => finding.rawValue)
    .sort((left, right) => right.length - left.length);
  return findings.map((finding) => ({
    ...finding,
    preview: redactPreview(finding.preview, sensitiveValues),
  }));
}

function scanLinkReferences(
  definition: RuleDefinition,
  view: ContentView,
  assetUrl: string,
  output: Map<string, DetectedFinding>,
): void {
  for (const reference of extractEndpointReferences(
    view.text,
    decodeEscapes,
    assetUrl,
  )) {
    const start = Math.max(0, view.sourceOffset + reference.start);
    const end = Math.max(start, view.sourceOffset + reference.end);
    const valueHash = sha256(reference.value);
    const fingerprint = sha256(
      `${assetUrl}\n${definition.id}\n${start}\n${valueHash}`,
    );
    output.set(`${definition.id}\n${reference.value}\n${start}`, {
      fingerprint,
      valueHash,
      ruleId: definition.id,
      ruleName: definition.name,
      kind: definition.kind,
      severity: definition.severity,
      confidence: reference.confidence,
      assetUrl,
      line:
        view.label === "source"
          ? lineAt(view.text, reference.start)
          : view.sourceLine,
      start,
      end,
      preview: `${view.label} | ${snippet(
        view.text,
        reference.start,
        reference.end,
        reference.raw,
      )}`,
      maskedValue: reference.presentation,
      evidenceHighlight: mask(reference.raw),
      rawValue: reference.value,
      endpoint: reference.metadata,
    });
  }
}

function suppressGenericEndpointDuplicates(
  findings: DetectedFinding[],
): DetectedFinding[] {
  const generic = new Map<string, DetectedFinding>();
  for (const finding of findings) {
    if (finding.ruleId !== "javascript-link-reference") continue;
    const current = generic.get(finding.valueHash);
    if (
      current === undefined ||
      (current.endpoint?.source === "LITERAL" &&
        finding.endpoint?.source !== "LITERAL")
    )
      generic.set(finding.valueHash, finding);
  }
  const specific = new Set(
    findings
      .filter(
        (finding) =>
          finding.ruleId !== "javascript-link-reference" &&
          (finding.kind === "ENDPOINT" || finding.kind === "CONFIGURATION"),
      )
      .map((finding) => finding.valueHash),
  );
  return findings
    .filter(
      (finding) =>
        finding.ruleId !== "javascript-link-reference" ||
        !specific.has(finding.valueHash),
    )
    .map((finding) => {
      const context = generic.get(finding.valueHash);
      return finding.ruleId !== "javascript-link-reference" &&
        finding.kind === "ENDPOINT" &&
        context?.endpoint !== undefined
        ? {
            ...finding,
            maskedValue: context.maskedValue,
            endpoint: context.endpoint,
          }
        : finding;
    });
}

function scanRule(
  rule: CompiledRule,
  view: ContentView,
  assetUrl: string,
  output: Map<string, DetectedFinding>,
) {
  const lower = view.text.toLowerCase();
  if (
    rule.keywords.length > 0 &&
    !rule.keywords.some((keyword) => lower.includes(keyword))
  )
    return;
  rule.regex.lastIndex = 0;
  let count = 0;
  for (
    let match = rule.regex.exec(view.text);
    match && count < MAX_MATCHES_PER_RULE;
    match = rule.regex.exec(view.text)
  ) {
    count += 1;
    const group = rule.definition.secretGroup ?? 1;
    const captured = match[group];
    if (captured === undefined) continue;
    const raw = captured;
    const value = raw.trim();
    if (value.length < (rule.definition.minLength ?? 0)) continue;
    if (rule.allowlist !== undefined && rule.allowlist.test(value)) {
      rule.allowlist.lastIndex = 0;
      continue;
    }
    if (
      (rule.definition.minEntropy ?? 0) > 0 &&
      shannonEntropy(value) < (rule.definition.minEntropy ?? 0)
    )
      continue;

    const groupOffset = match[0].indexOf(raw);
    const leadingWhitespace = raw.length - raw.trimStart().length;
    const localStart =
      match.index + Math.max(0, groupOffset) + leadingWhitespace;
    const localEnd = localStart + value.length;
    const start = Math.max(0, view.sourceOffset + localStart);
    const end = Math.max(start, view.sourceOffset + localEnd);
    const valueHash = sha256(value);
    const fingerprint = sha256(
      `${assetUrl}\n${rule.definition.id}\n${start}\n${valueHash}`,
    );
    const endpoint =
      rule.definition.kind === "ENDPOINT"
        ? describeEndpoint(value, assetUrl)
        : undefined;
    output.set(`${rule.definition.id}\n${value}\n${start}`, {
      fingerprint,
      valueHash,
      ruleId: rule.definition.id,
      ruleName: rule.definition.name,
      kind: rule.definition.kind,
      severity: rule.definition.severity,
      confidence: rule.definition.confidence,
      assetUrl,
      line:
        view.label === "source"
          ? lineAt(view.text, localStart)
          : view.sourceLine,
      start,
      end,
      preview: `${view.label} | ${snippet(view.text, localStart, localEnd, value)}`,
      maskedValue:
        endpoint?.presentation ??
        (rule.definition.sensitiveValue === true
          ? mask(value)
          : maskForKind(value, rule.definition.kind)),
      evidenceHighlight: mask(value),
      rawValue: value,
      endpoint: endpoint?.metadata,
    });
    if (rule.regex.lastIndex === match.index) rule.regex.lastIndex += 1;
  }
}

function compileRule(definition: RuleDefinition): CompiledRule {
  if (definition.regex === undefined)
    throw new Error(`Regex rule '${definition.id}' has no pattern`);
  const regex = compileJavaPattern(definition.regex, true);
  const allowlist =
    definition.allowlistRegex === undefined
      ? undefined
      : compileJavaPattern(definition.allowlistRegex, false);
  return {
    definition,
    regex,
    allowlist,
    keywords: (definition.keywords ?? []).map((keyword) =>
      keyword.toLowerCase(),
    ),
  };
}

function compileJavaPattern(source: string, global: boolean): RegExp {
  let pattern = source;
  const flags = new Set(global ? ["g"] : []);
  const inline = pattern.match(/^\(\?([ims]+)\)/);
  if (inline?.[1] !== undefined) {
    pattern = pattern.slice(inline[0].length);
    for (const flag of inline[1]) flags.add(flag);
  }
  return new RegExp(pattern, [...flags].join(""));
}

function decodedViews(text: string): ContentView[] {
  const views: ContentView[] = [
    { text, sourceOffset: 0, sourceLine: 1, label: "source" },
  ];
  const seen = new Set<string>();
  const decodedSource = decodeEscapes(text);
  if (decodedSource !== text && !seen.has(decodedSource)) {
    seen.add(decodedSource);
    views.push({
      text: decodedSource,
      sourceOffset: 0,
      sourceLine: 1,
      label: "decoded-source",
    });
  }

  QUOTED.lastIndex = 0;
  for (
    let match = QUOTED.exec(text);
    match && views.length < MAX_DECODED_VIEWS;
    match = QUOTED.exec(text)
  ) {
    const raw = match[2] ?? "";
    const decoded = decodeEscapes(raw);
    if (decoded !== raw && !seen.has(decoded)) {
      seen.add(decoded);
      const offset = match.index + match[0].indexOf(raw);
      views.push({
        text: decoded,
        sourceOffset: offset,
        sourceLine: lineAt(text, offset),
        label: "decoded-js-string",
      });
    }
  }

  BASE64.lastIndex = 0;
  for (
    let match = BASE64.exec(text);
    match && views.length < MAX_DECODED_VIEWS;
    match = BASE64.exec(text)
  ) {
    const candidate = match[1] ?? "";
    try {
      const bytes = Buffer.from(candidate, "base64");
      if (bytes.length < 8 || bytes.length > 64 * 1024) continue;
      const decoded = bytes.toString("utf8");
      if (printableRatio(decoded) >= 0.85 && !seen.has(decoded)) {
        seen.add(decoded);
        const offset = match.index + match[0].indexOf(candidate);
        views.push({
          text: decoded,
          sourceOffset: offset,
          sourceLine: lineAt(text, offset),
          label: "decoded-base64",
        });
      }
    } catch {
      /* Invalid Base64 is not a finding. */
    }
  }
  return views;
}

export function decodeEscapes(value: string): string {
  let output = "";
  for (let index = 0; index < value.length; index += 1) {
    const current = value[index] ?? "";
    if (current !== "\\" || index + 1 >= value.length) {
      output += current;
      continue;
    }
    const next = value[index + 1] ?? "";
    index += 1;
    if (next === "n") output += "\n";
    else if (next === "r") output += "\r";
    else if (next === "t") output += "\t";
    else if (["\\", "/", "'", '"'].includes(next)) output += next;
    else if (next === "x" || next === "u") {
      const length = next === "x" ? 2 : 4;
      const hex = value.slice(index + 1, index + 1 + length);
      if (hex.length === length && /^[0-9a-f]+$/i.test(hex)) {
        output += String.fromCharCode(Number.parseInt(hex, 16));
        index += length;
      } else output += `\\${next}`;
    } else output += `\\${next}`;
  }
  return output;
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value)
    counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function printableRatio(value: string): number {
  if (value.length === 0) return 0;
  let printable = 0;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (
      character === "\n" ||
      character === "\r" ||
      character === "\t" ||
      (code >= 32 && code < 127)
    )
      printable += 1;
  }
  return printable / value.length;
}

function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let index = 0; index < Math.min(offset, text.length); index += 1)
    if (text[index] === "\n") line += 1;
  return line;
}

function snippet(
  text: string,
  start: number,
  end: number,
  value: string,
): string {
  const from = Math.max(0, start - 100);
  const to = Math.min(text.length, end + 120);
  const context = text
    .slice(from, to)
    .replace(/\s+/g, " ")
    .split(value)
    .join(mask(value));
  return context.length <= 500 ? context : `${context.slice(0, 500)}…`;
}

function maskForKind(value: string, kind: FindingKind): string {
  if (kind === "ENDPOINT" || kind === "CONFIGURATION")
    return redactUrlValue(value);
  return mask(value);
}

function redactPreview(value: string, sensitiveValues: string[]): string {
  let output = value
    .replace(
      /^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):.*$/gim,
      "$1: [REDACTED]",
    )
    .replace(/((?:https?|wss?):\/\/)[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|api[_-]?key|auth|code|credential|key|password|secret|session|sig|signature|token|x-amz-signature)=)[^&#\s]+/gi,
      "$1[REDACTED]",
    );
  for (const secret of sensitiveValues)
    if (secret.length > 0) output = output.split(secret).join(mask(secret));
  return output;
}

function redactUrlValue(value: string): string {
  return value
    .replace(/((?:https?|wss?):\/\/)[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|api[_-]?key|auth|code|credential|key|password|secret|session|sig|signature|token|x-amz-signature)=)[^&#\s]+/gi,
      "$1[REDACTED]",
    );
}

function mask(value: string): string {
  if (value.length <= 8) return "[REDACTED]";
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
