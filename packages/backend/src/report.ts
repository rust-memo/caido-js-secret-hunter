import packageMetadata from "../package.json";

import type {
  AssetDTO,
  FindingDTO,
  ReportFile,
  ReportFormat,
  RuleSummary,
} from "./types";

export type ReportData = {
  findings: FindingDTO[];
  assets: AssetDTO[];
  rules: RuleSummary[];
};

const SENSITIVE_KEY =
  "password|passwd|pwd|token|secret|signature|sig|credential|api[_-]?key|client[_-]?secret|authorization|cookie|session";
const PLUGIN_VERSION = packageMetadata.version;

export function buildReport(
  format: ReportFormat,
  data: ReportData,
  generatedAt = new Date().toISOString(),
): ReportFile {
  const timestamp = generatedAt.replace(/[:.]/g, "-");
  if (format === "html")
    return {
      filename: `caido-js-secret-hunter-${timestamp}.html`,
      mediaType: "text/html;charset=utf-8",
      content: htmlReport(data, generatedAt),
    };
  if (format === "json")
    return {
      filename: `caido-js-secret-hunter-${timestamp}.json`,
      mediaType: "application/json;charset=utf-8",
      content: JSON.stringify(exportable(data, generatedAt), undefined, 2),
    };
  return {
    filename: `caido-js-secret-hunter-findings-${timestamp}.csv`,
    mediaType: "text/csv;charset=utf-8",
    content: csvReport(data.findings),
  };
}

export function redact(value: string): string {
  return value
    .replace(
      /^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):.*$/gim,
      "$1: [REDACTED]",
    )
    .replace(/(https?:\/\/)[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      new RegExp(
        `(${SENSITIVE_KEY})(=|%3d|:\\s*|"\\s*:\\s*")[^&\\s,}"]{3,}`,
        "gi",
      ),
      "$1$2[REDACTED]",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      "[REDACTED_JWT]",
    );
}

function exportable(data: ReportData, generatedAt: string) {
  const actionable = data.findings.filter(
    (finding) => finding.status !== "FALSE_POSITIVE",
  );
  return {
    schemaVersion: 2,
    version: PLUGIN_VERSION,
    generatedAt,
    generator: `Caido JS Secret Hunter ${PLUGIN_VERSION}`,
    notice:
      "Matches are review candidates, not proof that a credential is valid. Raw HTTP, request IDs, internal fingerprints, and raw values are excluded.",
    summary: {
      findings: data.findings.length,
      needsReview: data.findings.filter(
        (finding) => finding.status === "NEEDS_REVIEW",
      ).length,
      reviewed: data.findings.filter((finding) => finding.status === "REVIEWED")
        .length,
      falsePositive: data.findings.filter(
        (finding) => finding.status === "FALSE_POSITIVE",
      ).length,
      critical: actionable.filter((finding) => finding.severity === "CRITICAL")
        .length,
      high: actionable.filter((finding) => finding.severity === "HIGH").length,
      endpoints: data.findings.filter((finding) => finding.kind === "ENDPOINT")
        .length,
      uniqueEndpoints: new Set(
        data.findings
          .filter((finding) => finding.kind === "ENDPOINT")
          .map(
            (finding) =>
              `${finding.endpoint?.method ?? "ANY"} ${finding.endpoint?.canonical ?? finding.maskedValue}`,
          ),
      ).size,
      files: new Set(data.findings.map((finding) => finding.assetUrl)).size,
      assets: data.assets.length,
      enabledRules: data.rules.filter((rule) => rule.enabled !== false).length,
      ignoredRules: data.rules.filter((rule) => rule.ignored).length,
    },
    findings: data.findings.map((finding) => ({
      severity: finding.severity,
      confidence: finding.confidence,
      kind: finding.kind,
      ruleId: finding.ruleId,
      ruleName: redact(finding.ruleName),
      maskedValue: redact(finding.maskedValue),
      assetUrl: redact(finding.assetUrl),
      line: finding.line,
      status: finding.status,
      reviewNote: redact(finding.reviewNote),
      preview: redact(finding.preview),
      valueHash: finding.valueHash,
      published: finding.published,
      createdAt: finding.createdAt,
      endpoint:
        finding.endpoint === undefined
          ? undefined
          : {
              method: finding.endpoint.method,
              source: finding.endpoint.source,
              scope: finding.endpoint.scope,
              parameters: finding.endpoint.parameters,
              dynamic: finding.endpoint.dynamic,
              canonical: redact(finding.endpoint.canonical),
            },
    })),
    assets: data.assets.map((asset) => ({
      url: redact(asset.url),
      parentUrl: redact(asset.parentUrl),
      rootUrl: redact(asset.rootUrl),
      depth: asset.depth,
      status: asset.status,
      detail: redact(asset.detail),
      updatedAt: asset.updatedAt,
    })),
    rules: data.rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      kind: rule.kind,
      severity: rule.severity,
      confidence: rule.confidence,
      enabled: rule.enabled !== false,
      ignored: rule.ignored,
    })),
  };
}

function htmlReport(data: ReportData, generatedAt: string): string {
  const report = exportable(data, generatedAt);
  const findings = report.findings
    .map(
      (finding) =>
        `<tr><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.status)}</td><td>${escapeHtml(finding.ruleName)}</td><td>${escapeHtml(finding.kind)}</td><td>${escapeHtml(finding.endpoint?.method ?? "")}</td><td>${escapeHtml(finding.maskedValue)}</td><td>${escapeHtml(finding.assetUrl)}</td><td>${finding.line}</td><td>${escapeHtml(`${finding.reviewNote}\n${finding.preview}`)}</td></tr>`,
    )
    .join("");
  const rules = report.rules
    .map(
      (rule) =>
        `<tr><td>${escapeHtml(rule.id)}</td><td>${escapeHtml(rule.name)}</td><td>${escapeHtml(rule.kind)}</td><td>${escapeHtml(rule.severity)}</td><td>${rule.ignored ? "Ignored" : rule.enabled ? "Enabled" : "Disabled"}</td></tr>`,
    )
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>Caido JS Secret Hunter Report</title><style>body{font:14px system-ui;margin:32px;color:#17202a}h1{color:#9f1239}table{border-collapse:collapse;width:100%;margin:16px 0 32px}th,td{border:1px solid #cbd5e1;padding:7px;text-align:left;vertical-align:top;white-space:pre-wrap}th{background:#1e293b;color:white}.notice{padding:12px;background:#fff7ed;border:1px solid #fdba74}.metrics{display:flex;gap:16px;flex-wrap:wrap;font-weight:600}</style></head><body><h1>Caido JS Secret Hunter Report</h1><p>Generated ${escapeHtml(generatedAt)} by Caido JS Secret Hunter ${escapeHtml(PLUGIN_VERSION)}.</p><p class="notice">Matches are review candidates, not proof that a credential is valid. Raw HTTP, request IDs, internal fingerprints, and raw values are excluded.</p><h2>Summary</h2><p class="metrics"><span>${report.summary.findings} findings</span><span>${report.summary.needsReview} need review</span><span>${report.summary.critical} critical</span><span>${report.summary.high} high</span><span>${report.summary.endpoints} endpoint observations</span><span>${report.summary.uniqueEndpoints} unique routes</span><span>${report.summary.files} sensitive files</span><span>${report.summary.assets} assets</span></p><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Status</th><th>Rule</th><th>Kind</th><th>Method</th><th>Masked value</th><th>Asset</th><th>Line</th><th>Review evidence</th></tr></thead><tbody>${findings}</tbody></table><h2>Rule library</h2><table><thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Severity</th><th>State</th></tr></thead><tbody>${rules}</tbody></table></body></html>`;
}

function csvReport(findings: FindingDTO[]): string {
  const header = [
    "Severity",
    "Confidence",
    "Kind",
    "Rule ID",
    "Rule",
    "Method",
    "Endpoint source",
    "Endpoint scope",
    "Endpoint parameters",
    "Masked value",
    "Asset URL",
    "Line",
    "Status",
    "Review note",
    "Value SHA-256",
    "Evidence",
  ];
  const rows = findings.map((finding) => [
    finding.severity,
    finding.confidence,
    finding.kind,
    finding.ruleId,
    redact(finding.ruleName),
    finding.endpoint?.method ?? "",
    finding.endpoint?.source ?? "",
    finding.endpoint?.scope ?? "",
    finding.endpoint?.parameters.join(" ") ?? "",
    redact(finding.maskedValue),
    redact(finding.assetUrl),
    finding.line,
    finding.status,
    redact(finding.reviewNote),
    finding.valueHash,
    redact(finding.preview),
  ]);
  return `${header.map(csvCell).join(",")}\n${rows
    .map((row) => row.map(csvCell).join(","))
    .join("\n")}`;
}

function csvCell(value: unknown): string {
  let raw = "";
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    raw = String(value);
  } else if (value !== undefined && value !== null) {
    raw = JSON.stringify(value) ?? "";
  }
  const safe = /^[=+@-]/.test(raw.trimStart()) ? `'${raw}` : raw;
  return `"${safe.replace(/"/g, '""')}"`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
