import type {
  Confidence,
  EndpointMetadata,
  EndpointMethod,
  EndpointSource,
} from "./types";

export type EndpointReference = {
  value: string;
  raw: string;
  start: number;
  end: number;
  presentation: string;
  metadata: EndpointMetadata;
  confidence: Confidence;
};

type InvocationContext = {
  method: EndpointMethod;
  source: EndpointSource;
};

const STRING_LITERAL =
  /"((?:\\[\s\S]|[^"\\]){2,4096})"|'((?:\\[\s\S]|[^'\\]){2,4096})'|`((?:\\[\s\S]|[^`\\]){2,4096})`/g;
const ENDPOINT_FILE =
  /\.(?:php|asp|aspx|ashx|asmx|jsp|jspx|do|action|cgi|cfm|html?|json|txt|xml)(?:[?#]|$)/i;
const STATIC_FILE =
  /\.(?:7z|avif|bmp|css|eot|gif|gz|ico|jpe?g|m?js|map|mp3|mp4|ogg|otf|pdf|png|rar|svg|tar|tgz|ttf|webm|webp|woff2?|zip)(?:[?#]|$)/i;
const RELATIVE_ROUTE_HINT =
  /^(?:api|auth|oauth|admin|account|accounts|graphql|graphiql|internal|manage|management|reports?|rest|rpc|search|service|services|session|user|users|v[0-9]+)\//i;
const GENERIC_RELATIVE_ROUTE =
  /^[A-Za-z0-9._~!$&()+,;=:@%{}-]+(?:\/[A-Za-z0-9._~!$&()+,;=:@%{}-]+)+(?:[?#][^\s]*)?$/;
const UNSAFE_SCHEME = /^(?:blob|data|file|javascript|mailto|tel|webpack):/i;
const HTTP_METHOD = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT";
const MODULE_PREFIXES = new Set([
  "@babel",
  "@caido",
  "@codemirror",
  "@lezer",
  "@types",
  "angular",
  "axios",
  "core-js",
  "date-fns",
  "lodash",
  "node",
  "react",
  "regenerator-runtime",
  "rxjs",
  "tslib",
  "vue",
]);

/**
 * Extract endpoint-shaped string literals without evaluating JavaScript. This
 * keeps LinkFinder-style coverage for full, dotted, slash-relative, and file
 * routes while adding import filtering, bounded context inference, canonical
 * route keys, method hints, and sensitive-query redaction for Caido.
 */
export function extractEndpointReferences(
  text: string,
  decode: (value: string) => string,
  assetUrl = "",
): EndpointReference[] {
  const output = new Map<string, EndpointReference>();
  STRING_LITERAL.lastIndex = 0;
  let count = 0;
  for (
    let match = STRING_LITERAL.exec(text);
    match && count < 5_000;
    match = STRING_LITERAL.exec(text)
  ) {
    count += 1;
    const raw = match[1] ?? match[2] ?? match[3] ?? "";
    const quote =
      match[1] !== undefined ? '"' : match[2] !== undefined ? "'" : "`";
    const value = normalize(raw, quote, decode);
    if (value === undefined || isImportSpecifier(text, match.index)) continue;
    const context = inferContext(
      text,
      match.index,
      match.index + match[0].length,
    );
    if (!isEndpoint(value, context.source)) continue;
    const local = match[0].indexOf(raw);
    const start = match.index + Math.max(0, local);
    const described = describeEndpoint(value, assetUrl, context);
    const confidence: Confidence =
      context.source === "LITERAL"
        ? /^(?:https?|wss?):\/\/|^(?:\/|\.\.\/|\.\/)/i.test(value)
          ? "MEDIUM"
          : "LOW"
        : "HIGH";
    output.set(`${context.method}\n${value}`, {
      value,
      raw,
      start,
      end: start + raw.length,
      presentation: described.presentation,
      metadata: described.metadata,
      confidence,
    });
  }
  return [...output.values()];
}

export function describeEndpoint(
  value: string,
  assetUrl: string,
  context: InvocationContext = { method: "ANY", source: "DETECTOR" },
): { presentation: string; metadata: EndpointMetadata } {
  const resolved = resolveTemplateReference(value, assetUrl);
  const presentation = redactEndpoint(resolved);
  return {
    presentation,
    metadata: {
      method: context.method,
      source: context.source,
      scope: endpointScope(resolved, assetUrl),
      parameters: extractParameters(value),
      dynamic: /\{[^}]+\}|(?:^|\/)[:*][A-Za-z_]/.test(value),
      canonical: canonicalizeEndpoint(presentation),
    },
  };
}

function normalize(
  raw: string,
  quote: string,
  decode: (value: string) => string,
): string | undefined {
  let value = decode(raw)
    .trim()
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#(?:39|x27);/gi, "'");
  if (quote === "`")
    value = value.replace(
      /\$\{[^{}\r\n]{1,160}\}/g,
      (_match, offset) => `{${templateName(raw, Number(offset))}}`,
    );
  if (
    value.length < 3 ||
    value.length > 2_048 ||
    value.includes("${") ||
    /[\r\n\0<>]/.test(value)
  )
    return undefined;
  value = value.replace(/[),;]+$/, "");
  return value.length < 3 ? undefined : value;
}

function templateName(raw: string, offset: number): string {
  const expression = raw.slice(offset).match(/^\$\{([^{}\r\n]{1,160})\}/)?.[1];
  const candidate = expression
    ?.split(/[.[]/, 1)[0]
    ?.replace(/[^A-Za-z0-9_-]/g, "")
    .slice(0, 48);
  return candidate === undefined || candidate === "" ? "param" : candidate;
}

function isEndpoint(value: string, source: EndpointSource): boolean {
  if (
    UNSAFE_SCHEME.test(value) ||
    value.startsWith("#") ||
    value.startsWith("@") ||
    value.includes("\\") ||
    /\s/.test(value) ||
    STATIC_FILE.test(value)
  )
    return false;
  if (/^(?:https?|wss?):\/\//i.test(value) || value.startsWith("//"))
    return true;
  if (value.startsWith("/")) return value !== "/" && !value.startsWith("/*");
  if (value.startsWith("./") || value.startsWith("../"))
    return value.length > (value.startsWith("../") ? 3 : 2);
  if (ENDPOINT_FILE.test(value) || RELATIVE_ROUTE_HINT.test(value)) return true;
  if (!GENERIC_RELATIVE_ROUTE.test(value)) return false;
  const first = value.split("/", 1)[0]?.toLowerCase() ?? "";
  if (MODULE_PREFIXES.has(first)) return false;
  if (/^(?:application|audio|font|image|multipart|text|video)\//i.test(value))
    return false;
  return source !== "MARKUP" || !value.startsWith("assets/");
}

function isImportSpecifier(text: string, literalStart: number): boolean {
  const prefix = text.slice(Math.max(0, literalStart - 100), literalStart);
  return /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)$/i.test(prefix);
}

function inferContext(
  text: string,
  literalStart: number,
  literalEnd: number,
): InvocationContext {
  const prefix = text.slice(Math.max(0, literalStart - 260), literalStart);
  const suffix = text.slice(
    literalEnd,
    Math.min(text.length, literalEnd + 260),
  );
  let match = prefix.match(
    new RegExp(
      `(?:router|route|app|server|api)\\s*\\.\\s*(${HTTP_METHOD})\\s*\\(\\s*$`,
      "i",
    ),
  );
  if (match?.[1] !== undefined)
    return { method: method(match[1]), source: "ROUTER" };
  match = prefix.match(
    new RegExp(`axios\\s*\\.\\s*(${HTTP_METHOD})\\s*\\(\\s*$`, "i"),
  );
  if (match?.[1] !== undefined)
    return { method: method(match[1]), source: "AXIOS" };
  match = prefix.match(
    new RegExp(`\\.open\\s*\\(\\s*["'](${HTTP_METHOD})["']\\s*,\\s*$`, "i"),
  );
  if (match?.[1] !== undefined)
    return { method: method(match[1]), source: "XHR" };
  match = prefix.match(/(?:\$|jQuery)\s*\.\s*(getJSON|get|post)\s*\(\s*$/i);
  if (match?.[1] !== undefined)
    return {
      method: match[1].toLowerCase() === "post" ? "POST" : "GET",
      source: "JQUERY",
    };
  if (/(?:\bfetch|globalThis\.fetch|window\.fetch)\s*\(\s*$/i.test(prefix)) {
    const configured = suffix.match(
      new RegExp(
        `^\\s*,\\s*\\{[\\s\\S]{0,220}?\\bmethod\\s*:\\s*["'](${HTTP_METHOD})["']`,
        "i",
      ),
    )?.[1];
    return {
      method: configured === undefined ? "GET" : method(configured),
      source: "FETCH",
    };
  }
  if (/\baxios\s*\(\s*$/i.test(prefix))
    return { method: "GET", source: "AXIOS" };
  if (/\bnew\s+(?:WebSocket|EventSource)\s*\(\s*$/i.test(prefix))
    return { method: "CONNECT", source: "WEBSOCKET" };
  if (/\b(?:href|action|formaction)\s*=\s*$/i.test(prefix))
    return { method: "GET", source: "MARKUP" };
  return { method: "ANY", source: "LITERAL" };
}

function method(value: string): EndpointMethod {
  const normalized = value.toUpperCase();
  return [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "CONNECT",
  ].includes(normalized)
    ? (normalized as EndpointMethod)
    : "ANY";
}

function resolveTemplateReference(value: string, assetUrl: string): string {
  const placeholders: string[] = [];
  const safe = value.replace(/\{([^}]{1,80})\}/g, (_match, name: string) => {
    const token = `__JSH_PARAM_${placeholders.length}__`;
    placeholders.push(name);
    return token;
  });
  try {
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    let output = new URL(safe, assetUrl).toString();
    placeholders.forEach((name, index) => {
      output = output.replace(`__JSH_PARAM_${index}__`, `{${name}}`);
    });
    return output;
  } catch {
    return value;
  }
}

function redactEndpoint(value: string): string {
  return value
    .replace(/((?:https?|wss?):\/\/)[^\s/@]+@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|api[_-]?key|auth|code|credential|key|password|secret|session|sig|signature|token|x-amz-signature)=)[^&#\s]+/gi,
      "$1[REDACTED]",
    );
}

function endpointScope(
  value: string,
  assetUrl: string,
): EndpointMetadata["scope"] {
  try {
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    const endpoint = new URL(value);
    // eslint-disable-next-line compat/compat -- Caido's plugin runtime provides the URL API.
    const source = new URL(assetUrl);
    if (!/^(?:https?|wss?):$/.test(endpoint.protocol)) return "NON_HTTP";
    return endpoint.origin === source.origin ? "SAME_ORIGIN" : "CROSS_ORIGIN";
  } catch {
    return "UNKNOWN";
  }
}

function extractParameters(value: string): string[] {
  const output = new Set<string>();
  for (const match of value.matchAll(/[?&]([^=&#]{1,80})(?:=|&|#|$)/g))
    addParameter(output, match[1] ?? "");
  for (const match of value.matchAll(
    /\{([^}]{1,80})\}|(?:^|\/)[:*]([A-Za-z_][\w-]{0,79})/g,
  ))
    addParameter(output, match[1] ?? match[2] ?? "");
  return [...output].slice(0, 32);
}

function addParameter(output: Set<string>, value: string): void {
  try {
    const decoded = decodeURIComponent(value).trim();
    if (
      /^[A-Za-z_][\w.-]{0,79}$/.test(decoded) ||
      /^[A-Za-z_][\w.-]{0,77}\[\]$/.test(decoded)
    )
      output.add(decoded);
  } catch {
    /* Malformed parameter encodings are ignored. */
  }
}

function canonicalizeEndpoint(value: string): string {
  const withoutFragment = value.split("#", 1)[0] ?? value;
  const [base = "", query = ""] = withoutFragment.split("?", 2);
  const canonicalPath = base
    .replace(/\/:[A-Za-z_][\w-]*/g, "/{param}")
    .replace(
      /\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?=\/|$)/gi,
      "/{id}",
    )
    .replace(
      /\/(?:[0-9]{2,}|[0-9a-f]{16,}|[A-Za-z0-9_-]{24,})(?=\/|$)/g,
      "/{id}",
    );
  const parameters = new Set<string>();
  for (const part of query.split("&")) {
    const name = part.split("=", 1)[0]?.trim().toLowerCase();
    if (name !== undefined && name !== "") parameters.add(name);
  }
  const suffix = [...parameters].sort().join("&");
  return suffix === "" ? canonicalPath : `${canonicalPath}?${suffix}`;
}
