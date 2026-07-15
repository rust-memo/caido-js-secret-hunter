export type EndpointReference = {
  value: string;
  raw: string;
  start: number;
  end: number;
};

const STRING_LITERAL =
  /"((?:\\[\s\S]|[^"\\]){2,4096})"|'((?:\\[\s\S]|[^'\\]){2,4096})'|`((?:\\[\s\S]|[^`\\]){2,4096})`/g;
const ENDPOINT_FILE =
  /\.(?:php|asp|aspx|ashx|asmx|jsp|jspx|do|action|cgi|json|xml)(?:[?#]|$)/i;
const STATIC_FILE =
  /\.(?:avif|bmp|css|eot|gif|ico|jpe?g|m?js|map|mp3|mp4|ogg|otf|pdf|png|svg|ttf|webm|webp|woff2?)(?:[?#]|$)/i;
const RELATIVE_ROUTE_HINT =
  /^(?:api|auth|oauth|admin|account|accounts|graphql|graphiql|internal|manage|management|rest|rpc|service|services|user|users|v[0-9]+)\//i;
const UNSAFE_SCHEME = /^(?:blob|data|file|javascript|mailto|tel|webpack):/i;

/**
 * Extract endpoint-shaped JavaScript string literals. The approach is inspired
 * by LinkFinder-style passive quoted-link discovery, with stricter filtering
 * for modern Caido traffic and without evaluating JavaScript.
 */
export function extractEndpointReferences(
  text: string,
  decode: (value: string) => string,
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
    if (value === undefined || !isEndpoint(value)) continue;
    const local = match[0].indexOf(raw);
    const start = match.index + Math.max(0, local);
    output.set(value, { value, raw, start, end: start + raw.length });
  }
  return [...output.values()];
}

function normalize(
  raw: string,
  quote: string,
  decode: (value: string) => string,
): string | undefined {
  let value = decode(raw).trim().replace(/&amp;/gi, "&");
  if (quote === "`")
    value = value.replace(/\$\{[^{}\r\n]{1,160}\}/g, "{param}");
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

function isEndpoint(value: string): boolean {
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
  return ENDPOINT_FILE.test(value) || RELATIVE_ROUTE_HINT.test(value);
}
