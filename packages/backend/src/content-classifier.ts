import { Buffer } from "buffer";

export type ContentClass =
  "JAVASCRIPT" | "HTML" | "JSON" | "XML" | "TEXT" | "SOURCE_MAP" | "BINARY";

export type ContentDescriptor = {
  contentType: string;
  url: string;
  method: string;
  bytes: Uint8Array;
};

const TEXT_EXTENSIONS =
  /\.(?:css|csv|graphql|gql|html?|json|m?js|cjs|map|md|text|txt|xml|ya?ml)$/i;
const BINARY_EXTENSIONS =
  /\.(?:7z|avif|bmp|bz2|class|dmg|eot|exe|gif|gz|ico|jpe?g|mp3|mp4|ogg|otf|pdf|png|rar|tar|tgz|ttf|webm|webp|woff2?|zip)$/i;

export function classifyContent(value: ContentDescriptor): ContentClass {
  const contentType = value.contentType.toLowerCase();
  const path = value.url.toLowerCase().split(/[?#]/, 1)[0] ?? "";
  if (path.endsWith(".map")) return "SOURCE_MAP";
  if (
    /\.(?:m?js|cjs)$/.test(path) ||
    contentType.includes("javascript") ||
    contentType.includes("ecmascript")
  )
    return "JAVASCRIPT";
  if (
    contentType.includes("html") ||
    path.endsWith(".html") ||
    path.endsWith(".htm")
  )
    return "HTML";
  if (contentType.includes("json") || path.endsWith(".json")) return "JSON";
  if (contentType.includes("xml") || path.endsWith(".xml")) return "XML";
  if (
    contentType.startsWith("text/") ||
    contentType.includes("graphql") ||
    contentType.includes("yaml") ||
    TEXT_EXTENSIONS.test(path) ||
    value.method.toUpperCase() === "OPTIONS"
  )
    return "TEXT";
  if (BINARY_EXTENSIONS.test(path)) return "BINARY";
  return sniffUnknown(value.bytes);
}

function sniffUnknown(bytes: Uint8Array): ContentClass {
  const sample = bytes.subarray(0, Math.min(bytes.length, 8_192));
  if (sample.length === 0) return "TEXT";
  let controls = 0;
  for (const byte of sample) {
    if (byte === 0) return "BINARY";
    if (byte < 32 && byte !== 9 && byte !== 10 && byte !== 12 && byte !== 13)
      controls += 1;
  }
  if (controls / sample.length > 0.01) return "BINARY";
  const text = Buffer.from(sample).toString("utf8").trimStart();
  if (/^(?:<!doctype\s+html|<html\b|<head\b|<body\b)/i.test(text))
    return "HTML";
  if (/^(?:<\?xml\b|<[A-Za-z_][\w:.-]*[\s>])/.test(text)) return "XML";
  if (/^(?:\[|\{)/.test(text)) return "JSON";
  if (
    /^(?:#!.*\n)?\s*(?:import\s|export\s|(?:const|let|var|class|function)\s)|=>|sourceMappingURL/.test(
      text,
    )
  )
    return "JAVASCRIPT";
  return "TEXT";
}
