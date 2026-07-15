import { describe, expect, it } from "vitest";

import { classifyContent } from "./content-classifier";

describe("response content classification", () => {
  it("honors declared and extension-based text formats", () => {
    expect(
      classifyContent({
        contentType: "application/json",
        url: "https://app.test/data",
        method: "GET",
        bytes: bytes('{"ok":true}'),
      }),
    ).toBe("JSON");
    expect(
      classifyContent({
        contentType: "application/octet-stream",
        url: "https://app.test/app.js",
        method: "GET",
        bytes: bytes("const route = '/api/users';"),
      }),
    ).toBe("JAVASCRIPT");
  });

  it("sniffs extensionless JavaScript served with generic metadata", () => {
    expect(
      classifyContent({
        contentType: "application/octet-stream",
        url: "https://app.test/bundle",
        method: "GET",
        bytes: bytes("export const endpoint = '/reports/export';"),
      }),
    ).toBe("JAVASCRIPT");
  });

  it("rejects binary payloads before text conversion", () => {
    expect(
      classifyContent({
        contentType: "application/octet-stream",
        url: "https://app.test/download",
        method: "GET",
        bytes: new Uint8Array([137, 80, 78, 71, 0, 13, 10, 26]),
      }),
    ).toBe("BINARY");
  });

  it("recognizes common extensionless text formats by content", () => {
    const classify = (value: string) =>
      classifyContent({
        contentType: "application/octet-stream",
        url: "https://app.test/resource",
        method: "GET",
        bytes: bytes(value),
      });
    expect(classify("<!doctype html><html></html>")).toBe("HTML");
    expect(classify('<?xml version="1.0"?><root/>')).toBe("XML");
    expect(classify('[{"route":"/api"}]')).toBe("JSON");
    expect(classify("plain configuration text")).toBe("TEXT");
  });

  it("classifies source maps and OPTIONS responses as text", () => {
    expect(
      classifyContent({
        contentType: "application/octet-stream",
        url: "https://app.test/bundle.js.map?cache=1",
        method: "GET",
        bytes: bytes("{}"),
      }),
    ).toBe("SOURCE_MAP");
    expect(
      classifyContent({
        contentType: "application/octet-stream",
        url: "https://app.test/options",
        method: "OPTIONS",
        bytes: bytes("Allow: GET, POST"),
      }),
    ).toBe("TEXT");
  });
});

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
