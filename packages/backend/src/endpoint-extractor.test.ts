import { describe, expect, it } from "vitest";

import {
  describeEndpoint,
  extractEndpointReferences,
} from "./endpoint-extractor";

const decode = (value: string) => value.replaceAll("\\/", "/");

describe("endpoint intelligence extraction", () => {
  it("infers methods and call-site sources without executing code", () => {
    const references = extractEndpointReferences(
      [
        'router.patch("/accounts/:accountId");',
        'fetch("/reports/export?format=csv", { method: "POST" });',
        'client.open("DELETE", "/api/users/123456");',
        'new WebSocket("wss://socket.example.test/events");',
        '<a href="/documentation/api">Docs</a>',
      ].join("\n"),
      decode,
      "https://app.example.test/assets/app.js",
    );

    expect(references).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          presentation: "https://app.example.test/accounts/:accountId",
          confidence: "HIGH",
          metadata: expect.objectContaining({
            method: "PATCH",
            source: "ROUTER",
            parameters: ["accountId"],
            dynamic: true,
          }),
        }),
        expect.objectContaining({
          presentation: "https://app.example.test/reports/export?format=csv",
          metadata: expect.objectContaining({
            method: "POST",
            source: "FETCH",
          }),
        }),
        expect.objectContaining({
          metadata: expect.objectContaining({
            method: "DELETE",
            source: "XHR",
          }),
        }),
        expect.objectContaining({
          metadata: expect.objectContaining({
            method: "CONNECT",
            source: "WEBSOCKET",
            scope: "CROSS_ORIGIN",
          }),
        }),
        expect.objectContaining({
          metadata: expect.objectContaining({
            method: "GET",
            source: "MARKUP",
          }),
        }),
      ]),
    );
  });

  it("normalizes templates, redacts sensitive URL data, and builds route keys", () => {
    const [reference] = extractEndpointReferences(
      [
        "const route =",
        "  `https://alice:password@api.example.test/users/${user.id}/orders/123456?token=secret&view=full`;",
      ].join("\n"),
      decode,
      "https://app.example.test/app.js",
    );

    expect(reference).toMatchObject({
      presentation:
        "https://[REDACTED]@api.example.test/users/{user}/orders/123456?token=[REDACTED]&view=full",
      metadata: {
        method: "ANY",
        source: "LITERAL",
        scope: "CROSS_ORIGIN",
        parameters: ["token", "view", "user"],
        dynamic: true,
        canonical:
          "https://[REDACTED]@api.example.test/users/{user}/orders/{id}?token&view",
      },
    });
  });

  it("keeps slash-relative coverage while filtering imports and static noise", () => {
    const references = extractEndpointReferences(
      [
        'const report = "customers/export";',
        'import helper from "company/shared-helper";',
        'const icon = "/assets/icon.svg";',
        'const unsafe = "javascript:alert(1)";',
        'const mime = "application/json";',
      ].join("\n"),
      decode,
      "https://app.example.test/assets/app.js",
    );

    expect(references).toHaveLength(1);
    expect(references[0]).toMatchObject({
      value: "customers/export",
      confidence: "LOW",
      presentation: "https://app.example.test/assets/customers/export",
    });
  });

  it("describes unresolved and non-HTTP routes safely", () => {
    expect(describeEndpoint("/api/users", "").metadata.scope).toBe("UNKNOWN");
    expect(
      describeEndpoint("wss://socket.example.test/events", "not a URL").metadata
        .scope,
    ).toBe("UNKNOWN");
  });
});
