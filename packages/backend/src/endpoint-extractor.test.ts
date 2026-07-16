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
      confidence: "MEDIUM",
      presentation: "https://app.example.test/assets/customers/export",
      metadata: {
        precisionScore: 67,
        signals: expect.arrayContaining([
          "Application route vocabulary",
          "REST-style resource",
        ]),
      },
    });
  });

  it("suppresses dependency, localization, UI, and generated asset paths", () => {
    const references = extractEndpointReferences(
      [
        'const locale = "en/messages";',
        'const icon = "icons/home";',
        'const chunk = "/assets/chunks/runtime";',
        'const weakModule = "feature/module";',
        'const lazy = import(/* webpackChunkName: "admin" */ "features/admin-panel");',
        'const resolved = require.resolve("company/shared-helper");',
        'jest.mock("client/testing-utils");',
        'define(["vendor/plugin", "framework/runtime"], factory);',
        'const customer = "customers/profile";',
        'const endpointUrl = "billing/portal";',
        'fetch("feature/module");',
      ].join("\n"),
      decode,
      "https://app.example.test/assets/app.js",
    );

    expect(references.map((reference) => reference.value)).toEqual(
      expect.arrayContaining([
        "customers/profile",
        "billing/portal",
        "feature/module",
      ]),
    );
    for (const noise of [
      "en/messages",
      "icons/home",
      "/assets/chunks/runtime",
      "features/admin-panel",
      "company/shared-helper",
      "client/testing-utils",
      "vendor/plugin",
      "framework/runtime",
    ])
      expect(references.some((reference) => reference.value === noise)).toBe(
        false,
      );
    expect(
      references.find(
        (reference) =>
          reference.value === "feature/module" &&
          reference.metadata.source === "FETCH",
      ),
    ).toMatchObject({
      confidence: "HIGH",
      metadata: {
        precisionScore: 100,
        signals: expect.arrayContaining(["Fetch call-site"]),
      },
    });
  });

  it("describes unresolved and non-HTTP routes safely", () => {
    expect(describeEndpoint("/api/users", "").metadata.scope).toBe("UNKNOWN");
    expect(
      describeEndpoint("wss://socket.example.test/events", "not a URL").metadata
        .scope,
    ).toBe("UNKNOWN");
  });

  it("holds precision on a mixed application and framework-noise corpus", () => {
    const references = extractEndpointReferences(
      [
        'const api = "/api/v1/users";',
        'const legacy = "../services/report.action?id=7";',
        'const external = "https://api.example.test/catalog";',
        'const graphql = "/graphql";',
        'const profile = "users/profile";',
        'const endpointUrl = "billing/portal";',
        'const download = "/download.php?id=1";',
        "const order = `/orders/${orderId}`;",
        'router.delete("/accounts/:accountId");',
        'fetch("feature/module");',
        'import runtime from "react/jsx-runtime";',
        'const lazy = import(/* webpackChunkName: "settings" */ "features/settings");',
        'const locale = "en/messages";',
        'const icon = "icons/home";',
        'const chunk = "/assets/chunks/runtime";',
        'const weak = "feature/module";',
        'const mime = "text/html";',
        'const imageMime = "image/svg+xml";',
        'const logo = "/assets/logo.svg";',
        'const selector = "div/span";',
        'const theme = "theme/dark";',
        'const vendor = "node_modules/library/runtime";',
        'const generated = "/static/runtime";',
        'const unsafe = "data:text/plain,hello";',
      ].join("\n"),
      decode,
      "https://app.example.test/assets/app.js",
    );
    const values = references.map((reference) => reference.value);

    expect(values).toEqual(
      expect.arrayContaining([
        "/api/v1/users",
        "../services/report.action?id=7",
        "https://api.example.test/catalog",
        "/graphql",
        "users/profile",
        "billing/portal",
        "/download.php?id=1",
        "/orders/{orderId}",
        "/accounts/:accountId",
        "feature/module",
      ]),
    );
    expect(references).toHaveLength(10);
    expect(
      references.filter((reference) => reference.metadata.precisionScore >= 80)
        .length,
    ).toBeGreaterThanOrEqual(6);
  });
});
