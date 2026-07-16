import { Buffer } from "buffer";

import { describe, expect, it } from "vitest";

import { decodeEscapes, rulePack, scanText, shannonEntropy } from "./detector";

describe("Caido JS Secret Hunter detector", () => {
  it("loads and compiles every bundled rule", () => {
    expect(rulePack.rules).toHaveLength(43);
    expect(rulePack.version).toBe("2026.07.4");
  });

  it("detects provider tokens and masks the stored presentation", () => {
    const token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const findings = scanText(
      `window.githubToken = "${token}";`,
      "https://app.test/assets/app.js",
    );
    const finding = findings.find(
      (candidate) => candidate.ruleId === "github-token",
    );
    expect(finding?.rawValue).toBe(token);
    expect(finding?.maskedValue).toBe("ghp_…6789");
    expect(finding?.evidenceHighlight).toBe("ghp_…6789");
    expect(finding?.preview).toContain(finding!.evidenceHighlight);
    expect(finding?.valueHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("supports Java-style case-insensitive rule flags", () => {
    const value = "aB9xK2mQ7pR4vT8zN6cD3fG5hJ1sL0wY";
    const findings = scanText(
      `CLIENT_SECRET = '${value}'`,
      "https://app.test/config.js",
    );
    expect(
      findings.some((finding) => finding.ruleId === "generic-api-secret"),
    ).toBe(true);
  });

  it("detects endpoints in escaped and base64 views", () => {
    const escaped = `const route = "\\/internal\\/debug";`;
    const encoded = Buffer.from("wss://internal.local/socket").toString(
      "base64",
    );
    const findings = scanText(
      `${escaped}\nconst encoded = '${encoded}';`,
      "https://app.test/app.js",
    );
    expect(
      findings.some((finding) => finding.ruleId === "admin-debug-route"),
    ).toBe(true);
    expect(
      findings.some((finding) => finding.ruleId === "websocket-endpoint"),
    ).toBe(true);
  });

  it("filters common placeholder passwords", () => {
    const findings = scanText(
      `const password = "changeme";`,
      "https://app.test/app.js",
    );
    expect(
      findings.some((finding) => finding.ruleId === "hardcoded-password"),
    ).toBe(false);
  });

  it("calculates entropy consistently", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
    expect(shannonEntropy("aB1!zQ9@")).toBeGreaterThan(2.5);
    expect(decodeEscapes("\\u0061\\x62\\/c")).toBe("ab/c");
    expect(decodeEscapes("\\q\\xZZ")).toBe("\\q\\xZZ");
  });

  it("discovers quoted endpoint shapes and filters static noise", () => {
    const findings = scanText(
      [
        'const legacy = "/legacy/search.php?q=test";',
        'const action = "../services/users.action";',
        'const absolute = "https://api.example.test/catalog";',
        "const dynamic = `/users/${userId}/profile`;",
        'const image = "/assets/logo.svg";',
        'const module = "react/jsx-runtime";',
      ].join("\n"),
      "https://app.test/assets/app.js",
    );
    const links = findings.filter(
      (finding) => finding.ruleId === "javascript-link-reference",
    );
    expect(links.map((finding) => finding.maskedValue)).toEqual(
      expect.arrayContaining([
        "https://app.test/legacy/search.php?q=test",
        "https://app.test/services/users.action",
        "https://api.example.test/catalog",
        "https://app.test/users/{userId}/profile",
      ]),
    );
    expect(links.some((finding) => finding.rawValue.includes("logo.svg"))).toBe(
      false,
    );
    expect(
      links.some((finding) => finding.rawValue.includes("jsx-runtime")),
    ).toBe(false);
  });

  it("keeps call-site context when a specific rule replaces a generic duplicate", () => {
    const findings = scanText(
      'fetch("/api/v2/users", { method: "PATCH" });',
      "https://app.test/app.js",
    );
    const endpoint = findings.find(
      (finding) => finding.ruleId === "api-endpoint",
    );
    expect(endpoint).toMatchObject({
      maskedValue: "https://app.test/api/v2/users",
      endpoint: {
        method: "PATCH",
        source: "FETCH",
        scope: "SAME_ORIGIN",
      },
    });
    expect(
      findings.some(
        (finding) => finding.ruleId === "javascript-link-reference",
      ),
    ).toBe(false);
  });

  it("redacts neighboring detected values from every stored preview", () => {
    const github = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const generic = "aB9xK2mQ7pR4vT8zN6cD3fG5hJ1sL0wY";
    const findings = scanText(
      `github_token = "${github}"; client_secret = "${generic}";`,
      "https://app.test/app.js",
    );
    expect(findings.length).toBeGreaterThan(1);
    for (const finding of findings) {
      expect(finding.preview).not.toContain(github);
      expect(finding.preview).not.toContain(generic);
    }
  });

  it("redacts sensitive query parameters in endpoint presentation", () => {
    const findings = scanText(
      `const endpoint = "/api/users?token=supersecretvalue";`,
      "https://app.test/app.js",
    );
    const endpoint = findings.find(
      (finding) => finding.ruleId === "api-endpoint",
    );
    expect(endpoint?.maskedValue).toContain("token=[REDACTED]");
    expect(endpoint?.maskedValue).not.toContain("supersecretvalue");
    expect(endpoint?.preview).not.toContain("supersecretvalue");
  });

  it("redacts signed endpoint parameters from stored previews", () => {
    const signature = "0123456789abcdef0123456789abcdef";
    const finding = scanText(
      `const endpoint = "/download?X-Amz-Signature=${signature}";`,
      "https://app.test/app.js",
    ).find((candidate) => candidate.kind === "ENDPOINT");
    expect(finding?.maskedValue).toContain("X-Amz-Signature=[REDACTED]");
    expect(finding?.preview).not.toContain(signature);
  });

  it("reports the source line for decoded values", () => {
    const encoded = Buffer.from("wss://internal.local/socket").toString(
      "base64",
    );
    const findings = scanText(
      `const first = true;\nconst second = true;\nconst encoded = "${encoded}";`,
      "https://app.test/app.js",
    );
    expect(
      findings.find((finding) => finding.ruleId === "websocket-endpoint")?.line,
    ).toBe(3);
  });

  it("adds method, source, parameter, scope, and canonical route context", () => {
    const findings = scanText(
      [
        'fetch(`/orders/${orderId}?expand=items`, { method: "POST" });',
        'axios.delete("https://api.example.test/users/123456?token=secret&verbose=true");',
      ].join("\n"),
      "https://app.test/assets/app.js",
    );
    const post = findings.find(
      (finding) => finding.endpoint?.method === "POST",
    );
    expect(post).toMatchObject({
      maskedValue: "https://app.test/orders/{orderId}?expand=items",
      confidence: "HIGH",
      endpoint: {
        method: "POST",
        source: "FETCH",
        scope: "SAME_ORIGIN",
        parameters: ["expand", "orderId"],
        dynamic: true,
        canonical: "https://app.test/orders/{orderId}?expand",
      },
    });
    const external = findings.find(
      (finding) => finding.endpoint?.source === "AXIOS",
    );
    expect(external?.maskedValue).toContain("token=[REDACTED]");
    expect(external?.endpoint).toMatchObject({
      method: "DELETE",
      scope: "CROSS_ORIGIN",
      canonical: "https://api.example.test/users/{id}?token&verbose",
    });
  });

  it("covers generic slash-relative LinkFinder routes but ignores imports", () => {
    const findings = scanText(
      [
        'const report = "reports/export";',
        'const profile = "customers/profile";',
        'import runtime from "react/jsx-runtime";',
        'const module = require("company/shared-utils");',
      ].join("\n"),
      "https://app.test/assets/app.js",
    );
    const links = findings.filter(
      (finding) => finding.ruleId === "javascript-link-reference",
    );
    expect(links.map((finding) => finding.maskedValue)).toEqual(
      expect.arrayContaining([
        "https://app.test/assets/reports/export",
        "https://app.test/assets/customers/profile",
      ]),
    );
    expect(links.some((finding) => finding.rawValue.includes("runtime"))).toBe(
      false,
    );
    expect(
      links.some((finding) => finding.rawValue.includes("shared-utils")),
    ).toBe(false);
  });

  it("detects documentation and health endpoints", () => {
    const findings = scanText(
      'const docs = "/openapi.json"; const health = "/healthz";',
      "https://app.test/app.js",
    );
    expect(
      findings.some((finding) => finding.ruleId === "api-documentation-route"),
    ).toBe(true);
    expect(
      findings.some((finding) => finding.ruleId === "health-metrics-route"),
    ).toBe(true);
  });

  it("masks sensitive configuration values before persistence", () => {
    const dsn =
      "https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/42";
    const finding = scanText(
      `window.SENTRY_DSN = "${dsn}";`,
      "https://app.test/app.js",
    ).find((candidate) => candidate.ruleId === "sentry-dsn");
    expect(finding?.maskedValue).toBe("http…o/42");
    expect(finding?.preview).not.toContain(dsn);
  });
});
