import { Buffer } from "buffer";

import { describe, expect, it } from "vitest";

import { decodeEscapes, rulePack, scanText, shannonEntropy } from "./detector";

describe("Caido JS Secret Hunter detector", () => {
  it("loads and compiles every bundled rule", () => {
    expect(rulePack.rules).toHaveLength(41);
    expect(rulePack.version).toBe("2026.07.3");
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
        "/users/{param}/profile",
      ]),
    );
    expect(links.some((finding) => finding.rawValue.includes("logo.svg"))).toBe(
      false,
    );
    expect(
      links.some((finding) => finding.rawValue.includes("jsx-runtime")),
    ).toBe(false);
  });

  it("prefers a specific endpoint rule over a generic link duplicate", () => {
    const findings = scanText(
      'const users = "/api/v2/users";',
      "https://app.test/app.js",
    );
    expect(findings.some((finding) => finding.ruleId === "api-endpoint")).toBe(
      true,
    );
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
});
