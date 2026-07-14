import { Buffer } from "buffer";

import { describe, expect, it } from "vitest";

import { decodeEscapes, rulePack, scanText, shannonEntropy } from "./detector";

describe("Caido JS Secret Hunter detector", () => {
  it("loads and compiles every bundled rule", () => {
    expect(rulePack.rules).toHaveLength(40);
    expect(rulePack.version).toBe("2026.07.2");
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
  });
});
