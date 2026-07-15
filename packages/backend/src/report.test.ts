import { describe, expect, it } from "vitest";

import { buildReport, redact, type ReportData } from "./report";

describe("redacted reports", () => {
  it("redacts authentication material and sensitive parameters", () => {
    const value = redact(
      "Authorization: Bearer secret\nhttps://alice:password@app.test/?token=abcdefghi",
    );
    expect(value).not.toContain("Bearer secret");
    expect(value).not.toContain("alice:password");
    expect(value).not.toContain("abcdefghi");
  });

  it("escapes HTML and excludes internal IDs", () => {
    const file = buildReport("html", data(), "2026-07-15T10:00:00.000Z");
    expect(file.filename).toContain("2026-07-15T10-00-00-000Z");
    expect(file.content).toContain("Rule library");
    expect(file.content).toContain("&lt;script&gt;");
    expect(file.content).not.toContain("request-1");
    expect(file.content).not.toContain("fingerprint-1");
  });

  it("exports structured JSON without raw values", () => {
    const file = buildReport("json", data(), "2026-07-15T10:00:00.000Z");
    expect(JSON.parse(file.content)).toMatchObject({
      schemaVersion: 1,
      version: "1.1.0",
      generator: "Caido JS Secret Hunter 1.1.0",
      summary: { findings: 1, critical: 1, endpoints: 0 },
    });
    expect(file.content).not.toContain("raw-secret-value");
    expect(file.content).not.toContain("request-1");
  });

  it("guards CSV cells against formulas", () => {
    const value = data();
    value.findings[0]!.reviewNote = '=HYPERLINK("https://evil.test")';
    expect(buildReport("csv", value).content).toContain("'=HYPERLINK");
  });
});

function data(): ReportData {
  return {
    findings: [
      {
        projectId: "project-1",
        fingerprint: "fingerprint-1",
        requestId: "request-1",
        responseId: "response-1",
        valueHash: "a".repeat(64),
        ruleId: "github-token",
        ruleName: "GitHub token",
        kind: "SECRET",
        severity: "CRITICAL",
        confidence: "HIGH",
        assetUrl: "https://app.test/app.js?token=abcdefghi",
        line: 2,
        start: 10,
        end: 20,
        preview: "<script> token=[REDACTED]",
        maskedValue: "ghp_…1234",
        status: "REVIEWED",
        reviewNote: "rotated",
        published: true,
        createdAt: "2026-07-15T10:00:00.000Z",
      },
    ],
    assets: [
      {
        projectId: "project-1",
        url: "https://app.test/app.js",
        requestId: "request-1",
        parentUrl: "https://app.test/",
        rootUrl: "https://app.test/",
        depth: 0,
        status: "SCANNED",
        detail: "1 candidate",
        updatedAt: "2026-07-15T10:00:00.000Z",
      },
    ],
    rules: [
      {
        id: "github-token",
        name: "GitHub token",
        kind: "SECRET",
        severity: "CRITICAL",
        confidence: "HIGH",
        ignored: false,
      },
    ],
  };
}
