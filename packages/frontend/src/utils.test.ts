// @vitest-environment happy-dom

import { describe, expect, it } from "vitest";

import {
  formatDate,
  hostOf,
  safeMessage,
  statusClass,
  statusLabel,
} from "./utils";

describe("frontend utilities", () => {
  it("formats labels and review classes", () => {
    expect(statusLabel("NEEDS_REVIEW")).toBe("Needs Review");
    expect(statusClass("FALSE_POSITIVE")).toBe("status-FALSE_POSITIVE");
  });

  it("extracts exact hosts without credentials or ports", () => {
    expect(hostOf("https://user:pass@APP.test:8443/app.js")).toBe("app.test");
    expect(hostOf("not a url")).toBe("");
  });

  it("formats valid dates and preserves invalid values", () => {
    expect(formatDate("not-a-date")).toBe("not-a-date");
    expect(formatDate("2026-07-15T10:00:00.000Z")).not.toBe("");
  });

  it("normalizes unknown errors", () => {
    expect(safeMessage(new Error("boom"))).toBe("boom");
    expect(safeMessage("failure")).toBe("failure");
  });
});
