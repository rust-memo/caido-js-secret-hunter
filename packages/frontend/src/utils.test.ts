// @vitest-environment happy-dom

import { describe, expect, it } from "vitest";

import {
  correctedPageOffset,
  createRequestGate,
  formatDate,
  highlightSegments,
  hostOf,
  responseBodyRange,
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

  it("rejects stale asynchronous request tokens", () => {
    const gate = createRequestGate();
    const first = gate.start();
    const second = gate.start();
    expect(gate.isCurrent(first)).toBe(false);
    expect(gate.isCurrent(second)).toBe(true);
    gate.invalidate();
    expect(gate.isCurrent(second)).toBe(false);
  });

  it("recovers pagination when a result mutation removes the current page", () => {
    expect(
      correctedPageOffset({ items: [], total: 51, offset: 100, limit: 50 }),
    ).toBe(50);
    expect(
      correctedPageOffset({ items: [], total: 0, offset: 50, limit: 50 }),
    ).toBeUndefined();
    expect(
      correctedPageOffset({ items: [], total: 100, offset: 50, limit: 50 }),
    ).toBe(0);
    expect(
      correctedPageOffset({ items: [{}], total: 51, offset: 50, limit: 50 }),
    ).toBeUndefined();
  });

  it("splits detected evidence for safe text-only highlighting", () => {
    expect(
      highlightSegments(
        'source | api_key="ghp_…6789"; backup="ghp_…6789"',
        "ghp_…6789",
      ),
    ).toEqual([
      { text: 'source | api_key="', highlighted: false },
      { text: "ghp_…6789", highlighted: true },
      { text: '"; backup="', highlighted: false },
      { text: "ghp_…6789", highlighted: true },
      { text: '"', highlighted: false },
    ]);
    expect(highlightSegments("<script>", "missing")).toEqual([
      { text: "<script>", highlighted: false },
    ]);
  });

  it("maps source-aligned findings into raw HTTP response coordinates", () => {
    const response =
      "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\nkey=secret";
    const range = responseBodyRange(response, 4, 10, true);
    expect(range).toBeDefined();
    expect(response.slice(range!.from, range!.to)).toBe("secret");
    expect(responseBodyRange(response, 4, 10, false)).toBeUndefined();
    expect(responseBodyRange(response, 1000, 2000, true)).toBeUndefined();
  });
});
