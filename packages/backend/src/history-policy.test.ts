import { describe, expect, it } from "vitest";

import {
  historyInspectionLimit,
  isAfterHistoryCutoff,
  isHistoryItemInCoverage,
} from "./history-policy";

describe("cleared History policy", () => {
  const cutoff = new Date("2026-07-16T06:00:00.000Z").getTime();

  it("keeps historical responses eligible until results are explicitly cleared", () => {
    expect(isAfterHistoryCutoff(new Date("2020-01-01T00:00:00.000Z"))).toBe(
      true,
    );
  });

  it("blocks old and boundary responses after a clear checkpoint", () => {
    expect(
      isAfterHistoryCutoff(new Date("2026-07-16T05:59:59.999Z"), cutoff),
    ).toBe(false);
    expect(
      isAfterHistoryCutoff(new Date("2026-07-16T06:00:00.000Z"), cutoff),
    ).toBe(false);
  });

  it("allows newly recorded traffic and rejects malformed timestamps", () => {
    expect(
      isAfterHistoryCutoff(new Date("2026-07-16T06:00:00.001Z"), cutoff),
    ).toBe(true);
    expect(isAfterHistoryCutoff(new Date("invalid"), cutoff)).toBe(false);
  });
});

describe("History coverage policy", () => {
  it("requires Caido Scope unless all-History mode is explicitly enabled", () => {
    expect(isHistoryItemInCoverage(false, true)).toBe(true);
    expect(isHistoryItemInCoverage(false, false)).toBe(false);
    expect(isHistoryItemInCoverage(true, false)).toBe(true);
  });

  it("looks deeper into History to fill the in-scope response quota", () => {
    expect(historyInspectionLimit(5_000, true)).toBe(5_000);
    expect(historyInspectionLimit(5_000, false)).toBe(50_000);
    expect(historyInspectionLimit(100, false)).toBe(1_000);
    expect(historyInspectionLimit(50_000, false)).toBe(50_000);
  });
});
