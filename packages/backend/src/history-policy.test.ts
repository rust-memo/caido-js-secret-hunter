import { describe, expect, it } from "vitest";

import { isAfterHistoryCutoff } from "./history-policy";

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
