export function isAfterHistoryCutoff(
  createdAt: Date,
  historyCutoff?: number,
): boolean {
  if (historyCutoff === undefined) return true;
  const recordedAt = createdAt.getTime();
  return Number.isFinite(recordedAt) && recordedAt > historyCutoff;
}

export function isHistoryItemInCoverage(
  scanAllHistory: boolean,
  inScope: boolean,
): boolean {
  return scanAllHistory || inScope;
}

export function historyInspectionLimit(
  maxHistoryEntries: number,
  scanAllHistory: boolean,
): number {
  if (scanAllHistory) return maxHistoryEntries;
  return Math.min(50_000, maxHistoryEntries * 10);
}
