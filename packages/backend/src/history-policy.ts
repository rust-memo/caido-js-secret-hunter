export function isAfterHistoryCutoff(
  createdAt: Date,
  historyCutoff?: number,
): boolean {
  if (historyCutoff === undefined) return true;
  const recordedAt = createdAt.getTime();
  return Number.isFinite(recordedAt) && recordedAt > historyCutoff;
}
