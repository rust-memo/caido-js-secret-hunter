import type { ReviewStatus } from "backend";

export function safeMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

export function statusLabel(value: string): string {
  return value
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function statusClass(value: ReviewStatus): string {
  return `status-${value}`;
}

export function hostOf(url: string): string {
  const match = url.match(/^https?:\/\/(?:[^@/?#]+@)?(\[[^\]]+\]|[^:/?#]+)/i);
  return match?.[1]?.toLowerCase() ?? "";
}

export function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function createRequestGate(): {
  start: () => number;
  isCurrent: (request: number) => boolean;
  invalidate: () => void;
} {
  let current = 0;
  return {
    start: () => {
      current += 1;
      return current;
    },
    isCurrent: (request) => request === current,
    invalidate: () => {
      current += 1;
    },
  };
}

export function correctedPageOffset(page: {
  items: unknown[];
  total: number;
  offset: number;
  limit: number;
}): number | undefined {
  if (page.items.length > 0 || page.total <= 0 || page.limit <= 0)
    return undefined;
  const lastOffset = Math.floor((page.total - 1) / page.limit) * page.limit;
  if (page.offset >= page.total) return lastOffset;
  return page.offset > 0 ? 0 : undefined;
}

export function downloadReport(file: {
  filename: string;
  mediaType: string;
  content: string;
}): void {
  const blob = new Blob([file.content], { type: file.mediaType });
  // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = file.filename;
  anchor.click();
  // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
  URL.revokeObjectURL(url);
}
