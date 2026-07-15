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
