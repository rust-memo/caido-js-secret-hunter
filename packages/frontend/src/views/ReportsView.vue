<script setup lang="ts">
import type { ProjectSummary, ReportFormat } from "backend";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";
import { downloadReport, safeMessage } from "@/utils";

const { summary } = defineProps<{ summary: ProjectSummary }>();
const sdk = useSDK();
const busy = ref<ReportFormat>();

async function exportReport(format: ReportFormat) {
  if (busy.value !== undefined) return;
  busy.value = format;
  try {
    const file = await sdk.backend.exportReport(format);
    downloadReport(file);
    sdk.window.showToast(`${file.filename} exported.`, { variant: "success" });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = undefined;
  }
}
</script>

<template>
  <section class="hunter-page">
    <div class="hunter-page-heading">
      <div>
        <span class="hunter-eyebrow">SAFE DELIVERABLES</span>
        <h2>Reports</h2>
        <p>Export complete, redacted evidence for review and handoff.</p>
      </div>
    </div>
    <div class="hunter-report-hero">
      <div class="hunter-report-copy">
        <span class="hunter-report-icon" aria-hidden="true">↗</span>
        <h3>Project intelligence report</h3>
        <p>
          Reports omit raw HTTP, request IDs, internal database fingerprints,
          and raw secret values. Authentication headers and common sensitive URL
          parameters are redacted again during generation.
        </p>
        <div class="hunter-report-metrics">
          <span
            ><strong>{{ summary.findingTotal }}</strong> findings</span
          >
          <span
            ><strong>{{ summary.fileTotal }}</strong> files</span
          >
          <span
            ><strong>{{ summary.endpointTotal }}</strong> endpoints</span
          >
          <span
            ><strong>{{ summary.reviewed }}</strong> reviewed</span
          >
          <span
            ><strong>{{ summary.published }}</strong> published</span
          >
        </div>
      </div>
      <div class="hunter-report-options">
        <button
          class="hunter-report-option"
          :disabled="busy !== undefined"
          @click="exportReport('html')"
        >
          <span class="format-mark html">HTML</span>
          <span
            ><strong>Executive report</strong
            ><small>Printable summary, findings, and rule coverage</small></span
          >
          <i>{{ busy === "html" ? "…" : "↓" }}</i>
        </button>
        <button
          class="hunter-report-option"
          :disabled="busy !== undefined"
          @click="exportReport('json')"
        >
          <span class="format-mark json">JSON</span>
          <span
            ><strong>Structured evidence</strong
            ><small>Complete machine-readable project export</small></span
          >
          <i>{{ busy === "json" ? "…" : "↓" }}</i>
        </button>
        <button
          class="hunter-report-option"
          :disabled="busy !== undefined"
          @click="exportReport('csv')"
        >
          <span class="format-mark csv">CSV</span>
          <span
            ><strong>Finding register</strong
            ><small>Spreadsheet-safe triage and evidence table</small></span
          >
          <i>{{ busy === "csv" ? "…" : "↓" }}</i>
        </button>
      </div>
    </div>
    <div class="hunter-notice">
      <strong>Before sharing:</strong> candidates can include false positives
      and public identifiers. Validate review status and project handling rules
      first.
    </div>
  </section>
</template>
