<script setup lang="ts">
import type { Overview } from "backend";
import { computed, ref } from "vue";

import SeverityBadge from "@/components/SeverityBadge.vue";
import { useSDK } from "@/plugins/sdk";
import { formatDate, safeMessage, statusLabel } from "@/utils";

const { overview } = defineProps<{ overview: Overview }>();
const emit = defineEmits<{
  refresh: [];
  openFinding: [fingerprint: string];
}>();
const sdk = useSDK();
const requestId = ref("");
const busy = ref(false);

const triageProgress = computed(() => {
  const total = overview.summary.findingTotal;
  if (total === 0) return 100;
  return Math.round(
    ((overview.summary.reviewed + overview.summary.falsePositive) / total) *
      100,
  );
});

async function run(action: () => Promise<unknown>, message: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    sdk.window.showToast(message, { variant: "success" });
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

async function analyzeOne() {
  const value = requestId.value.trim();
  if (value === "") {
    sdk.window.showToast("Enter a Caido Request ID.", { variant: "warning" });
    return;
  }
  await run(
    async () => sdk.backend.analyzeRequest(value),
    "Saved exchange analyzed.",
  );
}

function togglePause() {
  if (overview.state.phase === "PAUSED") void sdk.backend.resume();
  else void sdk.backend.pause();
}
</script>

<template>
  <section class="hunter-page hunter-dashboard">
    <div class="hunter-hero">
      <div>
        <span class="hunter-eyebrow">PROJECT INTELLIGENCE</span>
        <h2>Find exposed secrets before they ship.</h2>
        <p>
          Triage JavaScript, source maps, and text responses already captured by
          Caido. Candidates stay redacted until you validate them manually.
        </p>
        <div
          class="hunter-scope-status"
          :class="{ warning: overview.settings.scanAllHistory }"
        >
          <span>{{ overview.settings.scanAllHistory ? "!" : "✓" }}</span>
          {{
            overview.settings.scanAllHistory
              ? "All History coverage"
              : "Caido Scope enforced"
          }}
        </div>
      </div>
      <div class="hunter-actions hero-actions">
        <button
          class="hunter-button primary"
          :disabled="busy"
          @click="
            run(() => sdk.backend.rescanHistory(), 'History scan started.')
          "
        >
          Scan History
        </button>
        <button class="hunter-button" @click="togglePause">
          {{ overview.state.phase === "PAUSED" ? "Resume" : "Pause" }}
        </button>
        <button
          class="hunter-button ghost"
          :disabled="overview.state.queued + overview.state.active === 0"
          @click="sdk.backend.cancel()"
        >
          Cancel queue
        </button>
      </div>
    </div>

    <div class="hunter-stat-grid">
      <article class="hunter-stat-card accent">
        <span>Needs review</span>
        <strong>{{ overview.summary.needsReview }}</strong>
        <small>{{ overview.summary.findingTotal }} total candidates</small>
      </article>
      <article class="hunter-stat-card critical">
        <span>Critical exposure</span>
        <strong>{{ overview.summary.critical }}</strong>
        <small>{{ overview.summary.high }} additional high severity</small>
      </article>
      <article class="hunter-stat-card">
        <span>Sensitive files</span>
        <strong>{{ overview.summary.fileTotal }}</strong>
        <small>{{ overview.summary.assetTotal }} assets analyzed</small>
      </article>
      <article class="hunter-stat-card endpoint">
        <span>Endpoint intelligence</span>
        <strong>{{ overview.summary.endpointTotal }}</strong>
        <small>API routes and service references</small>
      </article>
      <article class="hunter-stat-card success">
        <span>Triage complete</span>
        <strong>{{ triageProgress }}%</strong>
        <div class="hunter-progress" aria-hidden="true">
          <i :style="{ width: `${triageProgress}%` }" />
        </div>
      </article>
    </div>

    <div class="hunter-dashboard-grid">
      <article class="hunter-panel recent-panel">
        <div class="hunter-panel-heading">
          <div>
            <span class="hunter-eyebrow">LATEST SIGNALS</span>
            <h3>Recent findings</h3>
          </div>
          <span>{{ overview.summary.published }} published</span>
        </div>
        <div v-if="overview.recentFindings.length" class="hunter-signal-list">
          <button
            v-for="finding in overview.recentFindings"
            :key="finding.fingerprint"
            class="hunter-signal"
            @click="emit('openFinding', finding.fingerprint)"
          >
            <SeverityBadge :severity="finding.severity" />
            <span class="hunter-signal-body">
              <strong>{{ finding.ruleName }}</strong>
              <small>{{ finding.assetUrl }}</small>
            </span>
            <span class="hunter-signal-meta">
              {{ statusLabel(finding.status) }}
              <small>{{ formatDate(finding.createdAt) }}</small>
            </span>
          </button>
        </div>
        <div v-else class="hunter-empty compact">
          <strong>No candidates yet</strong>
          <span
            >Scan History or analyze one saved exchange to get started.</span
          >
        </div>
      </article>

      <div class="hunter-side-stack">
        <article class="hunter-panel">
          <div class="hunter-panel-heading">
            <div>
              <span class="hunter-eyebrow">TARGETED ANALYSIS</span>
              <h3>Analyze a saved exchange</h3>
            </div>
          </div>
          <p class="hunter-panel-copy">
            Re-run detection against one existing Caido Request ID without
            clearing current results.
          </p>
          <div class="hunter-inline-form">
            <input
              v-model="requestId"
              class="hunter-input"
              aria-label="Caido Request ID"
              placeholder="Request ID"
              @keyup.enter="analyzeOne"
            />
            <button
              class="hunter-button primary"
              :disabled="busy"
              @click="analyzeOne"
            >
              Analyze
            </button>
          </div>
        </article>

        <article class="hunter-panel safety-panel">
          <div class="hunter-safety-icon" aria-hidden="true">✓</div>
          <div>
            <h3>Safe collection controls</h3>
            <p>
              History and live analysis use
              <strong>{{
                overview.settings.scanAllHistory
                  ? "all captured traffic"
                  : "Caido Scope only"
              }}</strong
              >. Automatic fetching is
              <strong>{{
                overview.settings.autoFetch ? "enabled" : "off"
              }}</strong
              >. Credential forwarding is
              <strong>{{
                overview.settings.includeCredentials ? "enabled" : "off"
              }}</strong
              >. Every fetch and redirect remains restricted to Caido Scope.
            </p>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
