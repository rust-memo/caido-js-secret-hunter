<script setup lang="ts">
import type { FindingDTO, FindingQuery, Page } from "backend";
import { onMounted, onUnmounted, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useSDK } from "@/plugins/sdk";
import {
  formatDate,
  hostOf,
  safeMessage,
  statusClass,
  statusLabel,
} from "@/utils";

const { revision } = defineProps<{ revision: number }>();
const emit = defineEmits<{ openFinding: [fingerprint: string] }>();
const sdk = useSDK();
const page = ref<Page<FindingDTO>>({
  items: [],
  total: 0,
  offset: 0,
  limit: 50,
});
const search = ref("");
const confidence = ref<FindingQuery["confidence"]>("ALL");
const status = ref<FindingQuery["status"]>("ALL");
const loading = ref(false);
let timer: number | undefined;

onMounted(() => load(0));
onUnmounted(() => {
  if (timer !== undefined) window.clearTimeout(timer);
});
watch([search, confidence, status], () => scheduleLoad(0));
watch(
  () => revision,
  () => scheduleLoad(page.value.offset),
);

function scheduleLoad(offset: number) {
  if (timer !== undefined) window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    timer = undefined;
    void load(offset);
  }, 220);
}

async function load(offset: number) {
  loading.value = true;
  try {
    page.value = await sdk.backend.listFindings({
      search: search.value,
      severity: "ALL",
      confidence: confidence.value,
      kind: "ENDPOINT",
      status: status.value,
      offset,
      limit: page.value.limit,
    });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <section class="hunter-page hunter-list-page">
    <div class="hunter-page-heading">
      <div>
        <span class="hunter-eyebrow">LINK INTELLIGENCE</span>
        <h2>Discovered endpoints</h2>
        <p>
          Review API routes, absolute service URLs, legacy action files, and
          dynamic JavaScript paths without executing application code.
        </p>
      </div>
      <div class="hunter-rule-summary">
        <strong>{{ page.total }}</strong> matching routes
      </div>
    </div>

    <div class="hunter-filterbar">
      <input
        v-model="search"
        class="hunter-input grow"
        aria-label="Search discovered endpoints"
        placeholder="Search route, source host, detector, or evidence…"
      />
      <select
        v-model="confidence"
        class="hunter-select"
        aria-label="Endpoint confidence"
      >
        <option value="ALL">All confidence</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>LOW</option>
      </select>
      <select v-model="status" class="hunter-select" aria-label="Review status">
        <option value="ALL">All statuses</option>
        <option>NEEDS_REVIEW</option>
        <option>REVIEWED</option>
        <option>FALSE_POSITIVE</option>
      </select>
    </div>

    <div class="hunter-table-card" :aria-busy="loading">
      <div class="hunter-table-wrap tall">
        <table class="hunter-table endpoint-table">
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Source</th>
              <th>Detector</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Detected</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="finding in page.items"
              :key="finding.fingerprint"
              @click="emit('openFinding', finding.fingerprint)"
            >
              <td class="endpoint-value" :title="finding.maskedValue">
                <code>{{ finding.maskedValue }}</code>
                <small>Line {{ finding.line }}</small>
              </td>
              <td class="url-cell" :title="finding.assetUrl">
                <strong>{{ hostOf(finding.assetUrl) }}</strong>
                <small>{{ finding.assetUrl }}</small>
              </td>
              <td>
                <strong>{{ finding.ruleName }}</strong>
                <small>{{ finding.ruleId }}</small>
              </td>
              <td>{{ statusLabel(finding.confidence) }}</td>
              <td>
                <span
                  class="hunter-status"
                  :class="statusClass(finding.status)"
                >
                  {{ statusLabel(finding.status) }}
                </span>
              </td>
              <td>{{ formatDate(finding.createdAt) }}</td>
              <td>
                <button
                  class="hunter-button ghost"
                  @click.stop="emit('openFinding', finding.fingerprint)"
                >
                  Review
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="page.total === 0 && !loading" class="hunter-empty">
        <strong>No endpoint references match</strong>
        <span>Scan JavaScript traffic or broaden the current filters.</span>
      </div>
      <PaginationControls
        :offset="page.offset"
        :limit="page.limit"
        :total="page.total"
        :disabled="loading"
        @change="load"
      />
    </div>
  </section>
</template>
