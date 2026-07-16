<script setup lang="ts">
import type {
  EndpointMethod,
  EndpointQuery,
  EndpointSummary,
  FindingDTO,
  Page,
} from "backend";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useSDK } from "@/plugins/sdk";
import {
  correctedPageOffset,
  createRequestGate,
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
const summary = ref<EndpointSummary>({
  observations: 0,
  uniqueRoutes: 0,
  dynamicRoutes: 0,
  crossOrigin: 0,
  parameterized: 0,
  methods: {},
  sources: {},
});
const search = ref("");
const confidence = ref<EndpointQuery["confidence"]>("ALL");
const status = ref<EndpointQuery["status"]>("ALL");
const method = ref<EndpointQuery["method"]>("ALL");
const scope = ref<EndpointQuery["scope"]>("ALL");
const loading = ref(false);
const requestGate = createRequestGate();
let timer: number | undefined;

const leadingMethods = computed<Array<[EndpointMethod, number]>>(() =>
  (Object.entries(summary.value.methods) as Array<[EndpointMethod, number]>)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5),
);

onMounted(() => load(0));
onUnmounted(() => {
  if (timer !== undefined) window.clearTimeout(timer);
  requestGate.invalidate();
});
watch([search, confidence, status, method, scope], () => scheduleLoad(0));
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
  const request = requestGate.start();
  loading.value = true;
  try {
    // eslint-disable-next-line compat/compat -- Caido's frontend runtime supports Promise.all.
    const [nextPage, nextSummary] = await Promise.all([
      sdk.backend.listEndpoints({
        search: search.value,
        confidence: confidence.value,
        status: status.value,
        method: method.value,
        scope: scope.value,
        offset,
        limit: page.value.limit,
      }),
      sdk.backend.getEndpointSummary(),
    ]);
    if (!requestGate.isCurrent(request)) return;
    const corrected = correctedPageOffset(nextPage);
    if (corrected !== undefined) {
      summary.value = nextSummary;
      void load(corrected);
      return;
    }
    page.value = nextPage;
    summary.value = nextSummary;
  } catch (cause) {
    if (requestGate.isCurrent(request))
      sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    if (requestGate.isCurrent(request)) loading.value = false;
  }
}

async function copyEndpoint(finding: FindingDTO) {
  try {
    await navigator.clipboard.writeText(finding.maskedValue);
    sdk.window.showToast("Endpoint copied.", { variant: "success" });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

function methodClass(value: EndpointMethod | undefined): string {
  return `method-${value ?? "ANY"}`;
}
</script>

<template>
  <section class="hunter-page hunter-list-page endpoint-page">
    <div class="hunter-page-heading endpoint-heading">
      <div>
        <span class="hunter-eyebrow">ENDPOINT INTELLIGENCE</span>
        <h2>Discovered attack surface</h2>
        <p>
          Inventory full, dotted, slash-relative, legacy, and dynamic routes
          with HTTP call-site context—without executing application code.
        </p>
      </div>
      <div class="endpoint-method-mix" aria-label="Observed HTTP methods">
        <span v-for="entry in leadingMethods" :key="entry[0]">
          <b class="endpoint-method" :class="methodClass(entry[0])">
            {{ entry[0] }}
          </b>
          {{ entry[1] }}
        </span>
      </div>
    </div>

    <div class="endpoint-metrics">
      <article>
        <span>Unique route patterns</span>
        <strong>{{ summary.uniqueRoutes }}</strong>
        <small>Canonical method + route</small>
      </article>
      <article>
        <span>Call-site observations</span>
        <strong>{{ summary.observations }}</strong>
        <small>Across captured assets</small>
      </article>
      <article>
        <span>Dynamic routes</span>
        <strong>{{ summary.dynamicRoutes }}</strong>
        <small>Template or path parameters</small>
      </article>
      <article>
        <span>Cross-origin</span>
        <strong>{{ summary.crossOrigin }}</strong>
        <small>External service boundaries</small>
      </article>
      <article>
        <span>Parameterized</span>
        <strong>{{ summary.parameterized }}</strong>
        <small>Query or route inputs</small>
      </article>
    </div>

    <div class="hunter-filterbar endpoint-filterbar">
      <input
        v-model="search"
        class="hunter-input grow"
        aria-label="Search discovered endpoints"
        placeholder="Search route, parameter, source host, method…"
      />
      <select v-model="method" class="hunter-select" aria-label="HTTP method">
        <option value="ALL">All methods</option>
        <option>GET</option>
        <option>POST</option>
        <option>PUT</option>
        <option>PATCH</option>
        <option>DELETE</option>
        <option>HEAD</option>
        <option>OPTIONS</option>
        <option>CONNECT</option>
        <option>ANY</option>
      </select>
      <select v-model="scope" class="hunter-select" aria-label="Endpoint scope">
        <option value="ALL">All origins</option>
        <option value="SAME_ORIGIN">Same origin</option>
        <option value="CROSS_ORIGIN">Cross origin</option>
        <option value="NON_HTTP">Non HTTP</option>
        <option value="UNKNOWN">Unknown origin</option>
      </select>
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

    <div class="hunter-table-card endpoint-inventory" :aria-busy="loading">
      <div class="endpoint-inventory-head">
        <span
          ><strong>{{ page.total }}</strong> matching observations</span
        >
        <span>Values shown here are redacted before storage.</span>
      </div>
      <div class="hunter-table-wrap tall">
        <table class="hunter-table endpoint-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Endpoint</th>
              <th>Parameters</th>
              <th>Context</th>
              <th>Source asset</th>
              <th>Review</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="finding in page.items"
              :key="finding.fingerprint"
              @click="emit('openFinding', finding.fingerprint)"
            >
              <td>
                <span
                  class="endpoint-method"
                  :class="methodClass(finding.endpoint?.method)"
                >
                  {{ finding.endpoint?.method ?? "ANY" }}
                </span>
              </td>
              <td class="endpoint-value" :title="finding.maskedValue">
                <code>{{ finding.maskedValue }}</code>
                <small>
                  {{ finding.endpoint?.dynamic ? "Dynamic · " : "" }}Line
                  {{ finding.line }}
                </small>
                <small
                  v-if="
                    finding.endpoint?.canonical &&
                    finding.endpoint.canonical !== finding.maskedValue
                  "
                  class="endpoint-canonical"
                >
                  Pattern: {{ finding.endpoint.canonical }}
                </small>
              </td>
              <td>
                <div
                  v-if="finding.endpoint?.parameters.length"
                  class="endpoint-parameter-list"
                >
                  <span
                    v-for="parameter in finding.endpoint.parameters"
                    :key="parameter"
                  >
                    {{ parameter }}
                  </span>
                </div>
                <span v-else class="muted-cell">None observed</span>
              </td>
              <td>
                <span
                  class="endpoint-scope"
                  :class="`scope-${finding.endpoint?.scope ?? 'UNKNOWN'}`"
                >
                  {{ statusLabel(finding.endpoint?.scope ?? "UNKNOWN") }}
                </span>
                <small>
                  {{ statusLabel(finding.endpoint?.source ?? "DETECTOR") }} ·
                  {{ statusLabel(finding.confidence) }} confidence
                </small>
              </td>
              <td class="url-cell" :title="finding.assetUrl">
                <strong>{{ hostOf(finding.assetUrl) }}</strong>
                <small>{{ finding.assetUrl }}</small>
                <small>{{ formatDate(finding.createdAt) }}</small>
              </td>
              <td>
                <span
                  class="hunter-status"
                  :class="statusClass(finding.status)"
                >
                  {{ statusLabel(finding.status) }}
                </span>
              </td>
              <td>
                <div class="endpoint-row-actions">
                  <button
                    class="hunter-icon-button"
                    aria-label="Copy endpoint"
                    title="Copy redacted endpoint"
                    @click.stop="copyEndpoint(finding)"
                  >
                    ⧉
                  </button>
                  <button
                    class="hunter-button ghost"
                    @click.stop="emit('openFinding', finding.fingerprint)"
                  >
                    Review
                  </button>
                </div>
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
