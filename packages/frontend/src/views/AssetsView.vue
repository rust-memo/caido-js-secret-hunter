<script setup lang="ts">
import type { AssetDTO, AssetQuery, Page } from "backend";
import { onMounted, onUnmounted, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import { useSDK } from "@/plugins/sdk";
import { formatDate, safeMessage, statusLabel } from "@/utils";

const { revision } = defineProps<{ revision: number }>();
const sdk = useSDK();
const page = ref<Page<AssetDTO>>({ items: [], total: 0, offset: 0, limit: 50 });
const search = ref("");
const status = ref<AssetQuery["status"]>("ALL");
const loading = ref(false);
let timer: number | undefined;

onMounted(() => load(0));
onUnmounted(() => {
  if (timer !== undefined) window.clearTimeout(timer);
});
watch([search, status], () => scheduleLoad(0));
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
    page.value = await sdk.backend.listAssets({
      search: search.value,
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
        <span class="hunter-eyebrow">DISCOVERY TELEMETRY</span>
        <h2>Asset graph</h2>
        <p>
          Inspect recursively discovered JavaScript, module, and source-map
          activity.
        </p>
      </div>
    </div>
    <div class="hunter-filterbar">
      <input
        v-model="search"
        class="hunter-input grow"
        aria-label="Search assets"
        placeholder="Search URL, parent, root, or detail…"
      />
      <select v-model="status" class="hunter-select" aria-label="Asset status">
        <option value="ALL">All statuses</option>
        <option>QUEUED</option>
        <option>FETCHING</option>
        <option>SCANNED</option>
        <option>SKIPPED</option>
        <option>FAILED</option>
        <option>CANCELLED</option>
      </select>
    </div>
    <div class="hunter-table-card" :aria-busy="loading">
      <div class="hunter-table-wrap tall">
        <table class="hunter-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Depth</th>
              <th>Asset URL</th>
              <th>Parent</th>
              <th>Root</th>
              <th>Detail</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="asset in page.items" :key="asset.url">
              <td>
                <span class="hunter-status" :class="`asset-${asset.status}`">{{
                  statusLabel(asset.status)
                }}</span>
              </td>
              <td>
                <span class="depth-pill">{{ asset.depth }}</span>
              </td>
              <td class="url-cell" :title="asset.url">
                <strong>{{ asset.url }}</strong>
              </td>
              <td class="url-cell" :title="asset.parentUrl">
                {{ asset.parentUrl }}
              </td>
              <td class="url-cell" :title="asset.rootUrl">
                {{ asset.rootUrl }}
              </td>
              <td>{{ asset.detail }}</td>
              <td>{{ formatDate(asset.updatedAt) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="page.total === 0 && !loading" class="hunter-empty">
        <strong>No asset activity yet</strong
        ><span>Enable scoped auto-fetch or scan captured asset responses.</span>
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
