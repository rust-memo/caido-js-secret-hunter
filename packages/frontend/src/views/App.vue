<script setup lang="ts">
import type { Overview, ScanState } from "backend";
import { onMounted, onUnmounted, provide, reactive, ref } from "vue";

import packageMetadata from "../../package.json";

import ConfirmDialog from "@/components/ConfirmDialog.vue";
import { ConfirmKey, type ConfirmOptions } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import AssetsView from "@/views/AssetsView.vue";
import DashboardView from "@/views/DashboardView.vue";
import EndpointsView from "@/views/EndpointsView.vue";
import FilesView from "@/views/FilesView.vue";
import FindingsView from "@/views/FindingsView.vue";
import ReportsView from "@/views/ReportsView.vue";
import RulesView from "@/views/RulesView.vue";
import SettingsView from "@/views/SettingsView.vue";

type Tab =
  | "dashboard"
  | "findings"
  | "endpoints"
  | "files"
  | "assets"
  | "rules"
  | "reports"
  | "settings";

const sdk = useSDK();
const pluginVersion = packageMetadata.version;
const overview = ref<Overview>();
const state = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  findings: 0,
  dropped: 0,
  message: "Loading JS Secret Hunter",
});
const activeTab = ref<Tab>("dashboard");
const revision = ref(0);
const focusFingerprint = ref("");
const loading = ref(false);
const dialog = reactive({
  open: false,
  title: "",
  message: "",
  confirmLabel: "Confirm",
  danger: false,
});
let refreshPending = false;
let dialogResolver: ((accepted: boolean) => void) | undefined;
let changeListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;

provide(ConfirmKey, (options: ConfirmOptions) => {
  dialogResolver?.(false);
  Object.assign(dialog, {
    open: true,
    title: options.title,
    message: options.message,
    confirmLabel: options.confirmLabel ?? "Confirm",
    danger: options.danger === true,
  });
  // eslint-disable-next-line compat/compat -- Caido's frontend runtime supports Promise.
  return new Promise<boolean>((resolve) => {
    dialogResolver = resolve;
  });
});

onMounted(async () => {
  changeListener = sdk.backend.onEvent("data-changed", () => {
    revision.value += 1;
    void refreshOverview();
  });
  stateListener = sdk.backend.onEvent("scan-state", (value) => {
    state.value = value;
    if (overview.value !== undefined) overview.value.state = value;
  });
  await refreshOverview();
});

onUnmounted(() => {
  changeListener?.stop();
  stateListener?.stop();
  dialogResolver?.(false);
});

async function refreshOverview() {
  if (loading.value) {
    refreshPending = true;
    return;
  }
  loading.value = true;
  try {
    overview.value = await sdk.backend.getOverview();
    state.value = overview.value.state;
  } catch (cause) {
    sdk.window.showToast(
      cause instanceof Error ? cause.message : String(cause),
      { variant: "error" },
    );
  } finally {
    loading.value = false;
    if (refreshPending) {
      refreshPending = false;
      void refreshOverview();
    }
  }
}

function resolveDialog(accepted: boolean) {
  dialog.open = false;
  const resolve = dialogResolver;
  dialogResolver = undefined;
  resolve?.(accepted);
}

function openFinding(fingerprint: string) {
  focusFingerprint.value = fingerprint;
  activeTab.value = "findings";
}

const tabs: Array<{ id: Tab; label: string }> = [
  { id: "dashboard", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "endpoints", label: "Endpoints" },
  { id: "files", label: "Sensitive files" },
  { id: "assets", label: "Asset graph" },
  { id: "rules", label: "Rule library" },
  { id: "reports", label: "Reports" },
  { id: "settings", label: "Settings" },
];
</script>

<template>
  <main class="hunter-shell">
    <header class="hunter-header">
      <div class="hunter-brand">
        <div class="hunter-logo" aria-hidden="true">JS</div>
        <div>
          <h1>
            Secret Hunter
            <span class="hunter-version">v{{ pluginVersion }}</span>
          </h1>
          <p>
            Continuous JavaScript intelligence
            <span>·</span>
            Rule pack {{ overview?.rulePackVersion ?? "…" }}
          </p>
        </div>
      </div>
      <div class="hunter-header-status">
        <span class="hunter-phase" :class="`phase-${state.phase}`">
          <i aria-hidden="true" />{{ state.phase }}
        </span>
        <span>{{ state.queued }} queued</span>
        <span>{{ state.active }} active</span>
        <span v-if="state.dropped" class="danger-text">
          {{ state.dropped }} dropped
        </span>
      </div>
    </header>

    <div class="hunter-state" role="status" aria-live="polite">
      <span>{{ state.message }}</span>
      <span>{{ state.scanned }} responses analyzed this run</span>
    </div>

    <nav class="hunter-tabs" role="tablist" aria-label="Secret Hunter views">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="hunter-tab"
        :class="{ active: activeTab === tab.id }"
        role="tab"
        :aria-selected="activeTab === tab.id"
        @click="activeTab = tab.id"
      >
        {{ tab.label }}
        <template v-if="overview">
          <span v-if="tab.id === 'findings'" class="hunter-tab-count">
            {{ overview.summary.findingTotal }}
          </span>
          <span v-else-if="tab.id === 'endpoints'" class="hunter-tab-count">
            {{ overview.summary.endpointTotal }}
          </span>
          <span v-else-if="tab.id === 'files'" class="hunter-tab-count">
            {{ overview.summary.fileTotal }}
          </span>
          <span v-else-if="tab.id === 'assets'" class="hunter-tab-count">
            {{ overview.summary.assetTotal }}
          </span>
        </template>
      </button>
    </nav>

    <div v-if="loading && !overview" class="hunter-loading" aria-busy="true">
      <span class="hunter-spinner" />
      Loading project intelligence…
    </div>
    <template v-else-if="overview">
      <DashboardView
        v-if="activeTab === 'dashboard'"
        :overview="overview"
        @refresh="refreshOverview"
        @open-finding="openFinding"
      />
      <FindingsView
        v-else-if="activeTab === 'findings'"
        :revision="revision"
        :focus-fingerprint="focusFingerprint"
        @refresh="refreshOverview"
      />
      <EndpointsView
        v-else-if="activeTab === 'endpoints'"
        :revision="revision"
        @open-finding="openFinding"
      />
      <FilesView
        v-else-if="activeTab === 'files'"
        :revision="revision"
        @refresh="refreshOverview"
      />
      <AssetsView v-else-if="activeTab === 'assets'" :revision="revision" />
      <RulesView
        v-else-if="activeTab === 'rules'"
        :revision="revision"
        :ignored-hosts="overview.ignoredHosts"
        @refresh="refreshOverview"
      />
      <ReportsView
        v-else-if="activeTab === 'reports'"
        :summary="overview.summary"
      />
      <SettingsView
        v-else
        :settings="overview.settings"
        :ignored-count="
          overview.ignoredRules.length + overview.ignoredHosts.length
        "
        @refresh="refreshOverview"
      />
    </template>

    <ConfirmDialog
      :open="dialog.open"
      :title="dialog.title"
      :message="dialog.message"
      :confirm-label="dialog.confirmLabel"
      :danger="dialog.danger"
      @confirm="resolveDialog(true)"
      @cancel="resolveDialog(false)"
    />
  </main>
</template>
