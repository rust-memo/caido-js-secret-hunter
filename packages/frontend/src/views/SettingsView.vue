<script setup lang="ts">
import type { HunterSettings } from "backend";
import { computed, reactive, ref, watch } from "vue";

import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { safeMessage } from "@/utils";

const { settings, ignoredCount } = defineProps<{
  settings: HunterSettings;
  ignoredCount: number;
}>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const form = reactive<HunterSettings>({ ...settings });
const busy = ref(false);

watch(
  () => settings,
  (value) => Object.assign(form, value),
  { immediate: true, deep: true },
);

const maxBodyMb = computed({
  get: () => Math.round((form.maxBodyBytes / 1024 / 1024) * 100) / 100,
  set: (value: number) => {
    form.maxBodyBytes = Math.max(0.06, value) * 1024 * 1024;
  },
});

const exclusionsText = computed({
  get: () => form.assetExclusions.join("\n"),
  set: (value: string) => {
    form.assetExclusions = value.split(/[\n,]/);
  },
});

async function save() {
  if (busy.value) return;
  if (form.autoFetch && !settings.autoFetch) {
    const accepted = await confirm({
      title: "Enable automatic asset fetching",
      message:
        "Allow JS Secret Hunter to send bounded GET requests for discovered assets? Every request and redirect must remain in Caido Scope.",
      confirmLabel: "Enable scoped fetch",
    });
    if (!accepted) {
      form.autoFetch = false;
      form.includeCredentials = false;
      return;
    }
  }
  if (form.includeCredentials && !settings.includeCredentials) {
    const accepted = await confirm({
      title: "Forward same-origin credentials",
      message:
        "Allow automatic asset requests to copy Cookie and Authorization only when scheme, host, and port exactly match the source request? Use this only for authorized authenticated testing.",
      confirmLabel: "Allow credentials",
      danger: true,
    });
    if (!accepted) {
      form.includeCredentials = false;
      return;
    }
  }
  if (!form.autoFetch) form.includeCredentials = false;
  await run(async () => {
    const saved = await sdk.backend.saveSettings({ ...form });
    Object.assign(form, saved);
  }, "Settings saved. Existing results were not changed.");
}

async function rebuild() {
  const accepted = await confirm({
    title: "Rebuild project results",
    message:
      "Delete current findings and asset activity, then rebuild them from bounded Caido History using saved Settings? Review states and reviewer notes remain available when matching candidates return.",
    confirmLabel: "Rebuild results",
    danger: true,
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.rebuildResults(),
    "Result rebuild started.",
  );
}

async function clearResults() {
  const accepted = await confirm({
    title: "Clear project results",
    message:
      "Delete current findings and asset activity? Saved review states, notes, Settings, and ignored values are retained.",
    confirmLabel: "Clear results",
    danger: true,
  });
  if (!accepted) return;
  await run(async () => sdk.backend.clearResults(), "Project results cleared.");
}

async function restoreIgnored() {
  if (ignoredCount === 0) return;
  const accepted = await confirm({
    title: "Restore ignored rules and hosts",
    message:
      "Re-enable every ignored rule and host? Existing results are not rebuilt automatically.",
    confirmLabel: "Restore all",
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.restoreIgnored(),
    "Ignored rules and hosts restored.",
  );
}

async function run(action: () => Promise<unknown>, success: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    sdk.window.showToast(success, { variant: "success" });
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="hunter-page">
    <div class="hunter-page-heading">
      <div>
        <span class="hunter-eyebrow">CONTROL PLANE</span>
        <h2>Settings</h2>
        <p>
          Bound local analysis, network collection, and retained project data.
        </p>
      </div>
      <button class="hunter-button primary" :disabled="busy" @click="save">
        Save settings
      </button>
    </div>

    <div class="hunter-settings-layout">
      <div class="hunter-settings-stack">
        <article class="hunter-settings-card">
          <div class="hunter-settings-heading">
            <span class="settings-icon">◎</span>
            <div>
              <h3>Analysis coverage</h3>
              <p>Choose which captured traffic can be analyzed locally.</p>
            </div>
          </div>
          <label class="hunter-switch-row">
            <span
              ><strong>Analyze all History</strong
              ><small
                >When off, only requests in Caido Scope are analyzed.</small
              ></span
            >
            <input v-model="form.scanAllHistory" type="checkbox" />
          </label>
          <label class="hunter-number-row">
            <span
              ><strong>History entries</strong
              ><small>Maximum recent exchanges per manual scan.</small></span
            >
            <input
              v-model.number="form.maxHistoryEntries"
              class="hunter-input number"
              type="number"
              min="100"
              max="50000"
            />
          </label>
          <label class="hunter-number-row">
            <span
              ><strong>Body size</strong
              ><small>Maximum decoded text response size in MiB.</small></span
            >
            <input
              v-model.number="maxBodyMb"
              class="hunter-input number"
              type="number"
              min="0.06"
              max="25"
              step="0.25"
            />
          </label>
          <label class="hunter-number-row">
            <span
              ><strong>Finding cap</strong
              ><small>Maximum candidates retained per project.</small></span
            >
            <input
              v-model.number="form.maxFindings"
              class="hunter-input number"
              type="number"
              min="100"
              max="50000"
            />
          </label>
        </article>

        <article class="hunter-settings-card network-card">
          <div class="hunter-settings-heading">
            <span class="settings-icon">↗</span>
            <div>
              <h3>Scoped asset collection</h3>
              <p>
                Network actions are off by default and always scope checked.
              </p>
            </div>
          </div>
          <label class="hunter-switch-row">
            <span
              ><strong>Automatic asset fetching</strong
              ><small
                >Send bounded GET requests for missing JS, modules, and source
                maps.</small
              ></span
            >
            <input
              v-model="form.autoFetch"
              type="checkbox"
              @change="!form.autoFetch && (form.includeCredentials = false)"
            />
          </label>
          <label
            class="hunter-switch-row"
            :class="{ disabled: !form.autoFetch }"
          >
            <span
              ><strong>Forward same-origin credentials</strong
              ><small
                >Copy Cookie and Authorization only to an exact same-origin
                request.</small
              ></span
            >
            <input
              v-model="form.includeCredentials"
              type="checkbox"
              :disabled="!form.autoFetch"
            />
          </label>
          <label class="hunter-number-row">
            <span
              ><strong>Discovery depth</strong
              ><small
                >Recursive dependency levels from each History root.</small
              ></span
            >
            <input
              v-model.number="form.maxDepth"
              class="hunter-input number"
              type="number"
              min="0"
              max="5"
            />
          </label>
          <label class="hunter-number-row">
            <span
              ><strong>Assets per root</strong
              ><small
                >Maximum scheduled dependencies for one root response.</small
              ></span
            >
            <input
              v-model.number="form.maxAssetsPerRoot"
              class="hunter-input number"
              type="number"
              min="1"
              max="2000"
            />
          </label>
          <label class="hunter-field hunter-exclusions-field">
            <span>Auto-fetch exclusions</span>
            <small>
              One case-insensitive URL substring per line. Captured responses
              are still analyzed locally.
            </small>
            <textarea
              v-model="exclusionsText"
              class="hunter-textarea"
              placeholder="jquery&#10;google-analytics&#10;googletagmanager"
            />
          </label>
        </article>
      </div>

      <aside class="hunter-settings-sidebar">
        <article class="hunter-panel safety-panel vertical">
          <div class="hunter-safety-icon">✓</div>
          <div>
            <h3>Data handling</h3>
            <p>
              Raw matches are transient. The database stores masked values,
              SHA-256 value hashes, and redacted previews.
            </p>
          </div>
        </article>
        <article class="hunter-panel">
          <span class="hunter-eyebrow">PROJECT MAINTENANCE</span>
          <h3>Results and exclusions</h3>
          <p class="hunter-panel-copy">
            Saving Settings is non-destructive. Use rebuild only when you
            intentionally want to replace current results.
          </p>
          <div class="hunter-maintenance-actions">
            <button class="hunter-button" :disabled="busy" @click="rebuild">
              Rebuild results
            </button>
            <button
              class="hunter-button danger"
              :disabled="busy"
              @click="clearResults"
            >
              Clear results
            </button>
            <button
              class="hunter-button ghost"
              :disabled="busy || ignoredCount === 0"
              @click="restoreIgnored"
            >
              Restore ignored ({{ ignoredCount }})
            </button>
          </div>
        </article>
      </aside>
    </div>
  </section>
</template>
