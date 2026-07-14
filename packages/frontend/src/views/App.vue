<script setup lang="ts">
import type {
  FindingDTO,
  HunterSettings,
  MessageDetails,
  ReviewStatus,
  ScanState,
  SensitiveFileDTO,
  Snapshot,
} from "backend";
import {
  computed,
  nextTick,
  onMounted,
  onUnmounted,
  onUpdated,
  reactive,
  ref,
} from "vue";

import { useSDK } from "@/plugins/sdk";

type Tab = "files" | "findings" | "links" | "assets" | "settings";

const sdk = useSDK();
const snapshot = ref<Snapshot>();
const scanState = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  findings: 0,
  message: "Loading",
});
const activeTab = ref<Tab>("files");
const loading = ref(false);
const error = ref("");
const search = ref("");
const severity = ref("ALL");
const confidence = ref("ALL");
const kind = ref("ALL");
const review = ref("ALL");
const selectedFindingFingerprint = ref("");
const selectedFileUrl = ref("");
const message = ref<MessageDetails>();
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
const settings = reactive<HunterSettings>({
  scanAllHistory: true,
  autoFetch: true,
  maxDepth: 2,
  maxAssetsPerRoot: 200,
  maxBodyBytes: 5 * 1024 * 1024,
  maxHistoryEntries: 5_000,
  maxFindings: 10_000,
});
const maxBodyMb = computed({
  get: () => Math.max(1, Math.round(settings.maxBodyBytes / 1024 / 1024)),
  set: (value: number) => {
    settings.maxBodyBytes = Math.max(1, value) * 1024 * 1024;
  },
});

let refreshTimer: number | undefined;
let snapshotListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;

const findings = computed(() => snapshot.value?.findings ?? []);
const files = computed(() => snapshot.value?.files ?? []);
const assets = computed(() => snapshot.value?.assets ?? []);
const filteredFindings = computed(() =>
  findings.value.filter((finding) => {
    const query = search.value.trim().toLowerCase();
    const text =
      `${finding.ruleName} ${finding.ruleId} ${finding.assetUrl} ${finding.maskedValue} ${finding.preview}`.toLowerCase();
    return (
      (severity.value === "ALL" || finding.severity === severity.value) &&
      (confidence.value === "ALL" || finding.confidence === confidence.value) &&
      (kind.value === "ALL" || finding.kind === kind.value) &&
      (review.value === "ALL" || finding.status === review.value) &&
      (query.length === 0 || text.includes(query))
    );
  }),
);
const links = computed(() =>
  filteredFindings.value.filter(
    (finding) =>
      finding.kind === "ENDPOINT" || finding.kind === "CONFIGURATION",
  ),
);
const selectedFinding = computed(() =>
  findings.value.find(
    (finding) => finding.fingerprint === selectedFindingFingerprint.value,
  ),
);
const selectedFile = computed(() =>
  files.value.find((file) => file.assetUrl === selectedFileUrl.value),
);
const selectedFileFindings = computed(() =>
  findings.value.filter(
    (finding) => finding.assetUrl === selectedFileUrl.value,
  ),
);
const evidence = computed(() => {
  if (activeTab.value === "files")
    return selectedFileFindings.value
      .map(
        (finding) =>
          `[${finding.status}] ${finding.severity} | ${finding.ruleName} | line ${finding.line} | ${finding.maskedValue}\n${finding.preview}`,
      )
      .join("\n\n");
  const finding = selectedFinding.value;
  return finding === undefined
    ? ""
    : `${finding.ruleName} (${finding.ruleId})\nStatus: ${finding.status}\n` +
        `Masked value: ${finding.maskedValue}\nValue SHA-256: ${finding.valueHash}\nLine: ${finding.line}\n\n${finding.preview}`;
});

onMounted(async () => {
  mountEditors();
  snapshotListener = sdk.backend.onEvent("snapshot-updated", scheduleRefresh);
  stateListener = sdk.backend.onEvent("scan-state", (state) => {
    scanState.value = state;
  });
  await refresh();
});

onUpdated(mountEditors);

onUnmounted(() => {
  snapshotListener?.stop();
  stateListener?.stop();
  if (refreshTimer !== undefined) window.clearTimeout(refreshTimer);
});

function scheduleRefresh() {
  if (refreshTimer !== undefined) window.clearTimeout(refreshTimer);
  refreshTimer = window.setTimeout(() => {
    void refresh();
  }, 150);
}

function mountEditors() {
  if (
    requestHost.value !== undefined &&
    !requestHost.value.contains(requestEditor.getElement())
  )
    requestHost.value.append(requestEditor.getElement());
  if (
    responseHost.value !== undefined &&
    !responseHost.value.contains(responseEditor.getElement())
  )
    responseHost.value.append(responseEditor.getElement());
}

async function refresh() {
  if (loading.value) return;
  loading.value = true;
  try {
    const current = await sdk.backend.getSnapshot();
    snapshot.value = current;
    scanState.value = current.state;
    Object.assign(settings, current.settings);
    if (
      selectedFindingFingerprint.value &&
      !current.findings.some(
        (finding) => finding.fingerprint === selectedFindingFingerprint.value,
      )
    )
      selectedFindingFingerprint.value = "";
    if (
      selectedFileUrl.value &&
      !current.files.some((file) => file.assetUrl === selectedFileUrl.value)
    )
      selectedFileUrl.value = "";
    error.value = "";
  } catch (cause) {
    error.value = safeMessage(cause);
  } finally {
    loading.value = false;
  }
}

async function selectFinding(finding: FindingDTO) {
  selectedFindingFingerprint.value = finding.fingerprint;
  await loadMessage(finding.requestId);
}

async function selectFile(file: SensitiveFileDTO) {
  selectedFileUrl.value = file.assetUrl;
  await loadMessage(file.requestId);
}

async function loadMessage(requestId: string) {
  try {
    message.value = await sdk.backend.getMessage(requestId);
    setEditor(
      requestEditor,
      message.value?.request ?? "Source request is unavailable",
    );
    setEditor(
      responseEditor,
      message.value?.response ?? "Source response is unavailable",
    );
    error.value = "";
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

function setEditor(
  editor: ReturnType<typeof sdk.ui.httpRequestEditor>,
  text: string,
) {
  const view = editor.getEditorView();
  view.dispatch({
    changes: { from: 0, to: view.state.doc.length, insert: text },
  });
}

async function updateStatus(fingerprints: string[], status: ReviewStatus) {
  if (fingerprints.length === 0) return;
  try {
    await sdk.backend.setStatus(fingerprints, status);
    await refresh();
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

async function sendToReplay(requestId: string | undefined) {
  if (requestId === undefined) return;
  try {
    const sessionId = await sdk.backend.createReplay(requestId);
    sdk.replay.openTab(sessionId as Parameters<typeof sdk.replay.openTab>[0]);
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

async function publish() {
  const finding = selectedFinding.value;
  if (finding === undefined) return;
  if (
    !window.confirm(
      "Create a redacted Caido Finding for this reviewed candidate?",
    )
  )
    return;
  try {
    await sdk.backend.publishFinding(finding.fingerprint);
    await refresh();
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

async function ignoreSelected(kindToIgnore: "rule" | "host") {
  const finding = selectedFinding.value;
  if (finding === undefined) return;
  const value =
    kindToIgnore === "rule" ? finding.ruleId : hostOf(finding.assetUrl);
  if (
    value.length === 0 ||
    !window.confirm(
      `Ignore ${kindToIgnore} '${value}' and remove its current findings?`,
    )
  )
    return;
  try {
    await sdk.backend.ignore(kindToIgnore, value);
    await refresh();
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

async function applySettings() {
  try {
    await sdk.backend.saveSettings({ ...settings });
    await refresh();
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

async function rescan() {
  try {
    await sdk.backend.rescanHistory();
    await refresh();
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

async function clearResults() {
  if (
    !window.confirm(
      "Clear current JS Secret Hunter results? Review decisions remain saved.",
    )
  )
    return;
  try {
    await sdk.backend.clearResults();
    message.value = undefined;
    clearEditors();
    await refresh();
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

function clearEditors() {
  setEditor(requestEditor, "");
  setEditor(responseEditor, "");
}
function togglePause() {
  if (scanState.value.phase === "PAUSED") void sdk.backend.resume();
  else void sdk.backend.pause();
}
function cancel() {
  void sdk.backend.cancel();
}

async function copyFileUrl() {
  if (selectedFile.value !== undefined)
    await navigator.clipboard.writeText(selectedFile.value.assetUrl);
}

function exportFindings(format: "json" | "csv") {
  const values = filteredFindings.value;
  const body =
    format === "json" ? JSON.stringify(values, undefined, 2) : toCsv(values);
  const blob = new Blob([body], {
    type: format === "json" ? "application/json" : "text/csv",
  });
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports object URLs.
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `caido-js-secret-hunter.${format}`;
  anchor.click();
  // eslint-disable-next-line compat/compat -- Caido's desktop webview supports object URLs.
  URL.revokeObjectURL(url);
}

function toCsv(values: FindingDTO[]): string {
  const columns: (keyof FindingDTO)[] = [
    "severity",
    "confidence",
    "kind",
    "ruleId",
    "ruleName",
    "maskedValue",
    "assetUrl",
    "line",
    "status",
    "valueHash",
    "preview",
  ];
  const escape = (value: string | number | boolean) =>
    `"${String(value).replace(/"/g, '""')}"`;
  return `${columns.join(",")}\n${values.map((finding) => columns.map((column) => escape(finding[column])).join(",")).join("\n")}`;
}

function hostOf(url: string): string {
  const match = url.match(/^https?:\/\/(?:[^@/?#]+@)?(\[[^\]]+\]|[^:/?#]+)/i);
  return match?.[1]?.toLowerCase() ?? "";
}
function safeMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
function activate(tab: Tab) {
  activeTab.value = tab;
  void nextTick();
}
</script>

<template>
  <main class="hunter-shell">
    <header class="hunter-header">
      <div>
        <div class="hunter-title">JS Secret Hunter for Caido</div>
        <div class="hunter-subtitle">
          Passive History/live analysis · Rule pack
          {{ snapshot?.rulePackVersion ?? "…" }} · Raw secrets are not persisted
        </div>
      </div>
      <div class="hunter-metrics">
        <span class="hunter-metric">{{ scanState.phase }}</span>
        <span class="hunter-metric">Queued {{ scanState.queued }}</span>
        <span class="hunter-metric">Active {{ scanState.active }}</span>
        <span class="hunter-metric">Scanned {{ scanState.scanned }}</span>
        <span class="hunter-metric">Files {{ files.length }}</span>
        <span class="hunter-metric">Findings {{ findings.length }}</span>
      </div>
    </header>
    <div v-if="error" class="hunter-error">{{ error }}</div>
    <nav class="hunter-tabs">
      <button
        class="hunter-tab"
        :class="{ active: activeTab === 'files' }"
        @click="activate('files')"
      >
        Sensitive Files
      </button>
      <button
        class="hunter-tab"
        :class="{ active: activeTab === 'findings' }"
        @click="activate('findings')"
      >
        Findings
      </button>
      <button
        class="hunter-tab"
        :class="{ active: activeTab === 'links' }"
        @click="activate('links')"
      >
        Links
      </button>
      <button
        class="hunter-tab"
        :class="{ active: activeTab === 'assets' }"
        @click="activate('assets')"
      >
        Assets
      </button>
      <button
        class="hunter-tab"
        :class="{ active: activeTab === 'settings' }"
        @click="activate('settings')"
      >
        Settings
      </button>
    </nav>

    <section v-if="activeTab !== 'settings'" class="hunter-toolbar">
      <button class="hunter-button primary" @click="rescan">
        Rescan History
      </button>
      <button class="hunter-button" @click="togglePause">
        {{ scanState.phase === "PAUSED" ? "Resume" : "Pause" }}
      </button>
      <button
        class="hunter-button"
        :disabled="scanState.queued + scanState.active === 0"
        @click="cancel"
      >
        Cancel queued
      </button>
      <button class="hunter-button danger" @click="clearResults">Clear</button>
      <template v-if="activeTab === 'findings' || activeTab === 'links'">
        <input
          v-model="search"
          class="hunter-input"
          placeholder="Search findings, rules, hosts…"
        />
        <select v-model="severity" class="hunter-select">
          <option value="ALL">All severities</option>
          <option>CRITICAL</option>
          <option>HIGH</option>
          <option>MEDIUM</option>
          <option>INFO</option>
        </select>
        <select v-model="confidence" class="hunter-select">
          <option value="ALL">All confidences</option>
          <option>HIGH</option>
          <option>MEDIUM</option>
          <option>LOW</option>
        </select>
        <select v-model="kind" class="hunter-select">
          <option value="ALL">All kinds</option>
          <option>SECRET</option>
          <option>CREDENTIAL</option>
          <option>ENDPOINT</option>
          <option>IDENTIFIER</option>
          <option>CONFIGURATION</option>
        </select>
        <select v-model="review" class="hunter-select">
          <option value="ALL">All statuses</option>
          <option>NEEDS_REVIEW</option>
          <option>REVIEWED</option>
          <option>FALSE_POSITIVE</option>
        </select>
        <button class="hunter-button" @click="exportFindings('json')">
          Export JSON
        </button>
        <button class="hunter-button" @click="exportFindings('csv')">
          Export CSV
        </button>
      </template>
    </section>

    <section v-if="activeTab === 'files'" class="hunter-content">
      <div class="hunter-toolbar">
        <button
          class="hunter-button"
          :disabled="!selectedFile"
          @click="copyFileUrl"
        >
          Copy file URL
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFile"
          @click="sendToReplay(selectedFile?.requestId)"
        >
          Send file to Replay
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFile"
          @click="updateStatus(selectedFile?.fingerprints ?? [], 'REVIEWED')"
        >
          Mark file reviewed
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFile"
          @click="
            updateStatus(selectedFile?.fingerprints ?? [], 'FALSE_POSITIVE')
          "
        >
          File false positive
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFile"
          @click="
            updateStatus(selectedFile?.fingerprints ?? [], 'NEEDS_REVIEW')
          "
        >
          Reset review
        </button>
      </div>
      <div v-if="files.length" class="hunter-table-wrap">
        <table class="hunter-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Findings</th>
              <th>Needs review</th>
              <th>Reviewed</th>
              <th>False positive</th>
              <th>File URL</th>
              <th>Rules</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="file in files"
              :key="file.assetUrl"
              :class="{ selected: selectedFileUrl === file.assetUrl }"
              @click="selectFile(file)"
            >
              <td>
                <span
                  class="hunter-badge"
                  :class="`severity-${file.severity}`"
                  >{{ file.severity }}</span
                >
              </td>
              <td>{{ file.findings }}</td>
              <td>{{ file.needsReview }}</td>
              <td>{{ file.reviewed }}</td>
              <td>{{ file.falsePositive }}</td>
              <td :title="file.assetUrl">{{ file.assetUrl }}</td>
              <td :title="file.rules">{{ file.rules }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="hunter-empty">
        No sensitive files yet. History and live responses are scanned in the
        background.
      </div>
      <div v-if="selectedFile" class="hunter-evidence">{{ evidence }}</div>
      <div v-if="selectedFile" class="hunter-split">
        <div class="hunter-editor">
          <div class="hunter-editor-title">Request from Caido History</div>
          <div ref="requestHost" class="hunter-editor-host" />
        </div>
        <div class="hunter-editor">
          <div class="hunter-editor-title">Response from Caido History</div>
          <div ref="responseHost" class="hunter-editor-host" />
        </div>
      </div>
    </section>

    <section v-else-if="activeTab === 'findings'" class="hunter-content">
      <div class="hunter-toolbar">
        <button
          class="hunter-button"
          :disabled="!selectedFinding"
          @click="sendToReplay(selectedFinding?.requestId)"
        >
          Send to Replay
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFinding"
          @click="
            updateStatus(
              selectedFinding ? [selectedFinding.fingerprint] : [],
              'REVIEWED',
            )
          "
        >
          Reviewed
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFinding"
          @click="
            updateStatus(
              selectedFinding ? [selectedFinding.fingerprint] : [],
              'FALSE_POSITIVE',
            )
          "
        >
          False positive
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFinding"
          @click="
            updateStatus(
              selectedFinding ? [selectedFinding.fingerprint] : [],
              'NEEDS_REVIEW',
            )
          "
        >
          Needs review
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFinding"
          @click="ignoreSelected('rule')"
        >
          Ignore rule
        </button>
        <button
          class="hunter-button"
          :disabled="!selectedFinding"
          @click="ignoreSelected('host')"
        >
          Ignore host
        </button>
        <button
          class="hunter-button"
          :disabled="
            !selectedFinding ||
            selectedFinding.status !== 'REVIEWED' ||
            selectedFinding.published
          "
          @click="publish"
        >
          Add as Caido Finding
        </button>
      </div>
      <div v-if="filteredFindings.length" class="hunter-table-wrap">
        <table class="hunter-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Kind</th>
              <th>Rule</th>
              <th>Value</th>
              <th>Line</th>
              <th>Asset URL</th>
              <th>Status</th>
              <th>Published</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="finding in filteredFindings"
              :key="finding.fingerprint"
              :class="{
                selected: selectedFindingFingerprint === finding.fingerprint,
              }"
              @click="selectFinding(finding)"
            >
              <td>
                <span
                  class="hunter-badge"
                  :class="`severity-${finding.severity}`"
                  >{{ finding.severity }}</span
                >
              </td>
              <td>{{ finding.confidence }}</td>
              <td>{{ finding.kind }}</td>
              <td>{{ finding.ruleName }}</td>
              <td>{{ finding.maskedValue }}</td>
              <td>{{ finding.line }}</td>
              <td :title="finding.assetUrl">{{ finding.assetUrl }}</td>
              <td :class="`status-${finding.status}`">{{ finding.status }}</td>
              <td>{{ finding.published ? "Yes" : "" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="hunter-empty">
        No findings match the current filters.
      </div>
      <div v-if="selectedFinding" class="hunter-evidence">{{ evidence }}</div>
      <div v-if="selectedFinding" class="hunter-split">
        <div class="hunter-editor">
          <div class="hunter-editor-title">Request</div>
          <div ref="requestHost" class="hunter-editor-host" />
        </div>
        <div class="hunter-editor">
          <div class="hunter-editor-title">Response</div>
          <div ref="responseHost" class="hunter-editor-host" />
        </div>
      </div>
    </section>

    <section v-else-if="activeTab === 'links'" class="hunter-content">
      <div v-if="links.length" class="hunter-table-wrap">
        <table class="hunter-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Kind</th>
              <th>Rule</th>
              <th>Detected link</th>
              <th>Source file</th>
              <th>Line</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="finding in links"
              :key="finding.fingerprint"
              :class="{
                selected: selectedFindingFingerprint === finding.fingerprint,
              }"
              @click="selectFinding(finding)"
            >
              <td>
                <span
                  class="hunter-badge"
                  :class="`severity-${finding.severity}`"
                  >{{ finding.severity }}</span
                >
              </td>
              <td>{{ finding.kind }}</td>
              <td>{{ finding.ruleName }}</td>
              <td>{{ finding.maskedValue }}</td>
              <td :title="finding.assetUrl">{{ finding.assetUrl }}</td>
              <td>{{ finding.line }}</td>
              <td :class="`status-${finding.status}`">{{ finding.status }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="hunter-empty">
        No endpoint or configuration links detected.
      </div>
    </section>

    <section v-else-if="activeTab === 'assets'" class="hunter-content">
      <div v-if="assets.length" class="hunter-table-wrap">
        <table class="hunter-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Depth</th>
              <th>URL</th>
              <th>Parent</th>
              <th>Detail</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="asset in assets" :key="asset.url">
              <td>{{ asset.status }}</td>
              <td>{{ asset.depth }}</td>
              <td :title="asset.url">{{ asset.url }}</td>
              <td :title="asset.parentUrl">{{ asset.parentUrl }}</td>
              <td>{{ asset.detail }}</td>
              <td>{{ asset.updatedAt }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="hunter-empty">No analyzed assets yet.</div>
    </section>

    <section v-else class="hunter-settings">
      <div class="hunter-settings-grid">
        <label for="all-history"
          >Analyze all Caido History and live responses locally</label
        ><input
          id="all-history"
          v-model="settings.scanAllHistory"
          type="checkbox"
        />
        <label for="auto-fetch"
          >Fetch missing assets automatically (Caido Scope only)</label
        ><input id="auto-fetch" v-model="settings.autoFetch" type="checkbox" />
        <label for="depth">Maximum discovery depth</label
        ><input
          id="depth"
          v-model.number="settings.maxDepth"
          class="hunter-input"
          type="number"
          min="0"
          max="5"
        />
        <label for="assets-root">Maximum discovered assets per root</label
        ><input
          id="assets-root"
          v-model.number="settings.maxAssetsPerRoot"
          class="hunter-input"
          type="number"
          min="1"
          max="2000"
        />
        <label for="body-size">Maximum text/JavaScript body size (MB)</label
        ><input
          id="body-size"
          v-model.number="maxBodyMb"
          class="hunter-input"
          type="number"
          min="1"
          max="25"
        />
        <label for="history-limit"
          >Maximum recent History entries per scan</label
        ><input
          id="history-limit"
          v-model.number="settings.maxHistoryEntries"
          class="hunter-input"
          type="number"
          min="100"
          max="50000"
        />
        <label for="findings-limit">Maximum retained findings</label
        ><input
          id="findings-limit"
          v-model.number="settings.maxFindings"
          class="hunter-input"
          type="number"
          min="100"
          max="50000"
        />
      </div>
      <div
        class="hunter-toolbar"
        style="
          padding-left: 0;
          margin-top: 1rem;
          border: 0;
          background: transparent;
        "
      >
        <button class="hunter-button primary" @click="applySettings">
          Apply and rescan</button
        ><button class="hunter-button" @click="sdk.backend.restoreIgnored()">
          Restore ignored rules/hosts
        </button>
      </div>
      <p class="hunter-settings-note">
        Passive analysis reads responses already stored by Caido. Every
        automatic HTTP request and every redirect is checked against Caido Scope
        before it is sent. Cookie and Authorization headers are copied only to
        the same scheme, host, and port. Candidate values are masked and only
        SHA-256 fingerprints are stored by the plugin.
      </p>
      <p class="hunter-settings-note">{{ scanState.message }}</p>
    </section>
  </main>
</template>
