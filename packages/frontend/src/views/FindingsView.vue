<script setup lang="ts">
import type { EditorView } from "@codemirror/view";
import type { FindingDTO, FindingQuery, Page, ReviewStatus } from "backend";
import { computed, onMounted, onUnmounted, onUpdated, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import {
  correctedPageOffset,
  createRequestGate,
  formatDate,
  highlightSegments,
  hostOf,
  responseBodyRange,
  safeMessage,
  statusClass,
  statusLabel,
} from "@/utils";

const { revision, focusFingerprint = "" } = defineProps<{
  revision: number;
  focusFingerprint?: string;
}>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const page = ref<Page<FindingDTO>>({
  items: [],
  total: 0,
  offset: 0,
  limit: 50,
});
const search = ref("");
const severity = ref<FindingQuery["severity"]>("ALL");
const confidence = ref<FindingQuery["confidence"]>("ALL");
const kind = ref<FindingQuery["kind"]>("ALL");
const status = ref<FindingQuery["status"]>("ALL");
const selected = ref<FindingDTO>();
const selectedIds = ref(new Set<string>());
const reviewNote = ref("");
const loading = ref(false);
const busy = ref(false);
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
const listGate = createRequestGate();
const messageGate = createRequestGate();
let timer: number | undefined;

type HttpEditor = {
  getEditorView: () => EditorView;
};

const allSelected = computed(
  () =>
    page.value.items.length > 0 &&
    page.value.items.every((finding) =>
      selectedIds.value.has(finding.fingerprint),
    ),
);
const evidenceSegments = computed(() =>
  selected.value === undefined
    ? []
    : highlightSegments(
        selected.value.preview,
        selected.value.evidenceHighlight,
      ),
);

onMounted(async () => {
  mountEditors();
  await load(0);
  await focusFinding(focusFingerprint);
});
onUpdated(mountEditors);
onUnmounted(() => {
  if (timer !== undefined) window.clearTimeout(timer);
  listGate.invalidate();
  messageGate.invalidate();
});

watch([search, severity, confidence, kind, status], () => scheduleLoad(0));
watch(
  () => revision,
  () => scheduleLoad(page.value.offset, true),
);
watch(
  () => focusFingerprint,
  (fingerprint) => void focusFinding(fingerprint),
);

function query(offset: number): FindingQuery {
  return {
    search: search.value,
    severity: severity.value,
    confidence: confidence.value,
    kind: kind.value,
    status: status.value,
    offset,
    limit: page.value.limit,
  };
}

function scheduleLoad(offset: number, refreshSelected = false) {
  if (timer !== undefined) window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    timer = undefined;
    void load(offset, refreshSelected);
  }, 220);
}

async function load(offset: number, refreshSelected = false) {
  const request = listGate.start();
  loading.value = true;
  try {
    const nextPage = await sdk.backend.listFindings(query(offset));
    if (!listGate.isCurrent(request)) return;
    const corrected = correctedPageOffset(nextPage);
    if (corrected !== undefined) {
      void load(corrected, refreshSelected);
      return;
    }
    page.value = nextPage;
    if (refreshSelected && selected.value !== undefined) {
      const current = await sdk.backend.getFinding(selected.value.fingerprint);
      if (listGate.isCurrent(request) && current !== undefined)
        hydrateSelected(current);
      else if (listGate.isCurrent(request)) clearSelected();
    }
  } catch (cause) {
    if (listGate.isCurrent(request))
      sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    if (listGate.isCurrent(request)) loading.value = false;
  }
}

async function focusFinding(fingerprint: string | undefined) {
  if (
    fingerprint === undefined ||
    fingerprint === "" ||
    selected.value?.fingerprint === fingerprint
  )
    return;
  try {
    const finding = await sdk.backend.getFinding(fingerprint);
    if (finding !== undefined) await selectFinding(finding);
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

async function selectFinding(finding: FindingDTO) {
  hydrateSelected(finding);
  await loadMessage(finding);
}

function hydrateSelected(finding: FindingDTO) {
  selected.value = finding;
  reviewNote.value = finding.reviewNote;
}

function clearSelected() {
  selected.value = undefined;
  reviewNote.value = "";
  messageGate.invalidate();
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

async function loadMessage(finding: FindingDTO) {
  const request = messageGate.start();
  try {
    const message = await sdk.backend.getMessage(finding.requestId);
    if (!messageGate.isCurrent(request)) return;
    setEditor(
      requestEditor,
      message?.request ?? "Source request is no longer available in Caido.",
    );
    setEditor(
      responseEditor,
      message?.response ?? "Source response is no longer available in Caido.",
      message === undefined
        ? undefined
        : responseBodyRange(
            message.response,
            finding.start,
            finding.end,
            finding.preview.startsWith("source | "),
          ),
    );
  } catch (cause) {
    if (messageGate.isCurrent(request))
      sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

function setEditor(
  editor: HttpEditor,
  value: string,
  selection?: { from: number; to: number },
) {
  const view = editor.getEditorView();
  view.dispatch({
    changes: { from: 0, to: view.state.doc.length, insert: value },
  });
  if (selection !== undefined)
    view.dispatch({
      selection: { anchor: selection.from, head: selection.to },
      scrollIntoView: true,
    });
}

async function run(action: () => Promise<unknown>, success: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    sdk.window.showToast(success, { variant: "success" });
    await load(page.value.offset, true);
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}

async function updateStatus(value: ReviewStatus, fingerprints?: string[]) {
  const ids =
    fingerprints ??
    (selected.value === undefined ? [] : [selected.value.fingerprint]);
  if (ids.length === 0) return;
  if (value === "FALSE_POSITIVE") {
    const accepted = await confirm({
      title: "Mark false positive",
      message: `Mark ${ids.length} selected candidate${ids.length === 1 ? "" : "s"} as false positive? The decision remains after results are rebuilt.`,
      confirmLabel: "Mark false positive",
      danger: true,
    });
    if (!accepted) return;
  }
  await run(
    async () => sdk.backend.setStatus(ids, value),
    `${ids.length} candidate${ids.length === 1 ? "" : "s"} updated.`,
  );
  selectedIds.value = new Set();
}

async function saveNote() {
  if (selected.value === undefined) return;
  await run(
    async () =>
      sdk.backend.setNote(selected.value!.fingerprint, reviewNote.value),
    "Reviewer note saved.",
  );
}

async function publish() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Publish redacted finding",
    message:
      "Publish this reviewed candidate to Caido Findings? Only the masked value, SHA-256 fingerprint, reviewer note, and redacted evidence are included.",
    confirmLabel: "Publish finding",
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.publishFinding(selected.value!.fingerprint),
    "Finding published to Caido.",
  );
}

async function sendToReplay() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Create Replay draft",
    message:
      "Create an unsent Replay session from the source request? No request is sent automatically.",
    confirmLabel: "Create Replay",
  });
  if (!accepted) return;
  await run(async () => {
    const id = await sdk.backend.createReplay(selected.value!.requestId);
    const sessionId = id as Parameters<typeof sdk.replay.renameSession>[0];
    await sdk.replay.renameSession(
      sessionId,
      `Secret Hunter - ${selected.value!.ruleName}`,
    );
    sdk.replay.openTab(sessionId);
  }, "Replay draft created.");
}

async function ignoreSelected(target: "rule" | "host") {
  if (selected.value === undefined) return;
  const value =
    target === "rule" ? selected.value.ruleId : hostOf(selected.value.assetUrl);
  if (value === "") return;
  const accepted = await confirm({
    title: `Ignore ${target}`,
    message: `Ignore ${target} '${value}' and remove its current candidates? Re-enable it later from the Rule library or Settings.`,
    confirmLabel: `Ignore ${target}`,
    danger: true,
  });
  if (!accepted) return;
  await run(
    async () => sdk.backend.ignore(target, value),
    `${target === "rule" ? "Rule" : "Host"} ignored.`,
  );
  selected.value = undefined;
}

function toggleSelected(fingerprint: string) {
  const values = new Set(selectedIds.value);
  if (values.has(fingerprint)) values.delete(fingerprint);
  else values.add(fingerprint);
  selectedIds.value = values;
}

function togglePage() {
  const values = new Set(selectedIds.value);
  if (allSelected.value)
    page.value.items.forEach((finding) => values.delete(finding.fingerprint));
  else page.value.items.forEach((finding) => values.add(finding.fingerprint));
  selectedIds.value = values;
}
</script>

<template>
  <section class="hunter-page hunter-list-page">
    <div class="hunter-page-heading">
      <div>
        <span class="hunter-eyebrow">TRIAGE WORKSPACE</span>
        <h2>Findings</h2>
        <p>Filter, validate, annotate, and publish redacted candidates.</p>
      </div>
      <div v-if="selectedIds.size" class="hunter-bulk-bar">
        <strong>{{ selectedIds.size }} selected</strong>
        <button
          class="hunter-button"
          :disabled="busy"
          @click="updateStatus('REVIEWED', [...selectedIds])"
        >
          Mark reviewed
        </button>
        <button
          class="hunter-button"
          :disabled="busy"
          @click="updateStatus('FALSE_POSITIVE', [...selectedIds])"
        >
          False positive
        </button>
        <button class="hunter-icon-button" @click="selectedIds = new Set()">
          ×
        </button>
      </div>
    </div>

    <div class="hunter-filterbar">
      <input
        v-model="search"
        class="hunter-input grow"
        aria-label="Search findings"
        placeholder="Search rule, host, evidence, note…"
      />
      <select v-model="severity" class="hunter-select" aria-label="Severity">
        <option value="ALL">All severities</option>
        <option>CRITICAL</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>INFO</option>
      </select>
      <select
        v-model="confidence"
        class="hunter-select"
        aria-label="Confidence"
      >
        <option value="ALL">All confidence</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>LOW</option>
      </select>
      <select v-model="kind" class="hunter-select" aria-label="Kind">
        <option value="ALL">All kinds</option>
        <option>SECRET</option>
        <option>CREDENTIAL</option>
        <option>ENDPOINT</option>
        <option>IDENTIFIER</option>
        <option>CONFIGURATION</option>
      </select>
      <select v-model="status" class="hunter-select" aria-label="Status">
        <option value="ALL">All statuses</option>
        <option>NEEDS_REVIEW</option>
        <option>REVIEWED</option>
        <option>FALSE_POSITIVE</option>
      </select>
    </div>

    <div class="hunter-workspace" :class="{ detailed: selected }">
      <div class="hunter-table-card" :aria-busy="loading">
        <div class="hunter-table-wrap">
          <table class="hunter-table">
            <thead>
              <tr>
                <th class="checkbox-cell">
                  <input
                    type="checkbox"
                    :checked="allSelected"
                    aria-label="Select current page"
                    @change="togglePage"
                  />
                </th>
                <th>Severity</th>
                <th>Candidate</th>
                <th>Kind</th>
                <th>Masked value</th>
                <th>Asset</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="finding in page.items"
                :key="finding.fingerprint"
                :class="{
                  selected: selected?.fingerprint === finding.fingerprint,
                }"
                @click="selectFinding(finding)"
              >
                <td class="checkbox-cell" @click.stop>
                  <input
                    type="checkbox"
                    :checked="selectedIds.has(finding.fingerprint)"
                    :aria-label="`Select ${finding.ruleName}`"
                    @change="toggleSelected(finding.fingerprint)"
                  />
                </td>
                <td><SeverityBadge :severity="finding.severity" /></td>
                <td>
                  <strong>{{ finding.ruleName }}</strong>
                  <small
                    >{{ finding.ruleId }} · confidence
                    {{ finding.confidence }}</small
                  >
                </td>
                <td>{{ statusLabel(finding.kind) }}</td>
                <td class="mono">{{ finding.maskedValue }}</td>
                <td class="url-cell" :title="finding.assetUrl">
                  {{ finding.assetUrl }}<small>Line {{ finding.line }}</small>
                </td>
                <td>
                  <span
                    class="hunter-status"
                    :class="statusClass(finding.status)"
                  >
                    {{ statusLabel(finding.status) }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="page.total === 0 && !loading" class="hunter-empty">
          <strong>No matching candidates</strong>
          <span>Adjust the filters or scan additional History.</span>
        </div>
        <PaginationControls
          :offset="page.offset"
          :limit="page.limit"
          :total="page.total"
          :disabled="loading"
          @change="load"
        />
      </div>

      <aside v-if="selected" class="hunter-detail-panel">
        <div class="hunter-detail-header">
          <div>
            <SeverityBadge :severity="selected.severity" />
            <h3>{{ selected.ruleName }}</h3>
            <p>{{ selected.ruleId }} · {{ selected.confidence }} confidence</p>
          </div>
          <button
            class="hunter-icon-button"
            aria-label="Close detail"
            @click="selected = undefined"
          >
            ×
          </button>
        </div>
        <div class="hunter-detail-scroll">
          <dl class="hunter-detail-grid">
            <div>
              <dt>Kind</dt>
              <dd>{{ statusLabel(selected.kind) }}</dd>
            </div>
            <div>
              <dt>Line</dt>
              <dd>{{ selected.line }}</dd>
            </div>
            <div>
              <dt>Detected</dt>
              <dd>{{ formatDate(selected.createdAt) }}</dd>
            </div>
            <div>
              <dt>Published</dt>
              <dd>{{ selected.published ? "Yes" : "No" }}</dd>
            </div>
          </dl>
          <div class="hunter-value-box">
            <span>Masked value</span><code>{{ selected.maskedValue }}</code>
            <small>SHA-256 {{ selected.valueHash }}</small>
          </div>
          <div v-if="selected.endpoint" class="endpoint-detail-card">
            <div class="endpoint-detail-heading">
              <span
                class="endpoint-method"
                :class="`method-${selected.endpoint.method}`"
              >
                {{ selected.endpoint.method }}
              </span>
              <div>
                <strong>Endpoint context</strong>
                <small>
                  {{ statusLabel(selected.endpoint.source) }} ·
                  {{ statusLabel(selected.endpoint.scope) }}
                </small>
              </div>
            </div>
            <dl class="hunter-detail-grid">
              <div>
                <dt>Dynamic</dt>
                <dd>{{ selected.endpoint.dynamic ? "Yes" : "No" }}</dd>
              </div>
              <div>
                <dt>Parameters</dt>
                <dd>{{ selected.endpoint.parameters.length }}</dd>
              </div>
            </dl>
            <code class="endpoint-detail-pattern">
              {{ selected.endpoint.canonical }}
            </code>
            <div
              v-if="selected.endpoint.parameters.length"
              class="endpoint-parameter-list"
            >
              <span
                v-for="parameter in selected.endpoint.parameters"
                :key="parameter"
              >
                {{ parameter }}
              </span>
            </div>
          </div>
          <div class="hunter-evidence-box">
            <span>Redacted evidence · detected match highlighted</span>
            <pre><template
                v-for="(segment, index) in evidenceSegments"
                :key="`${index}-${segment.highlighted}`"
              ><mark v-if="segment.highlighted">{{ segment.text }}</mark><template
                  v-else
                >{{ segment.text }}</template></template></pre>
          </div>
          <label class="hunter-field">
            <span>Reviewer note</span>
            <textarea
              v-model="reviewNote"
              class="hunter-textarea"
              placeholder="Validation steps, ownership, rotation status…"
            />
          </label>
          <div class="hunter-actions wrap">
            <button
              class="hunter-button primary"
              :disabled="busy"
              @click="saveNote"
            >
              Save note
            </button>
            <button
              class="hunter-button"
              :disabled="busy"
              @click="updateStatus('REVIEWED')"
            >
              Mark reviewed
            </button>
            <button
              class="hunter-button"
              :disabled="busy"
              @click="updateStatus('FALSE_POSITIVE')"
            >
              False positive
            </button>
            <button
              class="hunter-button ghost"
              :disabled="busy"
              @click="updateStatus('NEEDS_REVIEW')"
            >
              Reset
            </button>
          </div>
          <div class="hunter-actions wrap secondary-actions">
            <button
              class="hunter-button"
              :disabled="busy"
              @click="sendToReplay"
            >
              Create Replay
            </button>
            <button
              class="hunter-button primary"
              :disabled="
                busy || selected.status !== 'REVIEWED' || selected.published
              "
              @click="publish"
            >
              {{ selected.published ? "Published" : "Publish finding" }}
            </button>
            <button class="hunter-button ghost" @click="ignoreSelected('rule')">
              Ignore rule
            </button>
            <button class="hunter-button ghost" @click="ignoreSelected('host')">
              Ignore host
            </button>
          </div>
          <div class="hunter-editor-stack">
            <div class="hunter-editor">
              <span>Source request</span>
              <div ref="requestHost" class="hunter-editor-host" />
            </div>
            <div class="hunter-editor">
              <span>Source response</span>
              <div ref="responseHost" class="hunter-editor-host" />
            </div>
          </div>
        </div>
      </aside>
    </div>
  </section>
</template>
