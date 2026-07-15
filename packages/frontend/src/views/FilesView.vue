<script setup lang="ts">
import type { EditorView } from "@codemirror/view";
import type { Page, ReviewStatus, SensitiveFileDTO } from "backend";
import { onMounted, onUnmounted, onUpdated, ref, watch } from "vue";

import PaginationControls from "@/components/PaginationControls.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { createRequestGate, safeMessage } from "@/utils";

const { revision } = defineProps<{ revision: number }>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const page = ref<Page<SensitiveFileDTO>>({
  items: [],
  total: 0,
  offset: 0,
  limit: 50,
});
const search = ref("");
const selected = ref<SensitiveFileDTO>();
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

onMounted(async () => {
  mountEditors();
  await load(0);
});
onUpdated(mountEditors);
onUnmounted(() => {
  if (timer !== undefined) window.clearTimeout(timer);
  listGate.invalidate();
  messageGate.invalidate();
});
watch(search, () => scheduleLoad(0));
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
  const request = listGate.start();
  loading.value = true;
  try {
    const nextPage = await sdk.backend.listFiles({
      search: search.value,
      offset,
      limit: page.value.limit,
    });
    if (!listGate.isCurrent(request)) return;
    page.value = nextPage;
    if (
      selected.value !== undefined &&
      !page.value.items.some(
        (item) => item.assetUrl === selected.value?.assetUrl,
      )
    ) {
      selected.value = undefined;
      messageGate.invalidate();
    }
  } catch (cause) {
    if (listGate.isCurrent(request))
      sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    if (listGate.isCurrent(request)) loading.value = false;
  }
}

async function selectFile(file: SensitiveFileDTO) {
  selected.value = file;
  const request = messageGate.start();
  try {
    const message = await sdk.backend.getMessage(file.requestId);
    if (!messageGate.isCurrent(request)) return;
    setEditor(requestEditor, message?.request ?? "Source request unavailable.");
    setEditor(
      responseEditor,
      message?.response ?? "Source response unavailable.",
    );
  } catch (cause) {
    if (messageGate.isCurrent(request))
      sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
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

function setEditor(editor: HttpEditor, value: string) {
  const view = editor.getEditorView();
  view.dispatch({
    changes: { from: 0, to: view.state.doc.length, insert: value },
  });
}

async function updateFile(status: ReviewStatus) {
  if (selected.value === undefined) return;
  if (status === "FALSE_POSITIVE") {
    const accepted = await confirm({
      title: "Mark entire file false positive",
      message: `Mark all ${selected.value.findings} candidates in this file as false positive?`,
      confirmLabel: "Mark file false positive",
      danger: true,
    });
    if (!accepted) return;
  }
  await run(
    async () => sdk.backend.setStatus(selected.value!.fingerprints, status),
    "File review state updated.",
  );
}

async function replay() {
  if (selected.value === undefined) return;
  const accepted = await confirm({
    title: "Create Replay draft",
    message: "Create an unsent Replay session for this file request?",
    confirmLabel: "Create Replay",
  });
  if (!accepted) return;
  await run(async () => {
    const id = await sdk.backend.createReplay(selected.value!.requestId);
    const sessionId = id as Parameters<typeof sdk.replay.renameSession>[0];
    await sdk.replay.renameSession(sessionId, "Secret Hunter - asset");
    sdk.replay.openTab(sessionId);
  }, "Replay draft created.");
}

async function copyUrl() {
  if (selected.value === undefined) return;
  try {
    await navigator.clipboard.writeText(selected.value.assetUrl);
    sdk.window.showToast("File URL copied.", { variant: "success" });
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}

async function run(action: () => Promise<unknown>, success: string) {
  if (busy.value) return;
  busy.value = true;
  try {
    await action();
    sdk.window.showToast(success, { variant: "success" });
    await load(page.value.offset);
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section class="hunter-page hunter-list-page">
    <div class="hunter-page-heading">
      <div>
        <span class="hunter-eyebrow">ASSET-CENTRIC REVIEW</span>
        <h2>Sensitive files</h2>
        <p>
          Prioritize files by their highest-severity candidate and triage in
          bulk.
        </p>
      </div>
      <div v-if="selected" class="hunter-actions wrap">
        <button class="hunter-button" @click="copyUrl">Copy URL</button>
        <button class="hunter-button" :disabled="busy" @click="replay">
          Create Replay
        </button>
        <button
          class="hunter-button primary"
          :disabled="busy"
          @click="updateFile('REVIEWED')"
        >
          Mark reviewed
        </button>
        <button
          class="hunter-button"
          :disabled="busy"
          @click="updateFile('FALSE_POSITIVE')"
        >
          False positive
        </button>
        <button
          class="hunter-button ghost"
          :disabled="busy"
          @click="updateFile('NEEDS_REVIEW')"
        >
          Reset
        </button>
      </div>
    </div>
    <div class="hunter-filterbar">
      <input
        v-model="search"
        class="hunter-input grow"
        aria-label="Search sensitive files"
        placeholder="Search file URL or detector rule…"
      />
    </div>
    <div class="hunter-table-card" :aria-busy="loading">
      <div class="hunter-table-wrap medium">
        <table class="hunter-table">
          <thead>
            <tr>
              <th>Risk</th>
              <th>File</th>
              <th>Findings</th>
              <th>Needs review</th>
              <th>Reviewed</th>
              <th>False positive</th>
              <th>Rules</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="file in page.items"
              :key="file.assetUrl"
              :class="{ selected: selected?.assetUrl === file.assetUrl }"
              @click="selectFile(file)"
            >
              <td><SeverityBadge :severity="file.severity" /></td>
              <td class="url-cell" :title="file.assetUrl">
                <strong>{{ file.assetUrl }}</strong>
              </td>
              <td>{{ file.findings }}</td>
              <td>{{ file.needsReview }}</td>
              <td>{{ file.reviewed }}</td>
              <td>{{ file.falsePositive }}</td>
              <td class="muted-cell" :title="file.rules">{{ file.rules }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="page.total === 0 && !loading" class="hunter-empty">
        <strong>No sensitive files found</strong
        ><span>Scan JavaScript and source maps to populate this view.</span>
      </div>
      <PaginationControls
        :offset="page.offset"
        :limit="page.limit"
        :total="page.total"
        :disabled="loading"
        @change="load"
      />
    </div>
    <div v-if="selected" class="hunter-editor-grid">
      <div class="hunter-editor">
        <span>Source request</span>
        <div ref="requestHost" class="hunter-editor-host" />
      </div>
      <div class="hunter-editor">
        <span>Source response</span>
        <div ref="responseHost" class="hunter-editor-host" />
      </div>
    </div>
  </section>
</template>
