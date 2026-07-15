<script setup lang="ts">
import type { RuleSummary } from "backend";
import { computed, onMounted, ref, watch } from "vue";

import SeverityBadge from "@/components/SeverityBadge.vue";
import { useConfirm } from "@/plugins/confirm";
import { useSDK } from "@/plugins/sdk";
import { safeMessage, statusLabel } from "@/utils";

const { revision, ignoredHosts } = defineProps<{
  revision: number;
  ignoredHosts: string[];
}>();
const emit = defineEmits<{ refresh: [] }>();
const sdk = useSDK();
const confirm = useConfirm();
const rules = ref<RuleSummary[]>([]);
const search = ref("");
const kind = ref("ALL");
const loading = ref(false);

const filtered = computed(() => {
  const query = search.value.trim().toLowerCase();
  return rules.value.filter(
    (rule) =>
      (kind.value === "ALL" || rule.kind === kind.value) &&
      (query === "" ||
        `${rule.id} ${rule.name} ${rule.kind} ${rule.severity}`
          .toLowerCase()
          .includes(query)),
  );
});

onMounted(load);
watch(
  () => revision,
  () => void load(),
);

async function load() {
  loading.value = true;
  try {
    rules.value = await sdk.backend.listRules();
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  } finally {
    loading.value = false;
  }
}

async function toggleRule(rule: RuleSummary) {
  if (!rule.ignored) {
    const accepted = await confirm({
      title: "Ignore detector rule",
      message: `Ignore '${rule.name}' and remove its current candidates? Saved review decisions remain.`,
      confirmLabel: "Ignore rule",
      danger: true,
    });
    if (!accepted) return;
  }
  await run(
    async () =>
      rule.ignored
        ? sdk.backend.unignore("rule", rule.id)
        : sdk.backend.ignore("rule", rule.id),
    rule.ignored ? "Rule enabled." : "Rule ignored.",
  );
}

async function enableHost(host: string) {
  await run(
    async () => sdk.backend.unignore("host", host),
    "Host removed from ignore list.",
  );
}

async function run(action: () => Promise<unknown>, success: string) {
  try {
    await action();
    sdk.window.showToast(success, { variant: "success" });
    await load();
    emit("refresh");
  } catch (cause) {
    sdk.window.showToast(safeMessage(cause), { variant: "error" });
  }
}
</script>

<template>
  <section class="hunter-page hunter-list-page">
    <div class="hunter-page-heading">
      <div>
        <span class="hunter-eyebrow">DETECTION COVERAGE</span>
        <h2>Rule library</h2>
        <p>
          Understand and tune the bundled detector pack without editing files.
        </p>
      </div>
      <div class="hunter-rule-summary">
        <strong>{{ rules.filter((rule) => !rule.ignored).length }}</strong>
        active <span>·</span
        ><strong>{{ rules.filter((rule) => rule.ignored).length }}</strong>
        ignored
      </div>
    </div>
    <div class="hunter-filterbar">
      <input
        v-model="search"
        class="hunter-input grow"
        aria-label="Search rules"
        placeholder="Search detector ID, name, severity…"
      />
      <select v-model="kind" class="hunter-select" aria-label="Rule kind">
        <option value="ALL">All rule kinds</option>
        <option>SECRET</option>
        <option>CREDENTIAL</option>
        <option>ENDPOINT</option>
        <option>IDENTIFIER</option>
        <option>CONFIGURATION</option>
      </select>
    </div>
    <div class="hunter-rules-layout">
      <div class="hunter-rule-grid" :aria-busy="loading">
        <article
          v-for="rule in filtered"
          :key="rule.id"
          class="hunter-rule-card"
          :class="{ ignored: rule.ignored }"
        >
          <div class="hunter-rule-card-top">
            <SeverityBadge :severity="rule.severity" />
            <span class="hunter-confidence"
              >{{ rule.confidence }} confidence</span
            >
          </div>
          <h3>{{ rule.name }}</h3>
          <code>{{ rule.id }}</code>
          <div class="hunter-rule-card-bottom">
            <span>{{ statusLabel(rule.kind) }}</span>
            <button
              class="hunter-button"
              :class="rule.ignored ? 'primary' : 'ghost'"
              @click="toggleRule(rule)"
            >
              {{ rule.ignored ? "Enable" : "Ignore" }}
            </button>
          </div>
        </article>
        <div v-if="filtered.length === 0 && !loading" class="hunter-empty">
          <strong>No matching rules</strong
          ><span>Try a different search or kind.</span>
        </div>
      </div>
      <aside class="hunter-panel hunter-ignore-panel">
        <span class="hunter-eyebrow">IGNORED HOSTS</span>
        <h3>Host exclusions</h3>
        <p>Findings from these exact hosts are suppressed.</p>
        <div v-if="ignoredHosts.length" class="hunter-chip-list">
          <span v-for="host in ignoredHosts" :key="host" class="hunter-chip">
            {{ host }}
            <button :aria-label="`Enable ${host}`" @click="enableHost(host)">
              ×
            </button>
          </span>
        </div>
        <div v-else class="hunter-empty compact">
          <span>No ignored hosts.</span>
        </div>
      </aside>
    </div>
  </section>
</template>
