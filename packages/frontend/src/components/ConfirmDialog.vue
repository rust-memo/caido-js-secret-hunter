<script setup lang="ts">
import { nextTick, ref, watch } from "vue";

const { open } = defineProps<{
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  danger: boolean;
}>();
const emit = defineEmits<{ confirm: []; cancel: [] }>();
const confirmButton = ref<HTMLButtonElement>();

watch(
  () => open,
  async (value) => {
    if (!value) return;
    await nextTick();
    confirmButton.value?.focus();
  },
);
</script>

<template>
  <div
    v-if="open"
    class="hunter-dialog-backdrop"
    role="presentation"
    @click.self="emit('cancel')"
  >
    <section
      class="hunter-dialog"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="hunter-dialog-title"
      aria-describedby="hunter-dialog-message"
      @keydown.esc="emit('cancel')"
    >
      <div class="hunter-dialog-mark" aria-hidden="true">!</div>
      <div>
        <h2 id="hunter-dialog-title">{{ title }}</h2>
        <p id="hunter-dialog-message">{{ message }}</p>
      </div>
      <div class="hunter-actions hunter-dialog-actions">
        <button class="hunter-button ghost" @click="emit('cancel')">
          Cancel
        </button>
        <button
          ref="confirmButton"
          class="hunter-button"
          :class="danger ? 'danger solid' : 'primary'"
          @click="emit('confirm')"
        >
          {{ confirmLabel }}
        </button>
      </div>
    </section>
  </div>
</template>
