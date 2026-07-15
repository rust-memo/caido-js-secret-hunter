<script setup lang="ts">
import type { Severity } from "backend";

const { severity } = defineProps<{ severity: Severity }>();
</script>

<template>
  <span class="hunter-badge" :class="`severity-${severity}`">
    {{ severity }}
  </span>
</template>
