import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [vue()],
  test: {
    environmentMatchGlobs: [
      ["packages/frontend/src/**/*.test.ts", "happy-dom"],
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      reportsDirectory: "coverage",
      include: [
        "packages/backend/src/content-classifier.ts",
        "packages/backend/src/detector.ts",
        "packages/backend/src/endpoint-extractor.ts",
        "packages/backend/src/history-policy.ts",
        "packages/backend/src/report.ts",
        "packages/backend/src/store.ts",
        "packages/frontend/src/components/ConfirmDialog.vue",
        "packages/frontend/src/components/PaginationControls.vue",
        "packages/frontend/src/components/SeverityBadge.vue",
        "packages/frontend/src/utils.ts",
      ],
      thresholds: {
        statements: 80,
        branches: 70,
        functions: 80,
        lines: 80,
      },
    },
  },
});
