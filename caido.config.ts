import { defineConfig } from "@caido-community/dev";
import vue from "@vitejs/plugin-vue";
import path from "path";
import prefixwrap from "postcss-prefixwrap";

const id = "caido-js-secret-hunter";
export default defineConfig({
  id,
  name: "JS Secret Hunter",
  description: "Background JavaScript and text-response secret discovery and review for Caido",
  version: "1.1.0",
  author: {
    name: "rust-memo",
    email: "rust-memo@users.noreply.github.com",
    url: "https://github.com/rust-memo",
  },
  plugins: [
    {
      kind: "backend",
      id: "backend",
      root: "packages/backend",
    },
    {
      kind: "frontend",
      id: "frontend",
      root: "packages/frontend",
      backend: {
        id: "backend",
      },
      vite: {
        plugins: [vue()],
        build: {
          rollupOptions: {
            external: [
              "@caido/frontend-sdk",
              "@codemirror/autocomplete",
              "@codemirror/commands",
              "@codemirror/language",
              "@codemirror/lint",
              "@codemirror/search",
              "@codemirror/state",
              "@codemirror/view",
              "@lezer/common",
              "@lezer/highlight",
              "@lezer/lr",
              "vue",
            ],
          },
        },
        resolve: {
          alias: [
            {
              find: "@",
              replacement: path.resolve(__dirname, "packages/frontend/src"),
            },
          ],
        },
        css: {
          postcss: {
            plugins: [prefixwrap(`#plugin--${id}`)],
          },
        },
      },
    },
  ],
});
