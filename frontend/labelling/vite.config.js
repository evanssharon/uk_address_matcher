import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

export default defineConfig({
  root: fileURLToPath(new URL("../../uk_address_matcher/labelling/app", import.meta.url)),
  base: "./",
  resolve: {
    alias: {
      "@duckdb/duckdb-wasm": fileURLToPath(
        new URL("./node_modules/@duckdb/duckdb-wasm", import.meta.url),
      ),
    },
  },
  build: {
    outDir: "static",
    emptyOutDir: true,
  },
});
