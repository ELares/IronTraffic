/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

// `@types/node` is NOT on the devDependency allowlist, so `process` is declared here
// rather than imported. This is the only place the console names `process`.
declare const process: { env: Record<string, string | undefined> };

export default defineConfig({
  plugins: [preact()],
  base: "/ui/",
  build: {
    outDir: "../../crates/irontraffic-dashboard/embedded",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    sourcemap: false,
    target: "es2022",
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  define: { __BUILD_ID__: JSON.stringify(buildId()) },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});

// Exported so scripts/check-build-output.mjs can assert the character class directly
// against an in-memory string. A real OS environment variable cannot carry an embedded
// NUL code point at all (both a child process's environment and Node's own
// `process.env` setter truncate at the first NUL), so the NUL case named in the Tests
// section cannot be exercised by spawning `vite build` with `IT_BUILD_ID` set; it can
// only be exercised by calling this function directly with a string built in memory.
export function isValidBuildId(raw: string): boolean {
  return /^[A-Za-z0-9._-]{1,64}$/.test(raw);
}

// The build identifier is injected into the bundle as a source-level literal and is
// rendered into the DOM, so it is validated rather than trusted. CI sets it from a
// commit SHA, but a local or hostile environment can set it to anything.
function buildId(): string {
  const raw = process.env.IT_BUILD_ID ?? "dev";
  if (!isValidBuildId(raw)) {
    throw new Error(
      "IT_BUILD_ID must match ^[A-Za-z0-9._-]{1,64}$, got " +
        JSON.stringify(raw.slice(0, 128)),
    );
  }
  return raw;
}
