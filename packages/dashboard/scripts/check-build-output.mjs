#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Two modes, both invoked from the `build` script in package.json:
//
//   node scripts/check-build-output.mjs --preflight
//     Runs BEFORE `vite build`. Resolves the configured `build.outDir` and refuses to
//     continue unless it ends with `crates/irontraffic-dashboard/embedded`. `vite
//     build`'s `emptyOutDir: true` deletes the whole target directory before writing,
//     and that directory is outside the Vite project root, so a one-character edit to
//     `outDir` would otherwise be an unrecoverable deletion of committed source.
//
//   node scripts/check-build-output.mjs
//     Runs AFTER `vite build`. Asserts every invariant named in issue #377's Tests
//     section (4 through 11), then writes brotli and gzip siblings for every emitted
//     `.js`, `.css`, `.svg` and `.html` file so the Rust handler never compresses on
//     the request path.
//
// Exits 1 naming the first failed assertion.

import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import {
  brotliCompressSync,
  brotliDecompressSync,
  constants as zlibConstants,
  gunzipSync,
  gzipSync,
} from "node:zlib";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(SCRIPT_DIR, "..");
const VITE_CONFIG_PATH = path.join(PACKAGE_ROOT, "vite.config.ts");
const SRC_DIR = path.join(PACKAGE_ROOT, "src");

// The one location `vite.config.ts` is allowed to write to. Post-build mode assumes
// this literally, rather than re-resolving the Vite config, because preflight mode
// already refused to let `vite build` run at all unless the configured `outDir`
// resolves to exactly this path.
const EMBEDDED_DIR = path.resolve(
  PACKAGE_ROOT,
  "..",
  "..",
  "crates",
  "irontraffic-dashboard",
  "embedded",
);
const EXPECTED_OUTDIR_TAIL = ["crates", "irontraffic-dashboard", "embedded"];

// 3 MiB. Every byte here ends up in the release binary's read-only data. May only be
// ratcheted down by a later issue; see the Design section of #377.
const BUDGET_BYTES = 3 * 1024 * 1024;

const COMPRESSIBLE_EXTENSIONS = new Set([".js", ".css", ".svg", ".html"]);

function fail(testName, message) {
  console.error(`check-build-output: ${testName}: ${message}`);
  process.exit(1);
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full));
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Preflight: resolve `build.outDir` and refuse to run `vite build` unless it
// ends with crates/irontraffic-dashboard/embedded.
// ---------------------------------------------------------------------------
async function preflight() {
  const { resolveConfig } = await import("vite");
  let resolved;
  try {
    resolved = await resolveConfig(
      { root: PACKAGE_ROOT },
      "build",
      "production",
      "production",
    );
  } catch (err) {
    // A config load failure here is most often `buildId()` rejecting a hostile or
    // malformed `IT_BUILD_ID`, since `define` evaluates it eagerly. That error
    // already names IT_BUILD_ID; surface it as is rather than masking it with an
    // outDir-shaped message that would not match what actually went wrong.
    console.error(`check-build-output: preflight: ${err.message}`);
    process.exit(1);
    return;
  }
  const resolvedOutDir = path.resolve(resolved.root, resolved.build.outDir);
  const segments = resolvedOutDir.split(path.sep).filter((s) => s.length > 0);
  const tail = segments.slice(-EXPECTED_OUTDIR_TAIL.length);
  const matches =
    tail.length === EXPECTED_OUTDIR_TAIL.length &&
    tail.every((segment, i) => segment === EXPECTED_OUTDIR_TAIL[i]);
  if (!matches) {
    console.error(`refusing to build: outDir is ${resolvedOutDir}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Post-build assertions (tests 4 through 11) plus precompression.
// ---------------------------------------------------------------------------

function readIndexHtml() {
  const indexPath = path.join(EMBEDDED_DIR, "index.html");
  if (!existsSync(indexPath)) {
    fail("embedded_index_html_exists", `${indexPath} does not exist`);
  }
  return readFileSync(indexPath, "utf8");
}

// Not one of the numbered tests, but the enumerate-and-reject counterpart to all of
// them: every other assertion here checks a PROPERTY of files it already expects to
// find, so a file it never goes looking for (an extra entry sitting at the root of
// embedded/, or a stray directory beside assets/) would otherwise pass silently. This
// walks the top level of embedded/ and fails on anything other than the exact
// index.html (plus its .br/.gz siblings) and the assets/ directory. Everything under
// assets/ is still checked by testAssetsAreContentHashed's pattern match, which
// applies to every file there regardless of extension, so a stray non-hashed file
// nested under assets/ is already rejected without a second walk here.
function testNoUnexpectedFiles() {
  const allowedRootFiles = new Set([
    "index.html",
    "index.html.br",
    "index.html.gz",
  ]);
  const allowedRootDirs = new Set(["assets"]);
  for (const entry of readdirSync(EMBEDDED_DIR, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!allowedRootDirs.has(entry.name)) {
        fail(
          "no_unexpected_files",
          `unexpected directory at embedded/${entry.name}/`,
        );
      }
      continue;
    }
    if (!entry.isFile()) {
      fail(
        "no_unexpected_files",
        `unexpected non-regular entry at embedded/${entry.name}`,
      );
      continue;
    }
    if (!allowedRootFiles.has(entry.name)) {
      fail("no_unexpected_files", `unexpected file at embedded/${entry.name}`);
    }
  }
}

// 4. no_inline_script_or_style
function testNoInlineScriptOrStyle(html) {
  if (/<script(?![^>]*\bsrc=)/.test(html)) {
    fail(
      "no_inline_script_or_style",
      "embedded/index.html contains an inline <script> element",
    );
  }
  if (/<style/.test(html)) {
    fail(
      "no_inline_script_or_style",
      "embedded/index.html contains a <style> element",
    );
  }
}

// 5. assets_are_content_hashed
function testAssetsAreContentHashed() {
  const assetsDir = path.join(EMBEDDED_DIR, "assets");
  if (!existsSync(assetsDir)) {
    fail("assets_are_content_hashed", `${assetsDir} does not exist`);
  }
  const names = walk(assetsDir).map((f) => path.basename(f));
  const pattern =
    /^[A-Za-z0-9_.-]+-[A-Za-z0-9_-]{8,}\.(js|css|svg|woff2)(\.br|\.gz)?$/;
  // A .br/.gz sibling counts as a hashed name under the pattern above, so checking
  // `names.length === 0` alone would pass on an assets/ directory that holds only
  // compressed siblings with their uncompressed source deleted. Require at least one
  // PRIMARY (uncompressed) asset; testNoOrphanedCompressedSiblings separately catches
  // a compressed file whose source went missing while other primaries remain.
  const primaryNames = names.filter(
    (n) => !n.endsWith(".br") && !n.endsWith(".gz"),
  );
  if (primaryNames.length === 0) {
    fail(
      "assets_are_content_hashed",
      "embedded/assets/ has no primary (uncompressed) hashed asset",
    );
  }
  for (const name of names) {
    if (!pattern.test(name)) {
      fail(
        "assets_are_content_hashed",
        `embedded/assets/${name} does not match ${pattern}`,
      );
    }
  }
}

// The counterpart to writePrecompressedSiblings: every .br or .gz file anywhere under
// embedded/ must have a live uncompressed sibling. Without this, deleting an
// uncompressed asset while leaving its compressed siblings behind is invisible to
// every other check here, because each of them locates its inputs by walking for a
// specific extension and iterates zero times, which looks identical to "nothing was
// ever wrong" rather than "the thing this depends on is gone."
function testNoOrphanedCompressedSiblings() {
  for (const file of walk(EMBEDDED_DIR)) {
    if (!file.endsWith(".br") && !file.endsWith(".gz")) {
      continue;
    }
    const source = file.slice(0, -3);
    if (!existsSync(source)) {
      fail(
        "no_orphaned_compressed_siblings",
        `${path.relative(EMBEDDED_DIR, file)} has no matching uncompressed file at ${path.relative(EMBEDDED_DIR, source)}`,
      );
    }
  }
}

// 6. no_sourcemaps_emitted
function testNoSourcemapsEmitted() {
  const maps = walk(EMBEDDED_DIR).filter((f) => f.endsWith(".map"));
  if (maps.length > 0) {
    fail("no_sourcemaps_emitted", `found .map file(s): ${maps.join(", ")}`);
  }
}

// 7. no_eval_in_output
function testNoEvalInOutput() {
  const jsFiles = walk(EMBEDDED_DIR).filter((f) => f.endsWith(".js"));
  const forbidden = ["eval(", "new Function(", "document.write("];
  for (const file of jsFiles) {
    const content = readFileSync(file, "utf8");
    for (const needle of forbidden) {
      if (content.includes(needle)) {
        fail(
          "no_eval_in_output",
          `${path.relative(EMBEDDED_DIR, file)} contains ${JSON.stringify(needle)}`,
        );
      }
    }
  }
}

// Shared by the writer and the checker so the two can never drift apart, and so the
// checker can recompute the expected bytes from scratch rather than trust what is on
// disk (see testPrecompressedSiblingsExistAndDecompress below).
function compressBrotli(input) {
  return brotliCompressSync(input, {
    params: {
      [zlibConstants.BROTLI_PARAM_QUALITY]: zlibConstants.BROTLI_MAX_QUALITY,
      [zlibConstants.BROTLI_PARAM_SIZE_HINT]: input.length,
    },
  });
}
function compressGzip(input) {
  return gzipSync(input, { level: 9 });
}

// Precompression: brotli quality 11 (size hint set) and gzip level 9, sibling written
// only when smaller than the input. Runs over every emitted .js, .css, .svg and .html
// file, which is a superset of what test 7b checks (.js and .css under assets/).
function writePrecompressedSiblings() {
  const targets = walk(EMBEDDED_DIR).filter((f) =>
    COMPRESSIBLE_EXTENSIONS.has(path.extname(f)),
  );
  for (const file of targets) {
    const input = readFileSync(file);
    const br = compressBrotli(input);
    if (br.length < input.length) {
      writeFileSync(`${file}.br`, br);
    }
    const gz = compressGzip(input);
    if (gz.length < input.length) {
      writeFileSync(`${file}.gz`, gz);
    }
  }
}

// 7b. precompressed_siblings_exist_and_decompress
function testPrecompressedSiblingsExistAndDecompress() {
  const assetsDir = path.join(EMBEDDED_DIR, "assets");
  const jsAndCss = existsSync(assetsDir)
    ? walk(assetsDir).filter((f) => f.endsWith(".js") || f.endsWith(".css"))
    : [];
  for (const file of jsAndCss) {
    const input = readFileSync(file);
    const brPath = `${file}.br`;
    const gzPath = `${file}.gz`;
    if (!existsSync(brPath)) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `missing ${path.relative(EMBEDDED_DIR, brPath)}`,
      );
    }
    if (!existsSync(gzPath)) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `missing ${path.relative(EMBEDDED_DIR, gzPath)}`,
      );
    }
    const brBytes = readFileSync(brPath);
    const gzBytes = readFileSync(gzPath);
    if (brBytes.length >= input.length) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, brPath)} (${brBytes.length} bytes) is not smaller than its input (${input.length} bytes)`,
      );
    }
    if (gzBytes.length >= input.length) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, gzPath)} (${gzBytes.length} bytes) is not smaller than its input (${input.length} bytes)`,
      );
    }
    // Decompression alone is not a sufficient integrity check: Node's brotli decoder
    // silently ignores trailing bytes appended after a complete, valid stream and
    // still returns the correct content (verified directly; corrupting a .br file by
    // appending garbage decompresses cleanly with no error and no mismatch). Wrap the
    // decode in try/catch, since a genuinely malformed stream (mid-stream corruption,
    // which both codecs do detect) throws rather than returning wrong bytes, and
    // additionally recompute the expected compressed bytes from the live input with
    // the exact same parameters the writer used and require an exact match. That
    // catches trailing-byte corruption, truncation and any other tamper that
    // decompress-and-compare alone would miss, the same way a hash comparison would if
    // this format carried one.
    let brDecoded;
    try {
      brDecoded = brotliDecompressSync(brBytes);
    } catch (err) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, brPath)} failed to decompress: ${err.message}`,
      );
    }
    if (!brDecoded.equals(input)) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, brPath)} does not decompress to its input byte for byte`,
      );
    }
    if (!compressBrotli(input).equals(brBytes)) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, brPath)} does not match a fresh brotli compression of its input; the stored file is stale or corrupted`,
      );
    }
    let gzDecoded;
    try {
      gzDecoded = gunzipSync(gzBytes);
    } catch (err) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, gzPath)} failed to decompress: ${err.message}`,
      );
    }
    if (!gzDecoded.equals(input)) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, gzPath)} does not decompress to its input byte for byte`,
      );
    }
    if (!compressGzip(input).equals(gzBytes)) {
      fail(
        "precompressed_siblings_exist_and_decompress",
        `${path.relative(EMBEDDED_DIR, gzPath)} does not match a fresh gzip compression of its input; the stored file is stale or corrupted`,
      );
    }
  }
}

// 8. no_preact_compat
function testNoPreactCompat() {
  const needle = "preact/compat";
  const sourceFiles = [
    ...(existsSync(SRC_DIR) ? walk(SRC_DIR) : []),
    ...readdirSync(PACKAGE_ROOT, { withFileTypes: true })
      .filter((e) => e.isFile() && /\.tsx?$/.test(e.name))
      .map((e) => path.join(PACKAGE_ROOT, e.name)),
  ];
  for (const file of sourceFiles) {
    const content = readFileSync(file, "utf8");
    if (content.includes(needle)) {
      fail(
        "no_preact_compat",
        `${path.relative(PACKAGE_ROOT, file)} references ${needle}`,
      );
    }
  }
  const emittedJs = walk(EMBEDDED_DIR).filter((f) => f.endsWith(".js"));
  for (const file of emittedJs) {
    const content = readFileSync(file, "utf8");
    if (content.includes(needle)) {
      fail(
        "no_preact_compat",
        `${path.relative(EMBEDDED_DIR, file)} references ${needle}`,
      );
    }
  }
}

// 9. no_remote_references_in_document
function testNoRemoteReferencesInDocument(html) {
  const attrPattern = /\s(?:src|href)="([^"]*)"/g;
  let match = attrPattern.exec(html);
  let found = 0;
  while (match !== null) {
    found += 1;
    const value = match[1];
    if (!value.startsWith("/ui/")) {
      fail(
        "no_remote_references_in_document",
        `attribute value ${JSON.stringify(value)} does not begin with /ui/`,
      );
    }
    match = attrPattern.exec(html);
  }
  if (found === 0) {
    fail(
      "no_remote_references_in_document",
      "embedded/index.html has no src= or href= attribute to check",
    );
  }
}

// 10. embedded_tree_within_budget
function testEmbeddedTreeWithinBudget() {
  const total = walk(EMBEDDED_DIR).reduce(
    (sum, f) => sum + statSync(f).size,
    0,
  );
  if (total > BUDGET_BYTES) {
    fail(
      "embedded_tree_within_budget",
      `embedded tree is ${total} bytes, budget is ${BUDGET_BYTES}`,
    );
  }
}

// 11. build_id_is_validated
//
// The accept case and four of the five reject cases go through a real `vite build`
// subprocess with IT_BUILD_ID set, each writing to its own temporary directory well
// outside crates/irontraffic-dashboard/embedded so the committed tree is never
// touched. The fifth reject case (a string containing a NUL code point) cannot be
// carried through a process environment variable at all: both a child process's
// environment and Node's own `process.env` setter truncate a string at its first NUL
// byte (verified directly: writing "abc\0def" to process.env.X and reading it back
// yields "abc"). That case is asserted instead by importing the exported
// `isValidBuildId` helper from vite.config.ts and calling it with a string built in
// memory, which never crosses a process boundary.
async function testBuildIdIsValidated() {
  const viteBin = path.join(
    PACKAGE_ROOT,
    "node_modules",
    "vite",
    "bin",
    "vite.js",
  );
  if (!existsSync(viteBin)) {
    fail("build_id_is_validated", `${viteBin} does not exist`);
  }

  const subprocessCases = [
    { value: "abc-123.4", shouldFail: false },
    { value: "", shouldFail: true },
    { value: "a".repeat(65), shouldFail: true },
    { value: "a b", shouldFail: true },
    { value: "</script>", shouldFail: true },
  ];

  for (const { value, shouldFail } of subprocessCases) {
    const tmpDir = mkdtempSync(path.join(tmpdir(), "it-build-id-"));
    try {
      const result = spawnSync(
        process.execPath,
        [
          viteBin,
          "build",
          "--outDir",
          tmpDir,
          "--emptyOutDir",
          "--logLevel",
          "error",
        ],
        {
          cwd: PACKAGE_ROOT,
          env: { ...process.env, IT_BUILD_ID: value },
          encoding: "utf8",
        },
      );
      const failed = result.status !== 0;
      if (failed !== shouldFail) {
        fail(
          "build_id_is_validated",
          `IT_BUILD_ID=${JSON.stringify(value)} expected ${shouldFail ? "failure" : "success"}, got exit ${result.status}`,
        );
      }
      if (shouldFail && !(result.stderr ?? "").includes("IT_BUILD_ID")) {
        fail(
          "build_id_is_validated",
          `IT_BUILD_ID=${JSON.stringify(value)} failed but its message did not name IT_BUILD_ID: ${result.stderr}`,
        );
      }
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  const { isValidBuildId } = await import(pathToFileURL(VITE_CONFIG_PATH).href);
  if (typeof isValidBuildId !== "function") {
    fail(
      "build_id_is_validated",
      "vite.config.ts does not export isValidBuildId",
    );
  }
  const nulString = `abc${String.fromCharCode(0)}def`;
  if (isValidBuildId(nulString)) {
    fail(
      "build_id_is_validated",
      "isValidBuildId accepted a string containing a NUL code point",
    );
  }
  if (!isValidBuildId("abc-123.4")) {
    fail(
      "build_id_is_validated",
      "isValidBuildId rejected the valid value abc-123.4",
    );
  }
}

async function postBuild() {
  const html = readIndexHtml();
  testNoUnexpectedFiles();
  testNoOrphanedCompressedSiblings();
  testNoInlineScriptOrStyle(html);
  testAssetsAreContentHashed();
  testNoSourcemapsEmitted();
  testNoEvalInOutput();
  writePrecompressedSiblings();
  testPrecompressedSiblingsExistAndDecompress();
  testNoPreactCompat();
  testNoRemoteReferencesInDocument(html);
  testEmbeddedTreeWithinBudget();
  await testBuildIdIsValidated();
  console.log("check-build-output: all assertions passed");
}

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--preflight")) {
  console.error(`check-build-output: unknown arguments: ${args.join(" ")}`);
  process.exit(2);
}

if (args[0] === "--preflight") {
  await preflight();
} else {
  await postBuild();
}
