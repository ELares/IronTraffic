#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The frontend merge gate for packages/dashboard.
#
# Runs the toolchain, lockfile provenance, dependency budget, lifecycle-script,
# and source-level checks. Accepts one optional argument: --selftest.
set -euo pipefail

# The manifest budget check reads package.json and asserts the allowlists and
# exact-version rules before any package is fetched.
manifest_budget_check() {
  local pkg_path="$1"
  node --eval "$(cat <<'NODE'
const fs = require('fs');
const pkgPath = process.argv[1];
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

const DEP_ALLOW = new Set([
  'preact', 'uplot', 'yaml',
  '@codemirror/state', '@codemirror/view', '@codemirror/lang-json', '@codemirror/lang-yaml'
]);
const DEV_ALLOW = new Set([
  'typescript', 'vite', '@preact/preset-vite', 'eslint', 'typescript-eslint',
  'vitest', 'jsdom', '@playwright/test', 'axe-core', 'prettier'
]);
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/;

const failures = [];
function fail(msg) {
  failures.push(msg);
}

for (const name of Object.keys(pkg.dependencies ?? {})) {
  if (!DEP_ALLOW.has(name)) {
    fail('dependency not on the allowlist: ' + name);
  }
}

for (const name of Object.keys(pkg.devDependencies ?? {})) {
  if (!DEV_ALLOW.has(name)) {
    fail('devDependency not on the allowlist: ' + name);
  }
}

for (const [name, version] of Object.entries(pkg.dependencies ?? {})) {
  if (!VERSION_RE.test(version)) {
    fail('version must be exact, found: ' + name + '@' + version);
  }
}

for (const [name, version] of Object.entries(pkg.devDependencies ?? {})) {
  if (!VERSION_RE.test(version)) {
    fail('version must be exact, found: ' + name + '@' + version);
  }
}

if (failures.length > 0) {
  for (const msg of failures) {
    console.log(msg);
  }
  process.exit(1);
}
NODE
  )" "$pkg_path"
}

# The graph budget check reads the npm ls production tree and asserts the 40
# package budget, depth cap, and termination on cycles.
graph_budget_check() {
  local npm_ls_path="$1" npm_ls_exit="$2"
  node --eval "$(cat <<'NODE'
const fs = require('fs');
const npmLsPath = process.argv[1];
const npmLsExit = parseInt(process.argv[2], 10);

const root = JSON.parse(fs.readFileSync(npmLsPath, 'utf8'));

const MAX_PROD_PACKAGES = 40;
const MAX_DEPTH = 64;

const failures = [];
function fail(msg) {
  failures.push(msg);
}

const seen = new Set();
function walk(node, depth) {
  if (depth > MAX_DEPTH) {
    fail('dependency graph deeper than 64 levels');
    return;
  }
  for (const [name, child] of Object.entries(node.dependencies ?? {})) {
    const key = name + '@' + (child.version ?? 'unknown');
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    walk(child, depth + 1);
  }
}

walk(root, 0);

if (seen.size > MAX_PROD_PACKAGES) {
  fail('production package graph has ' + seen.size + ' packages, budget is 40');
}

if (npmLsExit !== 0 && Array.isArray(root.problems) && root.problems.length > 0) {
  for (const problem of root.problems) {
    fail('npm ls problem: ' + problem);
  }
}

if (npmLsExit !== 0 && failures.length === 0) {
  fail('npm ls exited with status ' + npmLsExit);
}

if (failures.length > 0) {
  for (const msg of failures) {
    console.log(msg);
  }
  process.exit(1);
}

console.log('budget check: ' + seen.size + ' production packages');
NODE
  )" "$npm_ls_path" "$npm_ls_exit"
}

# The lockfile provenance check asserts lockfileVersion 3, npm registry origins,
# and sha512 integrity for every entry.
lockfile_check() {
  local lock_path="$1"
  node --eval "$(cat <<'NODE'
const fs = require('fs');
const path = process.argv[1];
const lock = JSON.parse(fs.readFileSync(path, 'utf8'));

const failures = [];
function fail(msg) {
  failures.push(msg);
}

if (lock.lockfileVersion !== 3) {
  fail('package-lock.json must be lockfileVersion 3, found: ' + lock.lockfileVersion);
}

for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  if (path === '') {
    continue;
  }
  if (entry.link === true) {
    continue;
  }
  if (typeof entry.resolved !== 'string') {
    fail('lockfile entry has no resolved URL: ' + path);
    continue;
  }
  if (!entry.resolved.startsWith('https://registry.npmjs.org/')) {
    fail('lockfile entry resolves outside the npm registry: ' + path + ' -> ' + entry.resolved);
  }
  if (typeof entry.integrity !== 'string' || !entry.integrity.startsWith('sha512-')) {
    fail('lockfile entry has no sha512 integrity hash: ' + path);
  }
}

if (lock.dependencies !== undefined) {
  fail('package-lock.json contains a legacy dependencies block; regenerate with npm 10 or newer');
}

if (failures.length > 0) {
  for (const msg of failures) {
    console.log(msg);
  }
  process.exit(1);
}
NODE
  )" "$lock_path"
}

# The lifecycle-script check walks node_modules and asserts that no package
# declares a lifecycle hook unless its name is listed in the exception file.
lifecycle_check() {
  local allowed_path="$1" node_modules_path="$2" rebuild="$3"
  node --eval "$(cat <<'NODE'
const fs = require('fs');
const path = require('path');
const allowedPath = process.argv[1];
const nodeModulesPath = process.argv[2];
const rebuild = process.argv[3] === 'rebuild';

const allowedText = fs.readFileSync(allowedPath, 'utf8');
const ALLOWED = new Set();
for (const raw of allowedText.split('\n')) {
  const line = raw.trim();
  if (line === '' || line.startsWith('#')) {
    continue;
  }
  ALLOWED.add(line);
}

const HOOKS = [
  'preinstall', 'install', 'postinstall', 'prepare',
  'preprepare', 'postprepare', 'prepublish'
];
const MAX_DEPTH = 64;

const failures = [];
function fail(msg) {
  failures.push(msg);
}

const foundAllowed = new Set();

function walk(dir, depth) {
  if (depth > MAX_DEPTH) {
    fail('dependency graph deeper than 64 levels');
    return;
  }
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    const child = path.join(dir, entry.name);
    const pkgJsonPath = path.join(child, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      let pkg;
      try {
        pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      } catch (e) {
        fail('unreadable package.json: ' + child);
        continue;
      }
      const scripts = pkg.scripts ?? {};
      for (const hook of HOOKS) {
        if (hook in scripts) {
          if (ALLOWED.has(pkg.name)) {
            foundAllowed.add(pkg.name);
          } else {
            fail('package declares a lifecycle script: ' + pkg.name + ' (' + hook + ')');
          }
        }
      }
    }
    walk(child, depth + 1);
  }
}

walk(nodeModulesPath, 0);

for (const name of ALLOWED) {
  if (!foundAllowed.has(name)) {
    fail('stale lifecycle-script exception, no such installed package: ' + name);
  }
}

if (failures.length > 0) {
  for (const msg of failures) {
    console.log(msg);
  }
  process.exit(1);
}

if (rebuild) {
  for (const name of ALLOWED) {
    const result = require('child_process').spawnSync(
      'npm', ['rebuild', '--foreground-scripts', name],
      { stdio: 'inherit', shell: false }
    );
    if (result.status !== 0) {
      process.exit(result.status ?? 1);
    }
  }
}
NODE
  )" "$allowed_path" "$node_modules_path" "$rebuild"
}

# Self-test runs each checker against synthetic fixtures and exits without
# installing anything.
selftest() {
  local pkg npm_ls exit_code output
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  selftest_pass() {
    local name="$1" expected="$2" pattern="$3"
    shift 3
    local output exit_code
    exit_code=0
    output="$("$@" 2>&1)" || exit_code=$?
    if [ "$exit_code" -ne "$expected" ]; then
      echo "selftest $name: expected exit $expected, got $exit_code" >&2
      echo "$output" >&2
      return 1
    fi
    if [ -n "$pattern" ] && ! grep -qF "$pattern" <<<"$output"; then
      echo "selftest $name: expected output containing '$pattern'" >&2
      echo "$output" >&2
      return 1
    fi
    echo "selftest $name: ok"
  }

  # selftest_rejects_unlisted_dependency
  pkg="$work/pkg.json"
  printf '{"dependencies":{"lodash":"4.17.21"}}\n' > "$pkg"
  npm_ls="$work/ls.json"
  printf '{"dependencies":{}}\n' > "$npm_ls"
  selftest_pass rejects_unlisted_dependency 1 'dependency not on the allowlist: lodash' \
    manifest_budget_check "$pkg" || return 1

  # selftest_rejects_unlisted_dev_dependency
  printf '{"devDependencies":{"webpack":"5.0.0"}}\n' > "$pkg"
  selftest_pass rejects_unlisted_dev_dependency 1 'devDependency not on the allowlist: webpack' \
    manifest_budget_check "$pkg" || return 1

  # selftest_rejects_range_version
  printf '{"dependencies":{"preact":"^10.29.7"}}\n' > "$pkg"
  selftest_pass rejects_range_version 1 'version must be exact' \
    manifest_budget_check "$pkg" || return 1

  # selftest_accepts_allowlisted_exact
  printf '{"dependencies":{"preact":"10.29.7"}}\n' > "$pkg"
  selftest_pass accepts_allowlisted_exact 0 '' \
    manifest_budget_check "$pkg" || return 1
  printf '{"devDependencies":{"vite":"8.0.0"}}\n' > "$pkg"
  selftest_pass accepts_allowlisted_exact_dev 0 '' \
    manifest_budget_check "$pkg" || return 1

  # selftest_accepts_missing_sections
  printf '{}\n' > "$pkg"
  selftest_pass accepts_missing_sections 0 '' \
    manifest_budget_check "$pkg" || return 1

  # selftest_rejects_graph_over_budget
  {
    printf '{"dependencies":{'
    for i in $(seq 1 41); do
      [ "$i" -ne 1 ] && printf ','
      printf '"p%d":{"version":"%d.0.0"}' "$i" "$i"
    done
    printf '}}\n'
  } > "$npm_ls"
  selftest_pass rejects_graph_over_budget 1 'budget is 40' \
    graph_budget_check "$npm_ls" 0 || return 1

  # selftest_accepts_graph_at_budget
  {
    printf '{"dependencies":{'
    for i in $(seq 1 40); do
      [ "$i" -ne 1 ] && printf ','
      printf '"p%d":{"version":"%d.0.0"}' "$i" "$i"
    done
    printf '}}\n'
  } > "$npm_ls"
  selftest_pass accepts_graph_at_budget 0 'budget check: 40 production packages' \
    graph_budget_check "$npm_ls" 0 || return 1

  # selftest_terminates_on_cyclic_graph
  printf '{"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"1.0.0","dependencies":{"a":{"version":"1.0.0"}}}}}}}\n' > "$npm_ls"
  selftest_pass terminates_on_cyclic_graph 0 'budget check: 2 production packages' \
    graph_budget_check "$npm_ls" 0 || return 1

  # selftest_rejects_graph_deeper_than_64
  node -e 'let cur={version:"1.0.0"}; for(let i=64;i>=0;i--){ cur={version:"1.0.0",dependencies:{["a"+i]:cur}}; } console.log(JSON.stringify(cur));' > "$npm_ls"
  selftest_pass rejects_graph_deeper_than_64 1 'dependency graph deeper than 64 levels' \
    graph_budget_check "$npm_ls" 0 || return 1

  # selftest_rejects_non_registry_resolved
  printf '{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"},"node_modules/preact":{"version":"10.29.7","resolved":"git+ssh://git@github.com/evil/preact.git#deadbeef","integrity":"sha512-abc="}}}\n' > "$work/lock.json"
  selftest_pass rejects_non_registry_resolved 1 'lockfile entry resolves outside the npm registry' \
    lockfile_check "$work/lock.json" || return 1

  # selftest_rejects_http_resolved
  printf '{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"},"node_modules/preact":{"version":"10.29.7","resolved":"http://registry.npmjs.org/x.tgz","integrity":"sha512-abc="}}}\n' > "$work/lock.json"
  selftest_pass rejects_http_resolved 1 'lockfile entry resolves outside the npm registry' \
    lockfile_check "$work/lock.json" || return 1

  # selftest_rejects_missing_integrity
  printf '{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"},"node_modules/preact":{"version":"10.29.7","resolved":"https://registry.npmjs.org/x.tgz"}}}\n' > "$work/lock.json"
  selftest_pass rejects_missing_integrity 1 'lockfile entry has no sha512 integrity hash' \
    lockfile_check "$work/lock.json" || return 1

  # selftest_rejects_sha1_integrity
  printf '{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"},"node_modules/preact":{"version":"10.29.7","resolved":"https://registry.npmjs.org/x.tgz","integrity":"sha1-abc="}}}\n' > "$work/lock.json"
  selftest_pass rejects_sha1_integrity 1 'lockfile entry has no sha512 integrity hash' \
    lockfile_check "$work/lock.json" || return 1

  # selftest_accepts_clean_lockfile
  printf '{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"},"node_modules/preact":{"version":"10.29.7","resolved":"https://registry.npmjs.org/preact/-/preact-10.29.7.tgz","integrity":"sha512-OpN0zzVdiaiAhxpuuj5efpIS4sY9j7bY6uR5mnj5yPzGkdkjNKSJeUThPb60Jw29QuAZgA4o+/iB49kFiaBX6g=="}}}\n' > "$work/lock.json"
  selftest_pass accepts_clean_lockfile 0 '' \
    lockfile_check "$work/lock.json" || return 1

  # selftest_rejects_lifecycle_script
  mkdir -p "$work/node_modules/evil"
  printf '{"name":"evil","scripts":{"postinstall":"x"}}\n' > "$work/node_modules/evil/package.json"
  printf '# empty\n' > "$work/allowed.txt"
  selftest_pass rejects_lifecycle_script 1 'package declares a lifecycle script: evil (postinstall)' \
    lifecycle_check "$work/allowed.txt" "$work/node_modules" no-rebuild || return 1

  # selftest_accepts_listed_lifecycle_script
  printf 'evil\n' > "$work/allowed.txt"
  selftest_pass accepts_listed_lifecycle_script 0 '' \
    lifecycle_check "$work/allowed.txt" "$work/node_modules" no-rebuild || return 1

  # selftest_rejects_stale_lifecycle_exception
  printf 'ghost\n' > "$work/allowed.txt"
  selftest_pass rejects_stale_lifecycle_exception 1 'stale lifecycle-script exception' \
    lifecycle_check "$work/allowed.txt" "$work/node_modules" no-rebuild || return 1

  # selftest_wires_api_contract_check_selftest. The real (non-selftest)
  # invocation of this gate below runs scripts/api-contract-check.sh with no
  # arguments, which checks the committed document and never reaches that
  # script's own --selftest fixtures. Without this line, CI ran two commands
  # (this gate's --selftest, then this gate for real) and between them
  # executed zero of the contract checker self-tests, so a regression in a
  # rule the committed document happens not to exercise could ship
  # unnoticed. Running the contract checker self-test as one check of THIS
  # gate self-test closes that gap without adding a third CI step.
  selftest_pass wires_api_contract_check_selftest 0 '0 failed' \
    "$(git rev-parse --show-toplevel)/scripts/api-contract-check.sh" --selftest || return 1

  echo 'selftest: all 18 checks passed'
  return 0
}

# Argument handling: at most one argument, the literal --selftest.
if [ $# -gt 1 ]; then
  echo "dashboard-gate: unknown argument: $2" >&2
  exit 2
fi
if [ $# -gt 0 ]; then
  if [ "$1" = '--selftest' ]; then
    selftest
    exit $?
  fi
  echo "dashboard-gate: unknown argument: $1" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"
cd packages/dashboard

if ! command -v node >/dev/null 2>&1; then
  echo 'dashboard-gate: node is not installed' >&2
  exit 1
fi

want_raw="$(cat .nvmrc)"
want="$(printf '%s' "$want_raw" | sed 's/^v//;s/[[:space:]]*$//')"
have="$(node --version | sed 's/^v//')"

if [ "$have" != "$want" ]; then
  echo "dashboard-gate: node $want required (from packages/dashboard/.nvmrc), found $have" >&2
  exit 1
fi

if [ ! -f package-lock.json ]; then
  echo 'dashboard-gate: package-lock.json is missing' >&2
  exit 1
fi

lockfile_check package-lock.json

manifest_budget_check package.json

# The console is a thin client of contract/openapi.v1.json: every generated
# type, network call audit and screen parity manifest is derived from it, so
# a broken contract document must fail before a single dashboard dependency
# is fetched.
echo '==> api contract check'
"$(git rev-parse --show-toplevel)/scripts/api-contract-check.sh"

npm ci --no-audit --no-fund

npm_ls_tmp="$(mktemp)"
trap 'rm -f "$npm_ls_tmp"' EXIT
npm_ls_exit=0
npm ls --omit=dev --all --json > "$npm_ls_tmp" 2>&1 || npm_ls_exit=$?

graph_budget_check "$npm_ls_tmp" "$npm_ls_exit"

if [ -d node_modules ]; then
  lifecycle_check ALLOWED-LIFECYCLE-SCRIPTS.txt node_modules rebuild
fi

npm run -s gate
