#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Validates contract/openapi.v1.json against its own house rules: every
# operation carries a permission from the closed vocabulary and a safe irtctl
# command, every path parameter is bounded, every response set is complete,
# every $ref resolves, and every component is used. See contract/README.md for
# what this document is and who may change it.
#
# WHY A CHECKER AND NOT A SCHEMA VALIDATOR. contract/openapi.v1.json is valid
# OpenAPI 3.1, which a generic validator would accept unchanged: OpenAPI does
# not know that this project requires a Csrf header on every mutation, or that
# an rtctl command must never reach a shell. Those are house rules, so this
# script enumerates them by hand rather than delegating to a schema.
#
# FAIL CLOSED. Every check below is a positive assertion over the parsed
# document: it enumerates what is required and fails on anything that does
# not satisfy it, rather than scanning for a specific known-bad pattern. An
# empty document is caught by the per-operation structural checks having
# nothing to satisfy them (x-it-operation-count itself, step 16). A deleted
# operation, an added one, or a mutated path, method or permission on an
# EXISTING operation are caught by step 23, which pins the operation set and
# the permission vocabulary #380 froze against a copy of that table living in
# this script (FROZEN_OPERATIONS, FROZEN_PERMISSION_VOCABULARY), not against
# anything read out of the document under test: a check that compares the
# document to a value read from the same document proves only internal
# consistency, and step 6 and step 16 alone do exactly that. See the
# self-test steps below and the implementation's own PR description for a
# record of each failure mode proven to fail loud, then reverted to green.
#
# Implemented with node --eval reading the JSON, so it needs no npm package.
#
# Usage:  scripts/api-contract-check.sh              (checks contract/openapi.v1.json)
#         scripts/api-contract-check.sh --selftest   (runs the 38 named self-tests)
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  echo 'api-contract-check: node is not installed' >&2
  exit 1
fi

JS="$(cat <<'NODE'
'use strict';

const METHODS = ['get', 'put', 'post', 'patch', 'delete'];

// step 23: the frozen operation set and the frozen permission vocabulary,
// reproduced here from the operation table in issue 380, BY THE CHECKER,
// rather than read out of the document under test. Step 6 and step 16
// already compare the document to itself (a permission against
// x-it-permissions, a count against x-it-operation-count, both read from the
// same file); neither can catch a mutation that edits both the operation and
// the value it is checked against in the same stroke. This pair of constants
// is a copy the checker keeps of what issue 380 froze, so an edit to the
// document alone cannot pass step 23.
//
// Each entry is [operationId, METHOD, path, x-it-permission], in the order
// the operation table in issue 380 lists them. Do not derive this array from
// the document at runtime: that would reintroduce the exact defect this step
// exists to close.
const FROZEN_OPERATIONS = [
  ['getOverview', 'GET', '/overview', 'overview:read'],
  ['getWhoami', 'GET', '/whoami', 'none'],
  ['getStatsTimeseries', 'GET', '/stats/timeseries', 'stats:read'],
  ['getStatsTopN', 'GET', '/stats/topn', 'stats:read'],
  ['getConfig', 'GET', '/config', 'config:read'],
  ['listConfigKind', 'GET', '/config/{kind}', 'config:read'],
  ['getConfigResource', 'GET', '/config/{kind}/{ns}/{name}', 'config:read'],
  ['putConfigResource', 'PUT', '/config/{kind}/{ns}/{name}', 'config:write'],
  ['patchConfigResource', 'PATCH', '/config/{kind}/{ns}/{name}', 'config:write'],
  ['deleteConfigResource', 'DELETE', '/config/{kind}/{ns}/{name}', 'config:write'],
  ['loadConfig', 'POST', '/config:load', 'config:write'],
  ['dryrunConfig', 'POST', '/config:dryrun', 'config:read'],
  ['adaptConfig', 'POST', '/config:adapt', 'config:read'],
  ['rollbackConfig', 'POST', '/config:rollback', 'config:write'],
  ['getFreeze', 'GET', '/config/freeze', 'config:read'],
  ['unfreezeConfig', 'DELETE', '/config/freeze', 'config:freeze'],
  ['freezeConfig', 'POST', '/config:freeze', 'config:freeze'],
  ['listConfigVersions', 'GET', '/config/versions', 'config:read'],
  ['getConfigVersion', 'GET', '/config/versions/{version}', 'config:read'],
  ['diffConfigVersions', 'GET', '/config/versions/{from}/diff/{to}', 'config:read'],
  ['createTransaction', 'POST', '/transactions', 'config:write'],
  ['getTransaction', 'GET', '/transactions/{id}', 'config:read'],
  ['abortTransaction', 'DELETE', '/transactions/{id}', 'config:write'],
  ['commitTransaction', 'POST', '/transactions/{id}:commit', 'config:write'],
  ['getStatus', 'GET', '/status', 'config:read'],
  ['getRouteEffective', 'GET', '/routes/{id}/effective', 'config:read'],
  ['explainRequest', 'POST', '/explain', 'explain:run'],
  ['getRecordedExplain', 'GET', '/explain/requests/{request_id}', 'explain:run'],
  ['listRuntimeUpstreams', 'GET', '/runtime/upstreams', 'runtime:read'],
  ['getUpstreamEndpoints', 'GET', '/runtime/upstreams/{id}/endpoints', 'runtime:read'],
  ['getUpstreamEvents', 'GET', '/runtime/upstreams/{id}/events', 'runtime:read'],
  ['queryLogs', 'GET', '/logs/query', 'logs:read'],
  ['streamLogs', 'GET', '/logs/stream', 'logs:read'],
  ['streamEvents', 'GET', '/events/stream', 'events:read'],
  ['getTrace', 'GET', '/traces/{trace_id}', 'traces:read'],
  ['listCerts', 'GET', '/certs', 'certs:read'],
  ['getCert', 'GET', '/certs/{id}', 'certs:read'],
  ['listAcmeOrders', 'GET', '/acme/orders', 'certs:read'],
  ['listLimits', 'GET', '/limits', 'limits:read'],
  ['getLimitTopK', 'GET', '/limits/topk', 'limits:read'],
  ['getLimitKey', 'GET', '/limits/keys/{key}', 'limits:read'],
  ['listClusterNodes', 'GET', '/cluster/nodes', 'cluster:read'],
  ['queryAudit', 'GET', '/audit', 'audit:read'],
  ['verifyAuditChain', 'GET', '/audit/verify', 'audit:read'],
  ['listSessions', 'GET', '/sessions', 'sessions:read'],
  ['revokeSession', 'DELETE', '/sessions/{id}', 'sessions:manage'],
  ['listTokens', 'GET', '/tokens', 'tokens:read'],
  ['createToken', 'POST', '/tokens', 'tokens:manage'],
  ['revokeToken', 'DELETE', '/tokens/{id}', 'tokens:manage'],
  ['listRoles', 'GET', '/roles', 'rbac:read'],
  ['listApimProducts', 'GET', '/apim/products', 'apim:read'],
  ['getApimProduct', 'GET', '/apim/products/{id}', 'apim:read'],
  ['listApimPlans', 'GET', '/apim/plans', 'apim:read'],
  ['listApimConsumers', 'GET', '/apim/consumers', 'apim:read'],
  ['getApimConsumer', 'GET', '/apim/consumers/{id}', 'apim:read'],
  ['listApimCredentials', 'GET', '/apim/consumers/{id}/credentials', 'apim:read'],
  ['createApimCredential', 'POST', '/apim/consumers/{id}/credentials', 'apim:write'],
  ['deleteApimCredential', 'DELETE', '/apim/consumers/{id}/credentials/{credential_id}', 'apim:write'],
  ['getApimAnalytics', 'GET', '/apim/analytics', 'apim:read'],
  ['getSupportBundle', 'GET', '/support-bundle', 'support:read'],
  ['getSchema', 'GET', '/schema.json', 'none'],
  ['getOpenapi', 'GET', '/openapi.json', 'none'],
];

// The closed permission vocabulary #380 defines, in the order the issue lists
// it. x-it-permissions in the document must equal this exactly: not a
// subset, not a superset, and not merely the same set in a different order,
// so that a widened vocabulary (a permission string added and then used by
// some operation) cannot pass just because it is internally consistent.
const FROZEN_PERMISSION_VOCABULARY = [
  'none',
  'overview:read', 'stats:read', 'config:read', 'config:write', 'config:freeze',
  'runtime:read', 'explain:run', 'logs:read', 'events:read', 'traces:read',
  'certs:read', 'limits:read', 'cluster:read', 'audit:read', 'rbac:read',
  'sessions:read', 'sessions:manage', 'tokens:read', 'tokens:manage',
  'apim:read', 'apim:write', 'support:read',
];

// The path-parameter vocabulary the operation table in issue 380 pins:
// name -> { maxLength, pattern }. Step 24 on its own only checks that A
// pattern is present, of nonzero length; "^.*$" satisfies that and matches
// anything. This is a record the checker keeps of the exact bound named for
// each parameter name, so a pattern widened to something vacuous cannot pass
// merely because a pattern is there. Reproduced here rather than derived
// from the document at runtime, for the same reason FROZEN_OPERATIONS is.
const FROZEN_PATH_PARAMETER_VOCABULARY = {
  kind: { maxLength: 64, pattern: '^[a-z][a-z0-9-]{0,63}$' },
  ns: { maxLength: 63, pattern: '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' },
  name: { maxLength: 253, pattern: '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' },
  id: { maxLength: 128, pattern: '^[A-Za-z0-9._-]{1,128}$' },
  credential_id: { maxLength: 128, pattern: '^[A-Za-z0-9._-]{1,128}$' },
  version: { maxLength: 41, pattern: '^[0-9]{1,20}-[0-9]{1,20}$' },
  from: { maxLength: 41, pattern: '^[0-9]{1,20}-[0-9]{1,20}$' },
  to: { maxLength: 41, pattern: '^[0-9]{1,20}-[0-9]{1,20}$' },
  trace_id: { maxLength: 32, pattern: '^[0-9a-f]{32}$' },
  request_id: { maxLength: 64, pattern: '^[A-Za-z0-9._-]{1,64}$' },
  key: { maxLength: 128, pattern: '^[A-Za-z0-9._:~-]{1,128}$' },
};

function decodeJsonPointerSegment(s) {
  return s.replace(/~1/g, '/').replace(/~0/g, '~');
}
function encodeJsonPointerSegment(s) {
  return String(s).replace(/~/g, '~0').replace(/\//g, '~1');
}

// A hand-written recursive-descent JSON parser, because JSON.parse keeps the
// LAST occurrence of a duplicate object key with no diagnostic at all. On a
// hand-maintained multi-thousand-line document that is a live fail-open
// path: a second "x-it-permission": "none" inserted after the real one makes
// the effective permission "none" while the visible line above still reads
// something else, and a plain JSON.parse-based checker has no way to notice.
// This function rejects a duplicate key at parse time and names the JSON
// Pointer of the object it was duplicated in.
//
// It otherwise implements the JSON grammar directly (object, array, string,
// number, true, false, null) rather than delegating to JSON.parse per node,
// because the only way to see every key as it is parsed, in insertion order,
// with the object it belongs to still in scope, is to build the object one
// key at a time.
function parseJsonRejectingDuplicateKeys(text) {
  let i = 0;
  const n = text.length;

  function lineColAt(pos) {
    const upto = text.slice(0, pos);
    const lines = upto.split('\n');
    return { line: lines.length, col: lines[lines.length - 1].length + 1 };
  }

  function fail(message, pos) {
    const at = lineColAt(pos === undefined ? i : pos);
    const e = new Error(message);
    e.line = at.line;
    e.col = at.col;
    throw e;
  }

  function skipWs() {
    while (i < n) {
      const c = text[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i += 1; } else { break; }
    }
  }

  function parseValue(pointer) {
    skipWs();
    if (i >= n) fail('unexpected end of input, expected a value');
    const c = text[i];
    if (c === '{') return parseObject(pointer);
    if (c === '[') return parseArray(pointer);
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    fail('unexpected token ' + JSON.stringify(c) + ', expected a value');
  }

  function parseNumber() {
    const start = i;
    if (text[i] === '-') i += 1;
    if (text[i] === '0') {
      i += 1;
    } else if (text[i] >= '1' && text[i] <= '9') {
      while (i < n && text[i] >= '0' && text[i] <= '9') i += 1;
    } else {
      fail('invalid number');
    }
    if (text[i] === '.') {
      i += 1;
      if (!(text[i] >= '0' && text[i] <= '9')) fail('invalid number: no digit after decimal point');
      while (i < n && text[i] >= '0' && text[i] <= '9') i += 1;
    }
    if (text[i] === 'e' || text[i] === 'E') {
      i += 1;
      if (text[i] === '+' || text[i] === '-') i += 1;
      if (!(text[i] >= '0' && text[i] <= '9')) fail('invalid number: no digit in exponent');
      while (i < n && text[i] >= '0' && text[i] <= '9') i += 1;
    }
    return Number(text.slice(start, i));
  }

  function parseString() {
    const startPos = i;
    i += 1; // opening quote
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string', startPos);
      const c = text[i];
      if (c === '"') { i += 1; return out; }
      if (c === '\\') {
        i += 1;
        if (i >= n) fail('unterminated escape sequence', startPos);
        const e = text[i];
        if (e === 'n') out += '\n';
        else if (e === 't') out += '\t';
        else if (e === 'r') out += '\r';
        else if (e === 'b') out += '\b';
        else if (e === 'f') out += '\f';
        else if (e === '"') out += '"';
        else if (e === '\\') out += '\\';
        else if (e === '/') out += '/';
        else if (e === 'u') {
          const hex = text.slice(i + 1, i + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('invalid unicode escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else {
          fail('invalid escape character ' + JSON.stringify(e));
        }
        i += 1;
      } else if (c.charCodeAt(0) < 0x20) {
        fail('unescaped control character in string', startPos);
      } else {
        out += c;
        i += 1;
      }
    }
  }

  function parseObject(pointer) {
    i += 1; // {
    const obj = {};
    const seenKeys = new Set();
    skipWs();
    if (text[i] === '}') { i += 1; return obj; }
    for (;;) {
      skipWs();
      if (text[i] !== '"') fail('expected a string key');
      const keyPos = i;
      const key = parseString();
      if (seenKeys.has(key)) {
        fail('duplicate key ' + JSON.stringify(key) + ' at JSON Pointer ' +
          pointer + '/' + encodeJsonPointerSegment(key), keyPos);
      }
      seenKeys.add(key);
      skipWs();
      if (text[i] !== ':') fail('expected : after an object key');
      i += 1;
      const value = parseValue(pointer + '/' + encodeJsonPointerSegment(key));
      obj[key] = value;
      skipWs();
      if (text[i] === ',') { i += 1; continue; }
      if (text[i] === '}') { i += 1; break; }
      fail('expected , or } in an object');
    }
    return obj;
  }

  function parseArray(pointer) {
    i += 1; // [
    const arr = [];
    skipWs();
    if (text[i] === ']') { i += 1; return arr; }
    let idx = 0;
    for (;;) {
      const value = parseValue(pointer + '/' + idx);
      arr.push(value);
      idx += 1;
      skipWs();
      if (text[i] === ',') { i += 1; continue; }
      if (text[i] === ']') { i += 1; break; }
      fail('expected , or ] in an array');
    }
    return arr;
  }

  const result = parseValue('');
  skipWs();
  if (i !== n) fail('unexpected trailing content after the JSON value');
  return result;
}

function resolveRef(doc, ref) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) return undefined;
  const segs = ref.slice(2).split('/').map(decodeJsonPointerSegment);
  let cur = doc;
  for (const s of segs) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = cur[s];
  }
  return cur;
}

function collectRefs(node, pointer, out) {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => collectRefs(v, pointer + '/' + i, out));
    return;
  }
  if (typeof node['$ref'] === 'string') {
    out.push({ ref: node['$ref'], pointer: pointer + '/$ref' });
  }
  for (const k of Object.keys(node)) {
    collectRefs(node[k], pointer + '/' + encodeJsonPointerSegment(k), out);
  }
}

function resolveParam(doc, raw) {
  if (raw && typeof raw['$ref'] === 'string') {
    const r = resolveRef(doc, raw['$ref']);
    if (!r) return { name: undefined, in: undefined, required: undefined, schema: undefined };
    return r;
  }
  return raw || {};
}

function templateParamNames(p) {
  const names = [];
  const segments = p.split(/[/:]/);
  for (const seg of segments) {
    const m = /^\{([^}]*)\}$/.exec(seg);
    if (m) names.push(m[1]);
  }
  return names;
}

// Type in a 3.1 schema is either a plain string ("string") or an array of
// strings (["string", "null"]); both forms are standard and this document
// declares openapi: 3.1.0, so a node with a type ARRAY containing "string"
// or "array" is exactly as much a string or an array as one with a plain
// type STRING, and must be bounded the same way.
function schemaHasType(node, t) {
  if (typeof node.type === 'string') return node.type === t;
  if (Array.isArray(node.type)) return node.type.includes(t);
  return false;
}

// Follow a chain of $ref indirection to the schema it ultimately names,
// guarding against a cycle with a visited set of ref strings seen on THIS
// chain. Returns undefined for a dangling ref (step 13 reports that
// separately) or a cycle, never throws.
function resolveSchemaRef(doc, node, visited) {
  let cur = node;
  const seen = visited || new Set();
  while (cur && typeof cur === 'object' && typeof cur['$ref'] === 'string') {
    if (seen.has(cur['$ref'])) return undefined;
    seen.add(cur['$ref']);
    cur = resolveRef(doc, cur['$ref']);
  }
  return cur;
}

// Walks a schema node, resolving $ref before every test so the rule applies
// identically to an inline schema and to a named component reached through
// any number of $ref indirections, and recurses into every composition and
// map keyword OpenAPI 3.1 (which is JSON Schema 2020-12) defines: properties,
// items, prefixItems, additionalProperties, patternProperties, allOf, anyOf
// and oneOf. opId and pointer name the operation and JSON Pointer an
// unbounded node is reported at; visited is the $ref cycle guard threaded
// through the whole walk, not reset per branch, so a cycle anywhere in the
// composition is caught once rather than looping.
function checkBoundedSchema(doc, node, opId, pointer, failures, visited) {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => checkBoundedSchema(doc, v, opId, pointer + '/' + i, failures, visited));
    return;
  }
  if (typeof node['$ref'] === 'string') {
    const ref = node['$ref'];
    if (visited.has(ref)) return; // cycle: already walked this ref on this chain
    const resolved = resolveRef(doc, ref);
    if (resolved === undefined) return; // dangling ref: step 13 reports this
    const nextVisited = new Set(visited);
    nextVisited.add(ref);
    // Report against the location of the referenced component, not the
    // requestBody call site, because that is where the offending node
    // actually lives and where a fix belongs.
    checkBoundedSchema(doc, resolved, opId, '/' + ref.slice(2), failures, nextVisited);
    return;
  }
  if (schemaHasType(node, 'string')) {
    if (typeof node.maxLength !== 'number') {
      failures.push('unbounded string in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
  }
  if (schemaHasType(node, 'array')) {
    if (typeof node.maxItems !== 'number') {
      failures.push('unbounded array in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
  }
  if (node.additionalProperties && typeof node.additionalProperties === 'object') {
    if (typeof node.maxProperties !== 'number') {
      failures.push('unbounded object with additionalProperties and no maxProperties in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
    checkBoundedSchema(doc, node.additionalProperties, opId, pointer + '/additionalProperties', failures, visited);
  }
  if (node.patternProperties && typeof node.patternProperties === 'object') {
    if (typeof node.maxProperties !== 'number') {
      failures.push('unbounded object with patternProperties and no maxProperties in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
    for (const pk of Object.keys(node.patternProperties)) {
      checkBoundedSchema(doc, node.patternProperties[pk], opId, pointer + '/patternProperties/' + encodeJsonPointerSegment(pk), failures, visited);
    }
  }
  if (node.properties && typeof node.properties === 'object') {
    for (const k of Object.keys(node.properties)) {
      checkBoundedSchema(doc, node.properties[k], opId, pointer + '/properties/' + encodeJsonPointerSegment(k), failures, visited);
    }
  }
  if (node.items) {
    checkBoundedSchema(doc, node.items, opId, pointer + '/items', failures, visited);
  }
  if (Array.isArray(node.prefixItems)) {
    node.prefixItems.forEach((sub, i) => checkBoundedSchema(doc, sub, opId, pointer + '/prefixItems/' + i, failures, visited));
  }
  for (const keyword of ['allOf', 'anyOf', 'oneOf']) {
    if (Array.isArray(node[keyword])) {
      node[keyword].forEach((sub, i) => checkBoundedSchema(doc, sub, opId, pointer + '/' + keyword + '/' + i, failures, visited));
    }
  }
}

function checkDocument(doc, opts) {
  opts = opts || {};
  const failures = [];
  function fail(msg) { failures.push(msg); }

  if (doc.openapi !== '3.1.0') {
    fail('openapi must be "3.1.0", found: ' + JSON.stringify(doc.openapi));
  }
  const servers = doc.servers;
  if (!Array.isArray(servers) || servers.length !== 1 || !servers[0] || servers[0].url !== '/v1') {
    fail('servers must be exactly [{ "url": "/v1" }]');
  }

  const paths = doc.paths && typeof doc.paths === 'object' ? doc.paths : {};
  const ops = [];

  for (const p of Object.keys(paths)) {
    const item = paths[p];
    if (item === null || typeof item !== 'object') continue;
    const pathLevelParams = Array.isArray(item.parameters) ? item.parameters : [];

    if (!p.startsWith('/')) {
      fail('path must start with /: ' + p);
    }
    if (p.startsWith('/v1')) {
      fail('paths must not begin with /v1: ' + p);
    }

    for (const key of Object.keys(item)) {
      if (key === 'parameters') continue;
      if (key.startsWith('x-')) continue;
      if (!METHODS.includes(key)) {
        fail('method must be lowercase and one of get, put, post, patch, delete: "' + key + '" at ' + p);
        continue;
      }
      const opObj = item[key] || {};
      const rawParams = pathLevelParams.concat(Array.isArray(opObj.parameters) ? opObj.parameters : []);
      const resolvedParams = rawParams.map((rp) => resolveParam(doc, rp));
      ops.push({ method: key, path: p, operationId: opObj.operationId, obj: opObj, params: resolvedParams });
    }
  }

  // step 5: unique operationId matching ^[a-z][A-Za-z0-9]*$
  const idLocations = new Map();
  for (const op of ops) {
    const id = op.operationId;
    if (typeof id !== 'string' || !/^[a-z][A-Za-z0-9]*$/.test(id)) {
      fail('operationId missing or invalid at ' + op.method.toUpperCase() + ' ' + op.path + ': ' + JSON.stringify(id));
      continue;
    }
    if (!idLocations.has(id)) idLocations.set(id, []);
    idLocations.get(id).push(op.method.toUpperCase() + ' ' + op.path);
  }
  for (const [id, locs] of idLocations) {
    if (locs.length > 1) {
      fail('duplicate operationId ' + id + ' at ' + locs.join(' and '));
    }
  }

  const permissions = new Set(Array.isArray(doc['x-it-permissions']) ? doc['x-it-permissions'] : []);

  for (const op of ops) {
    const id = op.operationId || (op.method.toUpperCase() + ' ' + op.path);
    const isGet = op.method === 'get';
    const hasParam = (name, at) => op.params.some((pm) => pm && pm.name === name && pm.in === at);
    // Present AND required: a parameter that is merely referenced is not
    // enough for a security header, because required defaults to false and
    // an optional Csrf or IfMatch header is not the guarantee the name
    // promises. Step 11 already applies this same required === true test to
    // Retry-After; this is the same one-line check on the other two
    // security-relevant headers.
    const hasRequiredParam = (name, at) =>
      op.params.some((pm) => pm && pm.name === name && pm.in === at && pm.required === true);

    // step 6
    const perm = op.obj['x-it-permission'];
    if (typeof perm !== 'string' || perm.length === 0) {
      fail('operation has no x-it-permission: ' + id);
    } else if (!permissions.has(perm)) {
      fail('operation x-it-permission is not in the closed vocabulary: ' + id + ' has "' + perm + '"');
    }

    // step 7
    const cli = op.obj['x-it-cli'];
    if (typeof cli !== 'string' || cli.length === 0) {
      fail('operation has no x-it-cli: ' + id);
    } else if (!cli.startsWith('irtctl ')) {
      fail('operation x-it-cli must start with "irtctl ": ' + id + ' has "' + cli + '"');
    } else if (!/^irtctl [A-Za-z0-9 :{}._/-]+$/.test(cli)) {
      let offender = '';
      for (const ch of cli) {
        if (!/[A-Za-z0-9 :{}._/-]/.test(ch)) { offender = ch; break; }
      }
      fail('operation x-it-cli contains a disallowed character: ' + id + ' character ' + JSON.stringify(offender));
    }

    // step 8
    const summary = op.obj.summary;
    if (typeof summary !== 'string' || summary.length < 12) {
      fail('operation summary must be at least 12 characters: ' + id);
    }

    // step 9
    if (!isGet) {
      if (!hasParam('X-IT-CSRF', 'header')) {
        fail('non-GET operation does not reference the Csrf parameter: ' + id);
      } else if (!hasRequiredParam('X-IT-CSRF', 'header')) {
        fail('non-GET operation Csrf parameter is not required: ' + id);
      }
    }

    // step 10
    const isConfigMutating =
      (['put', 'patch', 'delete'].includes(op.method) && op.path.startsWith('/config')) ||
      op.operationId === 'loadConfig' || op.operationId === 'rollbackConfig';
    if (isConfigMutating) {
      if (!hasParam('If-Match', 'header')) {
        fail('config mutating operation does not reference the IfMatch parameter: ' + id);
      } else if (!hasRequiredParam('If-Match', 'header')) {
        fail('config mutating operation IfMatch parameter is not required: ' + id);
      }
    }

    // step 11
    const responses = op.obj.responses || {};
    for (const code of ['401', '403', '429', '500']) {
      if (!(code in responses)) {
        fail('operation is missing response ' + code + ': ' + id);
      }
    }
    if ('429' in responses) {
      const raw429 = responses['429'];
      const resolved429 = raw429 && typeof raw429['$ref'] === 'string' ? resolveRef(doc, raw429['$ref']) : raw429;
      const retryAfter = resolved429 && resolved429.headers && resolved429.headers['Retry-After'];
      if (!retryAfter || retryAfter.required !== true) {
        fail('operation 429 response does not declare a required Retry-After header: ' + id);
      }
    }

    // step 12
    const hasPathParam = op.path.includes('{');
    if (hasPathParam && !('404' in responses)) {
      fail('operation has a path parameter but does not list 404: ' + id);
    }
    if (op.obj.requestBody && !('413' in responses)) {
      fail('operation has a requestBody but does not list 413: ' + id);
    }

    // step 17
    for (const pm of op.params) {
      if (!pm || !pm.schema) {
        fail('parameter has no schema: ' + id + ' parameter ' + (pm && pm.name));
      }
    }

    // step 18
    const templateNames = templateParamNames(op.path);
    for (const name of templateNames) {
      const found = op.params.some((pm) => pm && pm.in === 'path' && pm.name === name && pm.required === true);
      if (!found) {
        fail('path template parameter {' + name + '} has no declared path parameter: ' + id + ' at ' + op.path);
      }
    }
    for (const pm of op.params) {
      if (pm && pm.in === 'path' && !templateNames.includes(pm.name)) {
        fail('declared path parameter does not appear in the path template: ' + id + ' parameter ' + pm.name + ' at ' + op.path);
      }
    }

    // step 20
    const isSSE = op.operationId === 'streamLogs' || op.operationId === 'streamEvents';
    const raw200 = responses['200'];
    const resolved200 = raw200 && typeof raw200['$ref'] === 'string' ? resolveRef(doc, raw200['$ref']) : raw200;
    const content200 = resolved200 && resolved200.content;
    const hasSseContent = !!(content200 && Object.prototype.hasOwnProperty.call(content200, 'text/event-stream'));
    const hasJsonContent = !!(content200 && Object.prototype.hasOwnProperty.call(content200, 'application/json'));
    if (isSSE) {
      if (!hasSseContent) fail('SSE operation does not have a text/event-stream 200 response: ' + id);
      if (hasJsonContent) fail('SSE operation must not have an application/json 200 response: ' + id);
    } else if (hasSseContent) {
      fail('non-SSE operation has a text/event-stream response: ' + id);
    }

    // step 21
    if (isGet && !isSSE) {
      if (!hasParam('If-None-Match', 'header')) {
        fail('GET operation does not reference the IfNoneMatch parameter: ' + id);
      }
      if (!('304' in responses)) {
        fail('GET operation does not list a 304 response: ' + id);
      }
    }
    if (isSSE) {
      if (hasParam('If-None-Match', 'header')) {
        fail('SSE operation must not reference the IfNoneMatch parameter: ' + id);
      }
      if ('304' in responses) {
        fail('SSE operation must not list a 304 response: ' + id);
      }
    }

    // step 22
    if (!isGet) {
      if (!hasParam('Idempotency-Key', 'header')) {
        fail('non-GET operation does not reference the IdempotencyKey parameter: ' + id);
      }
      if (!hasParam('X-IT-Reason', 'header')) {
        fail('non-GET operation does not reference the Reason parameter: ' + id);
      }
      if (op.method === 'delete' && !('204' in responses)) {
        fail('DELETE operation does not list a 204 response: ' + id);
      }
    }

    // step 24. pm.schema is resolved through any $ref chain before being
    // examined, because a parameter whose schema is a $ref to a component
    // (for example a Cursor-style shared schema) must be bounded by what it
    // ultimately resolves to, not exempted for having one extra layer of
    // indirection.
    for (const pm of op.params) {
      if (!pm || pm.in !== 'path') continue;
      const sch = resolveSchemaRef(doc, pm.schema, new Set()) || {};
      if (schemaHasType(sch, 'string')) {
        if (typeof sch.maxLength !== 'number' || sch.maxLength > 256) {
          fail('path parameter has no maxLength of at most 256: ' + id + ' parameter ' + pm.name);
        }
        if (typeof sch.pattern !== 'string' || sch.pattern.length === 0) {
          fail('path parameter has no pattern: ' + id + ' parameter ' + pm.name);
        }
        // Presence of a pattern is not the same as the pattern constraining
        // anything: "^.*$" satisfies the two checks above and matches every
        // string. When the caller supplies a pinned vocabulary (main()
        // supplies the real one from issue 380), a parameter whose name is
        // in it must match the pinned maxLength and pattern exactly.
        if (pm.name && opts.pathParameterVocabulary &&
          Object.prototype.hasOwnProperty.call(opts.pathParameterVocabulary, pm.name)) {
          const pinned = opts.pathParameterVocabulary[pm.name];
          if (sch.maxLength !== pinned.maxLength || sch.pattern !== pinned.pattern) {
            fail('path parameter does not match the frozen vocabulary for its name: ' + id +
              ' parameter ' + pm.name + ' expected maxLength ' + pinned.maxLength + ' and pattern ' +
              JSON.stringify(pinned.pattern) + ', found maxLength ' + JSON.stringify(sch.maxLength) +
              ' and pattern ' + JSON.stringify(sch.pattern));
          }
        }
      } else if (schemaHasType(sch, 'integer')) {
        if (typeof sch.minimum !== 'number' || typeof sch.maximum !== 'number') {
          fail('integer path parameter has no minimum and maximum: ' + id + ' parameter ' + pm.name);
        }
      } else {
        fail('path parameter must be type string or integer: ' + id + ' parameter ' + pm.name);
      }
    }

    // step 25. Same $ref resolution as step 24: a query or header parameter
    // whose schema is a $ref (for example components.parameters.Cursor
    // pointing its schema at a named component instead of declaring it
    // inline) must not silently skip the maxLength check just because
    // pm.schema.type is undefined on the unresolved $ref wrapper.
    for (const pm of op.params) {
      if (!pm) continue;
      if (pm.in !== 'query' && pm.in !== 'header') continue;
      const sch = resolveSchemaRef(doc, pm.schema, new Set());
      if (sch && schemaHasType(sch, 'string')) {
        if (typeof sch.maxLength !== 'number') {
          fail('query or header string parameter has no maxLength: ' + id + ' parameter ' + pm.name);
        }
      }
    }
    if (op.obj.requestBody) {
      const content = op.obj.requestBody.content || {};
      for (const mt of Object.keys(content)) {
        const schema = content[mt] && content[mt].schema;
        if (schema) {
          const pointer = '/paths/' + encodeJsonPointerSegment(op.path) + '/' + op.method +
            '/requestBody/content/' + encodeJsonPointerSegment(mt) + '/schema';
          checkBoundedSchema(doc, schema, id, pointer, failures, new Set());
        }
      }
    }
  }

  // step 13: every $ref resolves
  const allRefs = [];
  collectRefs(doc, '', allRefs);
  for (const r of allRefs) {
    if (resolveRef(doc, r.ref) === undefined) {
      fail('dangling $ref: ' + r.ref + ' at ' + r.pointer);
    }
  }

  // step 14: every component is referenced except the vocabulary schemas
  const refSet = new Set(allRefs.map((r) => r.ref));
  const schemas = (doc.components && doc.components.schemas) || {};
  const parametersComp = (doc.components && doc.components.parameters) || {};
  const responsesComp = (doc.components && doc.components.responses) || {};
  const vocab = new Set(Array.isArray(doc['x-it-vocabulary-schemas']) ? doc['x-it-vocabulary-schemas'] : []);
  for (const name of Object.keys(schemas)) {
    if (vocab.has(name)) continue;
    if (!refSet.has('#/components/schemas/' + name)) fail('component is unreferenced: ' + name);
  }
  for (const name of Object.keys(parametersComp)) {
    if (!refSet.has('#/components/parameters/' + name)) fail('component is unreferenced: ' + name);
  }
  for (const name of Object.keys(responsesComp)) {
    if (!refSet.has('#/components/responses/' + name)) fail('component is unreferenced: ' + name);
  }
  for (const name of vocab) {
    if (!(name in schemas)) fail('x-it-vocabulary-schemas names a schema that does not exist: ' + name);
  }

  // step 15
  const allowlist = doc['x-it-non-api-allowlist'];
  const expectedAllowlist = ['GET /ui/{*path}', 'GET /healthz', 'GET /readyz', 'GET /metrics'];
  const allowlistOk = Array.isArray(allowlist) && allowlist.length === expectedAllowlist.length &&
    expectedAllowlist.every((v, i) => allowlist[i] === v);
  if (!allowlistOk) {
    fail('x-it-non-api-allowlist must be exactly the four documented entries');
  }

  // step 16
  const opCount = ops.length;
  const declaredCount = doc['x-it-operation-count'];
  if (declaredCount !== opCount) {
    fail('operation count mismatch: x-it-operation-count is ' + JSON.stringify(declaredCount) + ' but paths contains ' + opCount);
  }

  // step 23: the frozen operation set and the frozen permission vocabulary,
  // pinned against a constant the caller supplies (opts.frozenOperations,
  // opts.frozenPermissionVocabulary) rather than against anything read out of
  // the document itself. main() supplies the real 62-operation table from
  // issue 380 and the 23-entry vocabulary when checking the committed
  // document; the generic self-tests below exercise every OTHER rule against
  // small synthetic documents that were never meant to reproduce that table,
  // so they do not supply these options and this step is a no-op for them.
  // Dedicated self-tests further down supply their own small frozen table to
  // exercise this mechanism in isolation. Without this step, a mutation that
  // edits the method, path or permission of an existing operation and
  // nothing else is invisible to every other check, because steps 6 and 16
  // only ever compare the document to a value read from the same document.
  if (Array.isArray(opts.frozenOperations)) {
    const actualById = new Map();
    for (const op of ops) {
      if (typeof op.operationId !== 'string') continue;
      actualById.set(op.operationId, {
        method: op.method.toUpperCase(),
        path: op.path,
        permission: op.obj['x-it-permission'],
      });
    }
    const expectedIds = new Set(opts.frozenOperations.map((e) => e[0]));
    for (const [expectedId, expectedMethod, expectedPath, expectedPermission] of opts.frozenOperations) {
      const actual = actualById.get(expectedId);
      if (!actual) {
        fail('frozen operation is missing from the document: ' + expectedId +
          ' (expected ' + expectedMethod + ' ' + expectedPath + ')');
        continue;
      }
      if (actual.method !== expectedMethod || actual.path !== expectedPath) {
        fail('frozen operation ' + expectedId + ' has moved: expected ' +
          expectedMethod + ' ' + expectedPath + ', found ' + actual.method + ' ' + actual.path);
      }
      if (actual.permission !== expectedPermission) {
        fail('frozen operation ' + expectedId + ' permission has changed: expected "' +
          expectedPermission + '", found ' + JSON.stringify(actual.permission));
      }
    }
    for (const id of actualById.keys()) {
      if (!expectedIds.has(id)) {
        fail('operation is not in the frozen operation set: ' + id);
      }
    }
  }
  if (Array.isArray(opts.frozenPermissionVocabulary)) {
    const actualPerms = Array.isArray(doc['x-it-permissions']) ? doc['x-it-permissions'] : [];
    const vocabOk = actualPerms.length === opts.frozenPermissionVocabulary.length &&
      opts.frozenPermissionVocabulary.every((v, i) => actualPerms[i] === v);
    if (!vocabOk) {
      fail('x-it-permissions must be exactly the frozen permission vocabulary, ' +
        opts.frozenPermissionVocabulary.length + ' entries in the frozen order: found ' +
        JSON.stringify(actualPerms));
    }
  }

  // step 19: CLI command path uniqueness
  const cliCommandPaths = new Map();
  for (const op of ops) {
    const cli = op.obj['x-it-cli'];
    if (typeof cli !== 'string' || !cli.startsWith('irtctl ')) continue;
    const words = cli.slice('irtctl '.length).split(/\s+/).filter((w) => w.length > 0);
    const kept = words.filter((w) => !w.startsWith('-') && !w.startsWith('{'));
    const cmd = kept.join(' ');
    if (!cliCommandPaths.has(cmd)) cliCommandPaths.set(cmd, []);
    cliCommandPaths.get(cmd).push(op.operationId);
  }
  for (const [cmd, idsForCmd] of cliCommandPaths) {
    if (idsForCmd.length > 1) {
      fail('duplicate CLI command path "' + cmd + '": ' + idsForCmd.join(' and '));
    }
  }

  // step 20 (mirror direction already handled above per-operation)

  // step 26
  const expensive = Array.isArray(doc['x-it-expensive-operations']) ? doc['x-it-expensive-operations'] : [];
  if (expensive.length === 0) {
    fail('x-it-expensive-operations must not be empty');
  }
  const knownIds = new Set(ops.map((op) => op.operationId));
  for (const name of expensive) {
    if (!knownIds.has(name)) {
      fail('x-it-expensive-operations names an operationId that does not exist: ' + name);
    }
  }

  const permCount = Array.isArray(doc['x-it-permissions']) ? doc['x-it-permissions'].length : 0;
  return { failures, opCount, permCount };
}


function runSelftest() {

function clone(x) { return JSON.parse(JSON.stringify(x)); }

function okGetOp(id, permission, cli) {
  return {
    operationId: id,
    summary: 'A summary that is long enough to pass step eight.',
    'x-it-permission': permission,
    'x-it-cli': cli,
    parameters: [
      { name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } },
    ],
    responses: {
      '200': { description: 'ok' },
      '304': { description: 'not modified' },
      '401': { description: 'unauthorized' },
      '403': { description: 'forbidden' },
      '429': { description: 'too many requests', headers: { 'Retry-After': { required: true, schema: { type: 'integer' } } } },
      '500': { description: 'internal error' },
    },
  };
}

function retryHeader() {
  return { required: true, schema: { type: 'integer' } };
}

function mkDoc(opts) {
  const d = {
    openapi: opts.openapi !== undefined ? opts.openapi : '3.1.0',
    info: { title: 'Test API', version: '1.0.0' },
    servers: opts.servers !== undefined ? opts.servers : [{ url: '/v1' }],
    'x-it-non-api-allowlist': opts.allowlist !== undefined
      ? opts.allowlist
      : ['GET /ui/{*path}', 'GET /healthz', 'GET /readyz', 'GET /metrics'],
    'x-it-permissions': opts.permissions || ['none', 'widget:read', 'widget:write', 'config:read', 'config:write'],
    'x-it-vocabulary-schemas': opts.vocabSchemas || [],
    'x-it-operation-count': opts.opCount,
    'x-it-expensive-operations': opts.expensive || ['getWidget'],
    paths: opts.paths || {},
  };
  if (opts.components) d.components = opts.components;
  return d;
}

// the base fixture used by test 13 and cloned by several 'rejects' tests
function baseValidTwoOpDoc() {
  return mkDoc({
    opCount: 2,
    expensive: ['getWidget'],
    paths: {
      '/widgets/{id}': {
        parameters: [
          { name: 'id', in: 'path', required: true, description: 'widget id',
            schema: { type: 'string', maxLength: 64, pattern: '^[a-z0-9]{1,64}$' } },
        ],
        get: {
          operationId: 'getWidget',
          summary: 'Return one widget by its identifier.',
          'x-it-permission': 'widget:read',
          'x-it-cli': 'irtctl widgets show',
          parameters: [
            { name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } },
          ],
          responses: {
            '200': { description: 'ok', content: { 'application/json': { schema: { type: 'object' } } } },
            '304': { description: 'not modified' },
            '401': { description: 'unauthorized' },
            '403': { description: 'forbidden' },
            '404': { description: 'not found' },
            '429': { description: 'too many requests', headers: { 'Retry-After': retryHeader() } },
            '500': { description: 'internal error' },
          },
        },
        put: {
          operationId: 'putWidget',
          summary: 'Replace one widget by its identifier.',
          'x-it-permission': 'widget:write',
          'x-it-cli': 'irtctl widgets apply',
          parameters: [
            { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
            { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
            { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
          ],
          responses: {
            '200': { description: 'ok', content: { 'application/json': { schema: { type: 'object' } } } },
            '401': { description: 'unauthorized' },
            '403': { description: 'forbidden' },
            '404': { description: 'not found' },
            '409': { description: 'conflict' },
            '412': { description: 'precondition failed' },
            '413': { description: 'payload too large' },
            '422': { description: 'unprocessable' },
            '429': { description: 'too many requests', headers: { 'Retry-After': retryHeader() } },
            '500': { description: 'internal error' },
          },
        },
      },
    },
  });
}

let passCount = 0;
let failCount = 0;
const results = [];

function expect(name, cond, detail) {
  if (cond) {
    passCount += 1;
    results.push('selftest ' + name + ': ok');
  } else {
    failCount += 1;
    results.push('selftest ' + name + ': FAILED ' + (detail || ''));
  }
}

function run(name, fn) {
  try {
    fn();
  } catch (e) {
    failCount += 1;
    results.push('selftest ' + name + ': THREW ' + e.stack);
  }
}

// 1. selftest_rejects_v1_prefixed_path
run('selftest_rejects_v1_prefixed_path', () => {
  const d = baseValidTwoOpDoc();
  const item = d.paths['/widgets/{id}'];
  delete d.paths['/widgets/{id}'];
  d.paths['/v1/widgets/{id}'] = item;
  const r = checkDocument(d);
  expect('selftest_rejects_v1_prefixed_path', r.failures.length > 0 &&
    r.failures.some((f) => f.includes('paths must not begin with /v1')),
    JSON.stringify(r.failures));
});

// 2. selftest_rejects_duplicate_operation_id
run('selftest_rejects_duplicate_operation_id', () => {
  const d = baseValidTwoOpDoc();
  d.paths['/widgets/{id}'].put.operationId = 'getWidget';
  const r = checkDocument(d);
  expect('selftest_rejects_duplicate_operation_id',
    r.failures.some((f) => f.includes('duplicate operationId getWidget') &&
      f.includes('GET /widgets/{id}') && f.includes('PUT /widgets/{id}')),
    JSON.stringify(r.failures));
});

// 3. selftest_rejects_unknown_permission
run('selftest_rejects_unknown_permission', () => {
  const d = baseValidTwoOpDoc();
  d.paths['/widgets/{id}'].get['x-it-permission'] = 'config:writes';
  const r = checkDocument(d);
  expect('selftest_rejects_unknown_permission',
    r.failures.some((f) => f.includes('not in the closed vocabulary') && f.includes('getWidget')),
    JSON.stringify(r.failures));
});

// 4. selftest_rejects_missing_cli
run('selftest_rejects_missing_cli', () => {
  const d = baseValidTwoOpDoc();
  delete d.paths['/widgets/{id}'].get['x-it-cli'];
  const r = checkDocument(d);
  expect('selftest_rejects_missing_cli',
    r.failures.some((f) => f.includes('operation has no x-it-cli') && f.includes('getWidget')),
    JSON.stringify(r.failures));
});

// 5. selftest_rejects_cli_not_irtctl
run('selftest_rejects_cli_not_irtctl', () => {
  const d = baseValidTwoOpDoc();
  d.paths['/widgets/{id}'].get['x-it-cli'] = 'curl /v1/overview';
  const r = checkDocument(d);
  expect('selftest_rejects_cli_not_irtctl',
    r.failures.some((f) => f.includes('must start with "irtctl "') && f.includes('getWidget')),
    JSON.stringify(r.failures));
});

// 6. selftest_rejects_mutation_without_csrf
run('selftest_rejects_mutation_without_csrf', () => {
  const d = baseValidTwoOpDoc();
  d.paths['/widgets/{id}'].put.parameters = d.paths['/widgets/{id}'].put.parameters
    .filter((p) => p.name !== 'X-IT-CSRF');
  const r = checkDocument(d);
  expect('selftest_rejects_mutation_without_csrf',
    r.failures.some((f) => f.includes('does not reference the Csrf parameter') && f.includes('putWidget')),
    JSON.stringify(r.failures));
});

// 7. selftest_rejects_config_write_without_if_match
run('selftest_rejects_config_write_without_if_match', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['putConfigResource'],
    paths: {
      '/config/{kind}/{ns}/{name}': {
        parameters: [
          { name: 'kind', in: 'path', required: true, schema: { type: 'string', maxLength: 64, pattern: '^[a-z][a-z0-9-]{0,63}$' } },
          { name: 'ns', in: 'path', required: true, schema: { type: 'string', maxLength: 63, pattern: '^[a-z0-9-]{1,63}$' } },
          { name: 'name', in: 'path', required: true, schema: { type: 'string', maxLength: 253, pattern: '^[a-z0-9.-]{1,253}$' } },
        ],
        put: {
          operationId: 'putConfigResource',
          summary: 'Replace one namespaced configuration resource.',
          'x-it-permission': 'config:write',
          'x-it-cli': 'irtctl config apply -f -',
          parameters: [
            { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
            { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
            { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
          ],
          responses: {
            '200': { description: 'ok' }, '401': { description: 'x' }, '403': { description: 'x' },
            '404': { description: 'x' }, '409': { description: 'x' }, '412': { description: 'x' },
            '413': { description: 'x' }, '422': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_config_write_without_if_match',
    r.failures.some((f) => f.includes('does not reference the IfMatch parameter') && f.includes('putConfigResource')),
    JSON.stringify(r.failures));
});

// 8. selftest_rejects_dangling_ref
run('selftest_rejects_dangling_ref', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['getThing'],
    paths: {
      '/thing': {
        get: {
          operationId: 'getThing',
          summary: 'Return one thing for testing purposes.',
          'x-it-permission': 'widget:read',
          'x-it-cli': 'irtctl thing show',
          parameters: [{ name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } }],
          responses: {
            '200': { description: 'ok', content: { 'application/json': { schema: { '$ref': '#/components/schemas/Nope' } } } },
            '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_dangling_ref',
    r.failures.some((f) => f.includes('dangling $ref') && f.includes('#/components/schemas/Nope')),
    JSON.stringify(r.failures));
});

// 9. selftest_rejects_unreferenced_component
run('selftest_rejects_unreferenced_component', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['getWidget'],
    paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } },
    components: { schemas: { Widget: { type: 'object' } } },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_unreferenced_component',
    r.failures.some((f) => f.includes('component is unreferenced: Widget')),
    JSON.stringify(r.failures));
});

// 10. selftest_rejects_undeclared_path_parameter
run('selftest_rejects_undeclared_path_parameter', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['getCert'],
    paths: {
      '/certs/{id}': {
        get: {
          operationId: 'getCert',
          summary: 'Return one certificate for testing purposes.',
          'x-it-permission': 'certs:read',
          'x-it-cli': 'irtctl certs show',
          parameters: [{ name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } }],
          responses: {
            '200': { description: 'x' }, '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '404': { description: 'x' }, '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
    permissions: ['none', 'certs:read'],
  });
  const r = checkDocument(d);
  expect('selftest_rejects_undeclared_path_parameter',
    r.failures.some((f) => f.includes('path template parameter {id} has no declared path parameter') && f.includes('getCert')),
    JSON.stringify(r.failures));
});

// 11. selftest_rejects_declared_but_absent_parameter
run('selftest_rejects_declared_but_absent_parameter', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['listCerts'],
    paths: {
      '/certs': {
        get: {
          operationId: 'listCerts',
          summary: 'List every certificate for testing purposes.',
          'x-it-permission': 'certs:read',
          'x-it-cli': 'irtctl certs',
          parameters: [
            { name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } },
            { name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 128, pattern: '^[A-Za-z0-9._-]{1,128}$' } },
          ],
          responses: {
            '200': { description: 'x' }, '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
    permissions: ['none', 'certs:read'],
  });
  const r = checkDocument(d);
  expect('selftest_rejects_declared_but_absent_parameter',
    r.failures.some((f) => f.includes('declared path parameter does not appear in the path template') &&
      f.includes('listCerts') && f.includes('id')),
    JSON.stringify(r.failures));
});

// 12. selftest_rejects_count_mismatch
run('selftest_rejects_count_mismatch', () => {
  const d = mkDoc({
    opCount: 2,
    expensive: ['getWidget'],
    paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_count_mismatch',
    r.failures.some((f) => f.includes('operation count mismatch')),
    JSON.stringify(r.failures));
});

// 13. selftest_accepts_a_minimal_valid_document
run('selftest_accepts_a_minimal_valid_document', () => {
  const d = baseValidTwoOpDoc();
  const r = checkDocument(d);
  expect('selftest_accepts_a_minimal_valid_document', r.failures.length === 0, JSON.stringify(r.failures));
});

// 14. selftest_rejects_missing_403
run('selftest_rejects_missing_403', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['getWidget'],
    paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } },
  });
  delete d.paths['/widget'].get.responses['403'];
  const r = checkDocument(d);
  expect('selftest_rejects_missing_403',
    r.failures.some((f) => f.includes('operation is missing response 403') && f.includes('getWidget')),
    JSON.stringify(r.failures));
});

// 15. selftest_rejects_a_parameter_without_a_schema
run('selftest_rejects_a_parameter_without_a_schema', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['getThings'],
    paths: {
      '/things': {
        get: {
          operationId: 'getThings',
          summary: 'List every thing for testing purposes.',
          'x-it-permission': 'widget:read',
          'x-it-cli': 'irtctl things',
          parameters: [
            { name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } },
            { name: 'q', in: 'query' },
          ],
          responses: {
            '200': { description: 'x' }, '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_a_parameter_without_a_schema',
    r.failures.some((f) => f.includes('parameter has no schema') && f.includes('getThings') && f.includes('q')),
    JSON.stringify(r.failures));
});

// 16. selftest_rejects_duplicate_cli_command_paths
run('selftest_rejects_duplicate_cli_command_paths', () => {
  const explainOp = {
    operationId: 'explainRequest',
    summary: 'Run a synthetic request for testing purposes.',
    'x-it-permission': 'explain:run',
    'x-it-cli': 'irtctl explain',
    parameters: [
      { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
      { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
      { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
    ],
    responses: {
      '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
      '409': { description: 'x' }, '412': { description: 'x' }, '413': { description: 'x' }, '422': { description: 'x' },
      '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
    },
  };
  const recordedOp = {
    operationId: 'getRecordedExplain',
    summary: 'Return a previously recorded explain run.',
    'x-it-permission': 'explain:run',
    'x-it-cli': 'irtctl explain --request-id',
    parameters: [
      { name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } },
    ],
    responses: {
      '200': { description: 'x' }, '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
      '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
    },
  };
  const d = mkDoc({
    opCount: 2,
    expensive: ['explainRequest'],
    permissions: ['none', 'explain:run'],
    paths: { '/explain': { post: explainOp }, '/explain/recorded': { get: recordedOp } },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_duplicate_cli_command_paths',
    r.failures.some((f) => f.includes('duplicate CLI command path "explain"') &&
      f.includes('explainRequest') && f.includes('getRecordedExplain')),
    JSON.stringify(r.failures));
});

// 17. selftest_rejects_a_json_sse_operation
run('selftest_rejects_a_json_sse_operation', () => {
  const streamLogsOp = {
    operationId: 'streamLogs',
    summary: 'Stream matching log lines for testing purposes.',
    'x-it-permission': 'logs:read',
    'x-it-cli': 'irtctl logs tail',
    parameters: [],
    responses: {
      '200': { description: 'x', content: { 'application/json': { schema: { type: 'string' } } } },
      '401': { description: 'x' }, '403': { description: 'x' },
      '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
    },
  };
  const d = mkDoc({
    opCount: 1,
    expensive: ['streamLogs'],
    permissions: ['none', 'logs:read'],
    paths: { '/logs/stream': { get: streamLogsOp } },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_a_json_sse_operation (json instead of event-stream)',
    r.failures.some((f) => f.includes('does not have a text/event-stream 200 response') && f.includes('streamLogs')),
    JSON.stringify(r.failures));

  // mirror: a third, non-SSE operation declaring text/event-stream
  const d2 = mkDoc({
    opCount: 1,
    expensive: ['getWidget'],
    paths: {
      '/widget': {
        get: Object.assign({}, okGetOp('getWidget', 'widget:read', 'irtctl widget show'), {
          responses: Object.assign({}, okGetOp('getWidget', 'widget:read', 'irtctl widget show').responses, {
            '200': { description: 'x', content: { 'text/event-stream': { schema: { type: 'string' } } } },
          }),
        }),
      },
    },
  });
  const r2 = checkDocument(d2);
  expect('selftest_rejects_a_json_sse_operation (mirror: non-SSE with event-stream)',
    r2.failures.some((f) => f.includes('non-SSE operation has a text/event-stream response') && f.includes('getWidget')),
    JSON.stringify(r2.failures));
});

// 18. selftest_exempts_only_the_vocabulary_schemas
run('selftest_exempts_only_the_vocabulary_schemas', () => {
  const base = () => mkDoc({
    opCount: 1,
    expensive: ['getWidget'],
    paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } },
    components: { schemas: { Widget: { type: 'object' } } },
  });

  const d1 = base();
  d1['x-it-vocabulary-schemas'] = [];
  const r1 = checkDocument(d1);
  expect('selftest_exempts_only_the_vocabulary_schemas (rejects without exemption)',
    r1.failures.some((f) => f.includes('component is unreferenced: Widget')), JSON.stringify(r1.failures));

  const d2 = base();
  d2['x-it-vocabulary-schemas'] = ['Widget'];
  const r2 = checkDocument(d2);
  expect('selftest_exempts_only_the_vocabulary_schemas (accepts with exemption)',
    !r2.failures.some((f) => f.includes('unreferenced')), JSON.stringify(r2.failures));

  const d3 = base();
  d3['x-it-vocabulary-schemas'] = ['Ghost'];
  const r3 = checkDocument(d3);
  expect('selftest_exempts_only_the_vocabulary_schemas (rejects naming a schema that does not exist)',
    r3.failures.some((f) => f.includes('x-it-vocabulary-schemas names a schema that does not exist: Ghost')),
    JSON.stringify(r3.failures));
});

// 19. selftest_rejects_a_get_without_if_none_match
run('selftest_rejects_a_get_without_if_none_match', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['getWidget'],
    paths: {
      '/widget': {
        get: {
          operationId: 'getWidget',
          summary: 'Return one widget for testing purposes.',
          'x-it-permission': 'widget:read',
          'x-it-cli': 'irtctl widget show',
          parameters: [],
          responses: {
            '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_a_get_without_if_none_match',
    r.failures.some((f) => f.includes('does not reference the IfNoneMatch parameter') && f.includes('getWidget')),
    JSON.stringify(r.failures));

  // mirror: streamLogs declaring IfNoneMatch and a 304
  const d2 = mkDoc({
    opCount: 1,
    expensive: ['streamLogs'],
    permissions: ['none', 'logs:read'],
    paths: {
      '/logs/stream': {
        get: {
          operationId: 'streamLogs',
          summary: 'Stream matching log lines for testing purposes.',
          'x-it-permission': 'logs:read',
          'x-it-cli': 'irtctl logs tail',
          parameters: [{ name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } }],
          responses: {
            '200': { description: 'x', content: { 'text/event-stream': { schema: { type: 'string' } } } },
            '304': { description: 'x' },
            '401': { description: 'x' }, '403': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r2 = checkDocument(d2);
  expect('selftest_rejects_a_get_without_if_none_match (mirror: SSE with IfNoneMatch and 304)',
    r2.failures.some((f) => f.includes('SSE operation must not reference the IfNoneMatch parameter')) &&
    r2.failures.some((f) => f.includes('SSE operation must not list a 304 response')),
    JSON.stringify(r2.failures));
});

// 20. selftest_rejects_a_mutation_without_idempotency_or_reason
run('selftest_rejects_a_mutation_without_idempotency_or_reason', () => {
  function postOp(withIdempotency, withReason) {
    const parameters = [{ name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } }];
    if (withIdempotency) parameters.push({ name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } });
    if (withReason) parameters.push({ name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } });
    return {
      operationId: 'createThing',
      summary: 'Create one thing for testing purposes.',
      'x-it-permission': 'widget:write',
      'x-it-cli': 'irtctl things create',
      parameters,
      responses: {
        '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
        '409': { description: 'x' }, '412': { description: 'x' }, '413': { description: 'x' }, '422': { description: 'x' },
        '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
      },
    };
  }
  const d1 = mkDoc({ opCount: 1, expensive: ['createThing'], paths: { '/things': { post: postOp(false, true) } } });
  const r1 = checkDocument(d1);
  expect('selftest_rejects_a_mutation_without_idempotency_or_reason (no idempotency key)',
    r1.failures.some((f) => f.includes('does not reference the IdempotencyKey parameter') && f.includes('createThing')),
    JSON.stringify(r1.failures));

  const d2 = mkDoc({ opCount: 1, expensive: ['createThing'], paths: { '/things': { post: postOp(true, false) } } });
  const r2 = checkDocument(d2);
  expect('selftest_rejects_a_mutation_without_idempotency_or_reason (no reason)',
    r2.failures.some((f) => f.includes('does not reference the Reason parameter') && f.includes('createThing')),
    JSON.stringify(r2.failures));

  const deleteOp = postOp(true, true);
  deleteOp.operationId = 'deleteThing';
  deleteOp['x-it-cli'] = 'irtctl things delete';
  deleteOp.responses['200'] = { description: 'wrong: should be 204' };
  const d3 = mkDoc({ opCount: 1, expensive: ['deleteThing'], paths: { '/things/{id}': {
    parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', maxLength: 128, pattern: '^[A-Za-z0-9._-]{1,128}$' } }],
    delete: deleteOp,
  } } });
  d3.paths['/things/{id}'].delete.responses['404'] = { description: 'x' };
  const r3 = checkDocument(d3);
  expect('selftest_rejects_a_mutation_without_idempotency_or_reason (DELETE with 200 instead of 204)',
    r3.failures.some((f) => f.includes('DELETE operation does not list a 204 response') && f.includes('deleteThing')),
    JSON.stringify(r3.failures));
});

// 21. selftest_rejects_an_unbounded_path_parameter
run('selftest_rejects_an_unbounded_path_parameter', () => {
  function docWithIdSchema(schema) {
    return mkDoc({
      opCount: 1,
      expensive: ['getThing'],
      paths: {
        '/things/{id}': {
          parameters: [{ name: 'id', in: 'path', required: true, schema }],
          get: {
            operationId: 'getThing',
            summary: 'Return one thing for testing purposes.',
            'x-it-permission': 'widget:read',
            'x-it-cli': 'irtctl things show',
            parameters: [{ name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } }],
            responses: {
              '200': { description: 'x' }, '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
              '404': { description: 'x' }, '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
            },
          },
        },
      },
    });
  }

  const r1 = checkDocument(docWithIdSchema({ type: 'string' }));
  expect('selftest_rejects_an_unbounded_path_parameter (no maxLength)',
    r1.failures.some((f) => f.includes('path parameter has no maxLength of at most 256') && f.includes('getThing') && f.includes('id')),
    JSON.stringify(r1.failures));

  const r2 = checkDocument(docWithIdSchema({ type: 'string', maxLength: 4096, pattern: '^.*$' }));
  expect('selftest_rejects_an_unbounded_path_parameter (maxLength above 256)',
    r2.failures.some((f) => f.includes('path parameter has no maxLength of at most 256') && f.includes('getThing')),
    JSON.stringify(r2.failures));

  const r3 = checkDocument(docWithIdSchema({ type: 'string', maxLength: 64 }));
  expect('selftest_rejects_an_unbounded_path_parameter (no pattern)',
    r3.failures.some((f) => f.includes('path parameter has no pattern') && f.includes('getThing')),
    JSON.stringify(r3.failures));
});

// 22. selftest_rejects_an_unbounded_request_body_string
run('selftest_rejects_an_unbounded_request_body_string', () => {
  function docWithBody(schema) {
    return mkDoc({
      opCount: 1,
      expensive: ['createThing'],
      paths: {
        '/things': {
          post: {
            operationId: 'createThing',
            summary: 'Create one thing for testing purposes.',
            'x-it-permission': 'widget:write',
            'x-it-cli': 'irtctl things create',
            parameters: [
              { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
              { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
              { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
            ],
            requestBody: { content: { 'application/json': { schema } } },
            responses: {
              '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
              '409': { description: 'x' }, '412': { description: 'x' }, '413': { description: 'x' }, '422': { description: 'x' },
              '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
            },
          },
        },
      },
    });
  }

  const r1 = checkDocument(docWithBody({ type: 'object', properties: { expr: { type: 'string' } } }));
  expect('selftest_rejects_an_unbounded_request_body_string (no maxLength)',
    r1.failures.some((f) => f.includes('unbounded string in requestBody') && f.includes('properties/expr')),
    JSON.stringify(r1.failures));

  const r2 = checkDocument(docWithBody({ type: 'object', properties: { expr: { type: 'string', maxLength: 256 } } }));
  expect('selftest_rejects_an_unbounded_request_body_string (maxLength added, accepts)',
    r2.failures.length === 0, JSON.stringify(r2.failures));

  const r3 = checkDocument(docWithBody({ type: 'object', additionalProperties: { type: 'string', maxLength: 64 } }));
  expect('selftest_rejects_an_unbounded_request_body_string (additionalProperties, no maxProperties)',
    r3.failures.some((f) => f.includes('unbounded object with additionalProperties and no maxProperties')),
    JSON.stringify(r3.failures));

  // a RESPONSE schema with an unbounded string is exempt
  const d4 = docWithBody({ type: 'object', properties: { expr: { type: 'string', maxLength: 256 } } });
  d4.paths['/things'].post.responses['200'] = {
    description: 'x', content: { 'application/json': { schema: { type: 'object', properties: { note: { type: 'string' } } } } },
  };
  const r4 = checkDocument(d4);
  expect('selftest_rejects_an_unbounded_request_body_string (response schema exempt)',
    r4.failures.length === 0, JSON.stringify(r4.failures));
});

// 23. selftest_rejects_shell_metacharacters_in_cli
run('selftest_rejects_shell_metacharacters_in_cli', () => {
  const bad = ['irtctl a; id', 'irtctl a `id`', 'irtctl a | sh', 'irtctl a $(id)', 'irtctl a && id', 'irtctl a\nid'];
  for (const cli of bad) {
    const d = mkDoc({
      opCount: 1,
      expensive: ['getWidget'],
      paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', cli) } },
    });
    const r = checkDocument(d);
    expect('selftest_rejects_shell_metacharacters_in_cli (' + JSON.stringify(cli) + ')',
      r.failures.some((f) => f.includes('disallowed character') && f.includes('getWidget')),
      JSON.stringify(r.failures));
  }
});

// 24. selftest_rejects_missing_500_or_retry_after
run('selftest_rejects_missing_500_or_retry_after', () => {
  const d1 = mkDoc({ opCount: 1, expensive: ['getWidget'], paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } } });
  delete d1.paths['/widget'].get.responses['500'];
  const r1 = checkDocument(d1);
  expect('selftest_rejects_missing_500_or_retry_after (missing 500)',
    r1.failures.some((f) => f.includes('operation is missing response 500') && f.includes('getWidget')),
    JSON.stringify(r1.failures));

  const d2 = mkDoc({ opCount: 1, expensive: ['getWidget'], paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } } });
  d2.paths['/widget'].get.responses['429'] = { description: 'x' };
  const r2 = checkDocument(d2);
  expect('selftest_rejects_missing_500_or_retry_after (429 without Retry-After)',
    r2.failures.some((f) => f.includes('does not declare a required Retry-After header') && f.includes('getWidget')),
    JSON.stringify(r2.failures));
});

// 25. selftest_rejects_unknown_expensive_operation
run('selftest_rejects_unknown_expensive_operation', () => {
  const d1 = mkDoc({ opCount: 1, expensive: ['getGhost'], paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } } });
  const r1 = checkDocument(d1);
  expect('selftest_rejects_unknown_expensive_operation (names getGhost)',
    r1.failures.some((f) => f.includes('does not exist: getGhost')), JSON.stringify(r1.failures));

  const d2 = mkDoc({ opCount: 1, expensive: [], paths: { '/widget': { get: okGetOp('getWidget', 'widget:read', 'irtctl widget show') } } });
  const r2 = checkDocument(d2);
  expect('selftest_rejects_unknown_expensive_operation (empty list)',
    r2.failures.some((f) => f.includes('x-it-expensive-operations must not be empty')), JSON.stringify(r2.failures));
});

// 26. selftest_rejects_missing_413_on_a_request_body
run('selftest_rejects_missing_413_on_a_request_body', () => {
  const d = mkDoc({
    opCount: 1,
    expensive: ['createThing'],
    paths: {
      '/things': {
        post: {
          operationId: 'createThing',
          summary: 'Create one thing for testing purposes.',
          'x-it-permission': 'widget:write',
          'x-it-cli': 'irtctl things create',
          parameters: [
            { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
            { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
            { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
          ],
          requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string', maxLength: 64 } } } } } },
          responses: {
            '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '409': { description: 'x' }, '412': { description: 'x' }, '422': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r = checkDocument(d);
  expect('selftest_rejects_missing_413_on_a_request_body',
    r.failures.some((f) => f.includes('has a requestBody but does not list 413') && f.includes('createThing')),
    JSON.stringify(r.failures));
});

// 27. selftest_frozen_operation_pin_rejects_permission_path_and_deletion_mutations
run('selftest_frozen_operation_pin_rejects_permission_path_and_deletion_mutations', () => {
  // A small frozen table, independent of FROZEN_OPERATIONS, that describes
  // exactly the two operations baseValidTwoOpDoc() defines. This is the same
  // mechanism step 23 uses against the real 62-operation table, exercised
  // here against a synthetic document so the mechanism itself is tested
  // without needing every fixture in this file to reproduce the table in issue 380.
  const SMALL_FROZEN_TABLE = [
    ['getWidget', 'GET', '/widgets/{id}', 'widget:read'],
    ['putWidget', 'PUT', '/widgets/{id}', 'widget:write'],
  ];

  const accepted = checkDocument(baseValidTwoOpDoc(), { frozenOperations: SMALL_FROZEN_TABLE });
  expect('selftest_frozen_operation_pin_rejects_permission_path_and_deletion_mutations (accepts the matching document)',
    accepted.failures.length === 0, JSON.stringify(accepted.failures));

  const permChanged = baseValidTwoOpDoc();
  // "config:write" remains part of x-it-permissions in this document, so
  // step 6 does not fail; only the frozen pin can catch this mutation.
  permChanged.paths['/widgets/{id}'].put['x-it-permission'] = 'config:write';
  const rPerm = checkDocument(permChanged, { frozenOperations: SMALL_FROZEN_TABLE });
  expect('selftest_frozen_operation_pin_rejects_permission_path_and_deletion_mutations (permission changed)',
    rPerm.failures.some((f) => f.includes('frozen operation putWidget permission has changed') &&
      f.includes('widget:write') && f.includes('config:write')),
    JSON.stringify(rPerm.failures));

  const pathMoved = baseValidTwoOpDoc();
  const movedItem = pathMoved.paths['/widgets/{id}'];
  delete pathMoved.paths['/widgets/{id}'];
  pathMoved.paths['/widgets/{id}/moved'] = movedItem;
  const rPath = checkDocument(pathMoved, { frozenOperations: SMALL_FROZEN_TABLE });
  expect('selftest_frozen_operation_pin_rejects_permission_path_and_deletion_mutations (path moved)',
    rPath.failures.some((f) => f.includes('frozen operation getWidget has moved')) &&
    rPath.failures.some((f) => f.includes('frozen operation putWidget has moved')),
    JSON.stringify(rPath.failures));

  const deleted = baseValidTwoOpDoc();
  delete deleted.paths['/widgets/{id}'].put;
  deleted['x-it-operation-count'] = 1;
  const rDel = checkDocument(deleted, { frozenOperations: SMALL_FROZEN_TABLE });
  expect('selftest_frozen_operation_pin_rejects_permission_path_and_deletion_mutations (operation deleted)',
    rDel.failures.some((f) => f.includes('frozen operation is missing from the document: putWidget')),
    JSON.stringify(rDel.failures));
});

// 28. selftest_frozen_operation_pin_rejects_an_undeclared_extra_operation
run('selftest_frozen_operation_pin_rejects_an_undeclared_extra_operation', () => {
  const SMALL_FROZEN_TABLE = [
    ['getWidget', 'GET', '/widgets/{id}', 'widget:read'],
    ['putWidget', 'PUT', '/widgets/{id}', 'widget:write'],
  ];
  const d = baseValidTwoOpDoc();
  d.paths['/widgets/extra'] = { get: okGetOp('getWidgetExtra', 'widget:read', 'irtctl widgets extra') };
  d['x-it-operation-count'] = 3;
  const r = checkDocument(d, { frozenOperations: SMALL_FROZEN_TABLE });
  expect('selftest_frozen_operation_pin_rejects_an_undeclared_extra_operation',
    r.failures.some((f) => f.includes('operation is not in the frozen operation set: getWidgetExtra')),
    JSON.stringify(r.failures));
});

// 29. selftest_frozen_permission_vocabulary_pin_rejects_widening_and_reordering
run('selftest_frozen_permission_vocabulary_pin_rejects_widening_and_reordering', () => {
  const SMALL_FROZEN_PERM_VOCAB = ['none', 'widget:read', 'widget:write', 'config:read', 'config:write'];

  const accepted = checkDocument(baseValidTwoOpDoc(), { frozenPermissionVocabulary: SMALL_FROZEN_PERM_VOCAB });
  expect('selftest_frozen_permission_vocabulary_pin_rejects_widening_and_reordering (accepts the matching vocabulary)',
    accepted.failures.length === 0, JSON.stringify(accepted.failures));

  const widened = baseValidTwoOpDoc();
  widened['x-it-permissions'] = widened['x-it-permissions'].concat(['widget:admin']);
  const rWidened = checkDocument(widened, { frozenPermissionVocabulary: SMALL_FROZEN_PERM_VOCAB });
  expect('selftest_frozen_permission_vocabulary_pin_rejects_widening_and_reordering (widened)',
    rWidened.failures.some((f) => f.includes('x-it-permissions must be exactly the frozen permission vocabulary')),
    JSON.stringify(rWidened.failures));

  const reordered = baseValidTwoOpDoc();
  reordered['x-it-permissions'] = ['none', 'widget:write', 'widget:read', 'config:read', 'config:write'];
  const rReordered = checkDocument(reordered, { frozenPermissionVocabulary: SMALL_FROZEN_PERM_VOCAB });
  expect('selftest_frozen_permission_vocabulary_pin_rejects_widening_and_reordering (reordered)',
    rReordered.failures.some((f) => f.includes('x-it-permissions must be exactly the frozen permission vocabulary')),
    JSON.stringify(rReordered.failures));
});

// 30. selftest_rejects_an_unbounded_request_body_behind_a_ref
run('selftest_rejects_an_unbounded_request_body_behind_a_ref', () => {
  // The Do NOT list in issue 380 requires every future request body to be a
  // $ref to a named component schema, never inline. This is that shape,
  // checked against the same rule test 22 already exercises against the
  // inline form: the rule must produce the identical result behind a $ref.
  function docWithRefBody(schemas) {
    return mkDoc({
      opCount: 1,
      expensive: ['explainRequest'],
      permissions: ['none', 'explain:run'],
      paths: {
        '/explain': {
          post: {
            operationId: 'explainRequest',
            summary: 'Run a synthetic request for testing purposes.',
            'x-it-permission': 'explain:run',
            'x-it-cli': 'irtctl explain',
            parameters: [
              { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
              { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
              { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
            ],
            requestBody: { content: { 'application/json': { schema: { '$ref': '#/components/schemas/ExplainInput' } } } },
            responses: {
              '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
              '409': { description: 'x' }, '412': { description: 'x' }, '413': { description: 'x' }, '422': { description: 'x' },
              '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
            },
          },
        },
      },
      components: { schemas },
    });
  }

  const unbounded = docWithRefBody({
    ExplainInput: { type: 'object', properties: { expr: { type: 'string' } } },
  });
  const r1 = checkDocument(unbounded);
  expect('selftest_rejects_an_unbounded_request_body_behind_a_ref (unbounded ref target fails)',
    r1.failures.some((f) => f.includes('unbounded string in requestBody') &&
      f.includes('/components/schemas/ExplainInput/properties/expr')),
    JSON.stringify(r1.failures));

  const bounded = docWithRefBody({
    ExplainInput: { type: 'object', properties: { expr: { type: 'string', maxLength: 4096 } } },
  });
  const r2 = checkDocument(bounded);
  expect('selftest_rejects_an_unbounded_request_body_behind_a_ref (bounded ref target accepts)',
    r2.failures.length === 0, JSON.stringify(r2.failures));
});

// 31. selftest_rejects_unbounded_composition_type_array_and_pattern_properties
run('selftest_rejects_unbounded_composition_type_array_and_pattern_properties', () => {
  function docWithBody(schema) {
    return mkDoc({
      opCount: 1,
      expensive: ['createThing'],
      paths: {
        '/things': {
          post: {
            operationId: 'createThing',
            summary: 'Create one thing for testing purposes.',
            'x-it-permission': 'widget:write',
            'x-it-cli': 'irtctl things create',
            parameters: [
              { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
              { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
              { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
            ],
            requestBody: { content: { 'application/json': { schema } } },
            responses: {
              '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
              '409': { description: 'x' }, '412': { description: 'x' }, '413': { description: 'x' }, '422': { description: 'x' },
              '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
            },
          },
        },
      },
    });
  }

  const rAllOf = checkDocument(docWithBody({ allOf: [{ type: 'object', properties: { expr: { type: 'string' } } }] }));
  expect('selftest_rejects_unbounded_composition_type_array_and_pattern_properties (allOf)',
    rAllOf.failures.some((f) => f.includes('unbounded string in requestBody') && f.includes('allOf/0/properties/expr')),
    JSON.stringify(rAllOf.failures));

  const rOneOf = checkDocument(docWithBody({ oneOf: [{ type: 'array', items: { type: 'string', maxLength: 8 } }] }));
  expect('selftest_rejects_unbounded_composition_type_array_and_pattern_properties (oneOf array with no maxItems)',
    rOneOf.failures.some((f) => f.includes('unbounded array in requestBody') && f.includes('oneOf/0')),
    JSON.stringify(rOneOf.failures));

  const rTypeArray = checkDocument(docWithBody({ type: 'object', properties: { note: { type: ['string', 'null'] } } }));
  expect('selftest_rejects_unbounded_composition_type_array_and_pattern_properties (type array containing string)',
    rTypeArray.failures.some((f) => f.includes('unbounded string in requestBody') && f.includes('properties/note')),
    JSON.stringify(rTypeArray.failures));

  const rPatternProps = checkDocument(docWithBody({ type: 'object', patternProperties: { '^x-': { type: 'string', maxLength: 8 } } }));
  expect('selftest_rejects_unbounded_composition_type_array_and_pattern_properties (patternProperties with no maxProperties)',
    rPatternProps.failures.some((f) => f.includes('unbounded object with patternProperties and no maxProperties')),
    JSON.stringify(rPatternProps.failures));
});

// 32. selftest_rejects_a_ref_schema_that_strips_a_query_parameter_bound
run('selftest_rejects_a_ref_schema_that_strips_a_query_parameter_bound', () => {
  function docWithCursorLike(cursorSchema) {
    return mkDoc({
      opCount: 1,
      expensive: ['listThings'],
      paths: {
        '/things': {
          get: {
            operationId: 'listThings',
            summary: 'List every thing for testing purposes.',
            'x-it-permission': 'widget:read',
            'x-it-cli': 'irtctl things',
            parameters: [
              { name: 'If-None-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 4096 } },
              { name: 'cursor', in: 'query', required: false, schema: { '$ref': '#/components/schemas/CursorSchema' } },
            ],
            responses: {
              '200': { description: 'x' }, '304': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
              '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
            },
          },
        },
      },
      components: { schemas: { CursorSchema: cursorSchema } },
    });
  }

  const stripped = docWithCursorLike({ type: 'string' });
  const r1 = checkDocument(stripped);
  expect('selftest_rejects_a_ref_schema_that_strips_a_query_parameter_bound (ref target has no maxLength)',
    r1.failures.some((f) => f.includes('query or header string parameter has no maxLength') &&
      f.includes('listThings') && f.includes('cursor')),
    JSON.stringify(r1.failures));

  const bounded = docWithCursorLike({ type: 'string', maxLength: 512, pattern: '^[A-Za-z0-9_-]{1,512}$' });
  const r2 = checkDocument(bounded);
  expect('selftest_rejects_a_ref_schema_that_strips_a_query_parameter_bound (ref target bounded accepts)',
    r2.failures.length === 0, JSON.stringify(r2.failures));
});

// 33. selftest_rejects_an_optional_csrf_or_if_match_header
run('selftest_rejects_an_optional_csrf_or_if_match_header', () => {
  const csrfOptional = baseValidTwoOpDoc();
  csrfOptional.paths['/widgets/{id}'].put.parameters =
    csrfOptional.paths['/widgets/{id}'].put.parameters.map((p) =>
      p.name === 'X-IT-CSRF' ? Object.assign({}, p, { required: false }) : p);
  const r1 = checkDocument(csrfOptional);
  expect('selftest_rejects_an_optional_csrf_or_if_match_header (Csrf required flipped to false)',
    r1.failures.some((f) => f.includes('Csrf parameter is not required') && f.includes('putWidget')),
    JSON.stringify(r1.failures));

  // An inline replacement is exactly as unenforced as a required flip on the
  // shared component: neither goes through resolveParam differently, both
  // simply carry required !== true on the resolved parameter object.
  const csrfInlineOptional = baseValidTwoOpDoc();
  csrfInlineOptional.paths['/widgets/{id}'].put.parameters =
    csrfInlineOptional.paths['/widgets/{id}'].put.parameters.map((p) =>
      p.name === 'X-IT-CSRF'
        ? { name: 'X-IT-CSRF', in: 'header', required: false, schema: { type: 'string', maxLength: 1048576 } }
        : p);
  const r2 = checkDocument(csrfInlineOptional);
  expect('selftest_rejects_an_optional_csrf_or_if_match_header (inline Csrf replacement, required false)',
    r2.failures.some((f) => f.includes('Csrf parameter is not required') && f.includes('putWidget')),
    JSON.stringify(r2.failures));

  const ifMatchOptional = mkDoc({
    opCount: 1,
    expensive: ['putConfigResource'],
    paths: {
      '/config/{kind}/{ns}/{name}': {
        parameters: [
          { name: 'kind', in: 'path', required: true, schema: { type: 'string', maxLength: 64, pattern: '^[a-z][a-z0-9-]{0,63}$' } },
          { name: 'ns', in: 'path', required: true, schema: { type: 'string', maxLength: 63, pattern: '^[a-z0-9-]{1,63}$' } },
          { name: 'name', in: 'path', required: true, schema: { type: 'string', maxLength: 253, pattern: '^[a-z0-9.-]{1,253}$' } },
        ],
        put: {
          operationId: 'putConfigResource',
          summary: 'Replace one namespaced configuration resource.',
          'x-it-permission': 'config:write',
          'x-it-cli': 'irtctl config apply -f -',
          parameters: [
            { name: 'X-IT-CSRF', in: 'header', required: true, schema: { type: 'string', maxLength: 256 } },
            { name: 'If-Match', in: 'header', required: false, schema: { type: 'string', maxLength: 256 } },
            { name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 255 } },
            { name: 'X-IT-Reason', in: 'header', required: false, schema: { type: 'string', maxLength: 1024 } },
          ],
          responses: {
            '200': { description: 'x' }, '401': { description: 'x' }, '403': { description: 'x' },
            '404': { description: 'x' }, '409': { description: 'x' }, '412': { description: 'x' },
            '413': { description: 'x' }, '422': { description: 'x' },
            '429': { description: 'x', headers: { 'Retry-After': retryHeader() } }, '500': { description: 'x' },
          },
        },
      },
    },
  });
  const r3 = checkDocument(ifMatchOptional);
  expect('selftest_rejects_an_optional_csrf_or_if_match_header (IfMatch required false)',
    r3.failures.some((f) => f.includes('IfMatch parameter is not required') && f.includes('putConfigResource')),
    JSON.stringify(r3.failures));
});

// 34. selftest_path_parameter_vocabulary_pin_rejects_a_vacuous_pattern
run('selftest_path_parameter_vocabulary_pin_rejects_a_vacuous_pattern', () => {
  // A small vocabulary, independent of FROZEN_PATH_PARAMETER_VOCABULARY,
  // pinned to the exact schema baseValidTwoOpDoc() gives its "id" path
  // parameter. Presence-only step 24 accepts "^.*$" because it has nonzero
  // length; only a pin against a value the document under test cannot edit
  // can tell that pattern apart from one that actually constrains anything.
  const SMALL_PARAM_VOCAB = { id: { maxLength: 64, pattern: '^[a-z0-9]{1,64}$' } };

  const accepted = checkDocument(baseValidTwoOpDoc(), { pathParameterVocabulary: SMALL_PARAM_VOCAB });
  expect('selftest_path_parameter_vocabulary_pin_rejects_a_vacuous_pattern (accepts the matching schema)',
    accepted.failures.length === 0, JSON.stringify(accepted.failures));

  const vacuous = baseValidTwoOpDoc();
  vacuous.paths['/widgets/{id}'].parameters =
    vacuous.paths['/widgets/{id}'].parameters.map((p) =>
      p.name === 'id' ? Object.assign({}, p, { schema: { type: 'string', maxLength: 256, pattern: '^.*$' } }) : p);
  const rVacuous = checkDocument(vacuous, { pathParameterVocabulary: SMALL_PARAM_VOCAB });
  expect('selftest_path_parameter_vocabulary_pin_rejects_a_vacuous_pattern (widened to ^.*$ and 256, still present, still rejected)',
    rVacuous.failures.some((f) => f.includes('path parameter does not match the frozen vocabulary for its name') &&
      f.includes('getWidget') && f.includes('id')),
    JSON.stringify(rVacuous.failures));

  const shortened = baseValidTwoOpDoc();
  shortened.paths['/widgets/{id}'].parameters =
    shortened.paths['/widgets/{id}'].parameters.map((p) =>
      p.name === 'id' ? Object.assign({}, p, { schema: { type: 'string', maxLength: 8, pattern: '^[a-z0-9]{1,64}$' } }) : p);
  const rShortened = checkDocument(shortened, { pathParameterVocabulary: SMALL_PARAM_VOCAB });
  expect('selftest_path_parameter_vocabulary_pin_rejects_a_vacuous_pattern (maxLength narrowed still rejected, not just widened)',
    rShortened.failures.some((f) => f.includes('path parameter does not match the frozen vocabulary for its name')),
    JSON.stringify(rShortened.failures));
});

// 35. selftest_json_parser_matches_native_parse_for_a_document_with_no_duplicates
run('selftest_json_parser_matches_native_parse_for_a_document_with_no_duplicates', () => {
  const text = JSON.stringify({
    openapi: '3.1.0',
    paths: { '/x': { get: { operationId: 'getX', 'x-it-permission': 'none' } } },
    numbers: [0, -1, 1.5, -2.25e10, 3e-7],
    nested: { a: { b: { c: [1, 2, 3] } } },
    escapes: 'line one\nline two\ttabbed "quoted" back\\slash',
  });
  const native = JSON.parse(text);
  const custom = parseJsonRejectingDuplicateKeys(text);
  expect('selftest_json_parser_matches_native_parse_for_a_document_with_no_duplicates',
    JSON.stringify(custom) === JSON.stringify(native),
    'native=' + JSON.stringify(native) + ' custom=' + JSON.stringify(custom));
});

// 36. selftest_json_parser_rejects_a_top_level_duplicate_key
run('selftest_json_parser_rejects_a_top_level_duplicate_key', () => {
  let threw = null;
  try {
    parseJsonRejectingDuplicateKeys('{"a": 1, "b": 2, "a": 3}');
  } catch (e) {
    threw = e;
  }
  expect('selftest_json_parser_rejects_a_top_level_duplicate_key',
    threw !== null && /duplicate key "a"/.test(threw.message) && threw.message.includes('JSON Pointer /a'),
    threw ? threw.message : 'did not throw');
});

// 37. selftest_json_parser_rejects_a_nested_duplicate_key_naming_its_pointer
run('selftest_json_parser_rejects_a_nested_duplicate_key_naming_its_pointer', () => {
  const text = '{"paths": {"/overview": {"get": {"x-it-permission": "overview:read", ' +
    '"summary": "s", "x-it-permission": "none"}}}}';
  let threw = null;
  try {
    parseJsonRejectingDuplicateKeys(text);
  } catch (e) {
    threw = e;
  }
  expect('selftest_json_parser_rejects_a_nested_duplicate_key_naming_its_pointer',
    threw !== null && threw.message.includes('duplicate key "x-it-permission"') &&
    threw.message.includes('JSON Pointer /paths/~1overview/get/x-it-permission'),
    threw ? threw.message : 'did not throw');
});

// 38. selftest_json_parser_rejects_malformed_json_without_crashing
run('selftest_json_parser_rejects_malformed_json_without_crashing', () => {
  const cases = ['{"a": 1,}', '{"a": 1 "b": 2}', '{"a": "unterminated', '{"a": tru}', 'not json at all'];
  for (const text of cases) {
    let threw = null;
    try {
      parseJsonRejectingDuplicateKeys(text);
    } catch (e) {
      threw = e;
    }
    expect('selftest_json_parser_rejects_malformed_json_without_crashing (' + JSON.stringify(text) + ')',
      threw !== null && typeof threw.line === 'number' && typeof threw.col === 'number',
      threw ? threw.message : 'did not throw');
  }
});

  return { results, passCount, failCount };
}

function main() {
  const args = process.argv.slice(1);
  if (args[0] === '--selftest') {
    const { results, passCount, failCount } = runSelftest();
    for (const line of results) {
      console.log(line);
    }
    console.log('selftest: ' + passCount + ' passed, ' + failCount + ' failed (of ' + (passCount + failCount) + ' assertions across 38 named tests)');
    process.exit(failCount === 0 ? 0 : 1);
  }

  const filePath = args[0];
  if (!filePath) {
    console.error('usage: api-contract-check.js <path-to-openapi.json> | --selftest');
    process.exit(2);
  }

  const fs = require('fs');
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    console.log('cannot read file: ' + filePath + ': ' + e.message);
    process.exit(1);
  }

  let doc;
  try {
    doc = parseJsonRejectingDuplicateKeys(raw);
  } catch (e) {
    const line = typeof e.line === 'number' ? e.line : 1;
    const col = typeof e.col === 'number' ? e.col : 1;
    console.log('parse error at line ' + line + ' column ' + col + ': ' + e.message);
    process.exit(1);
  }

  const result = checkDocument(doc, {
    frozenOperations: FROZEN_OPERATIONS,
    frozenPermissionVocabulary: FROZEN_PERMISSION_VOCABULARY,
    pathParameterVocabulary: FROZEN_PATH_PARAMETER_VOCABULARY,
  });
  if (result.failures.length > 0) {
    for (const f of result.failures) console.log(f);
    process.exit(1);
  }
  console.log('api-contract-check: ' + result.opCount + ' operations, ' + result.permCount + ' permissions, ok');
  process.exit(0);
}

main();
NODE
)"

if [ $# -gt 1 ]; then
  echo "api-contract-check: unknown argument: $2" >&2
  exit 2
fi

if [ $# -gt 0 ]; then
  if [ "$1" = '--selftest' ]; then
    node --eval "$JS" -- --selftest
    exit $?
  fi
  echo "api-contract-check: unknown argument: $1" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

if [ ! -f contract/openapi.v1.json ]; then
  echo 'api-contract-check: contract/openapi.v1.json is missing' >&2
  exit 1
fi

node --eval "$JS" -- contract/openapi.v1.json
