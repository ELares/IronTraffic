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
# not satisfy it, rather than scanning for a specific known-bad pattern. A
# deleted operation, an added one, a mutated path or method, or an empty
# document are all caught by the same small set of rules (chiefly the
# x-it-operation-count invariant and the per-operation structural checks),
# not by a special case for each. See the self-test steps below and the
# implementation's own PR description for a record of each failure mode
# proven to fail loud, then reverted to green.
#
# Implemented with node --eval reading the JSON, so it needs no npm package.
#
# Usage:  scripts/api-contract-check.sh              (checks contract/openapi.v1.json)
#         scripts/api-contract-check.sh --selftest   (runs the 26 named self-tests)
set -euo pipefail

if ! command -v node >/dev/null 2>&1; then
  echo 'api-contract-check: node is not installed' >&2
  exit 1
fi

JS="$(cat <<'NODE'
'use strict';

const METHODS = ['get', 'put', 'post', 'patch', 'delete'];

function decodeJsonPointerSegment(s) {
  return s.replace(/~1/g, '/').replace(/~0/g, '~');
}
function encodeJsonPointerSegment(s) {
  return String(s).replace(/~/g, '~0').replace(/\//g, '~1');
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

function checkBoundedSchema(node, opId, pointer, failures) {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    if (Array.isArray(node)) {
      node.forEach((v, i) => checkBoundedSchema(v, opId, pointer + '/' + i, failures));
    }
    return;
  }
  if (typeof node['$ref'] === 'string') {
    return;
  }
  if (node.type === 'string') {
    if (typeof node.maxLength !== 'number') {
      failures.push('unbounded string in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
  }
  if (node.type === 'array') {
    if (typeof node.maxItems !== 'number') {
      failures.push('unbounded array in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
  }
  if (node.additionalProperties && typeof node.additionalProperties === 'object') {
    if (typeof node.maxProperties !== 'number') {
      failures.push('unbounded object with additionalProperties and no maxProperties in requestBody: ' + opId + ' at JSON Pointer ' + pointer);
    }
    checkBoundedSchema(node.additionalProperties, opId, pointer + '/additionalProperties', failures);
  }
  if (node.properties && typeof node.properties === 'object') {
    for (const k of Object.keys(node.properties)) {
      checkBoundedSchema(node.properties[k], opId, pointer + '/properties/' + encodeJsonPointerSegment(k), failures);
    }
  }
  if (node.items) {
    checkBoundedSchema(node.items, opId, pointer + '/items', failures);
  }
}

function checkDocument(doc) {
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
    if (!isGet && !hasParam('X-IT-CSRF', 'header')) {
      fail('non-GET operation does not reference the Csrf parameter: ' + id);
    }

    // step 10
    const isConfigMutating =
      (['put', 'patch', 'delete'].includes(op.method) && op.path.startsWith('/config')) ||
      op.operationId === 'loadConfig' || op.operationId === 'rollbackConfig';
    if (isConfigMutating && !hasParam('If-Match', 'header')) {
      fail('config mutating operation does not reference the IfMatch parameter: ' + id);
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

    // step 24
    for (const pm of op.params) {
      if (!pm || pm.in !== 'path') continue;
      const sch = pm.schema || {};
      if (sch.type === 'string') {
        if (typeof sch.maxLength !== 'number' || sch.maxLength > 256) {
          fail('path parameter has no maxLength of at most 256: ' + id + ' parameter ' + pm.name);
        }
        if (typeof sch.pattern !== 'string' || sch.pattern.length === 0) {
          fail('path parameter has no pattern: ' + id + ' parameter ' + pm.name);
        }
      } else if (sch.type === 'integer') {
        if (typeof sch.minimum !== 'number' || typeof sch.maximum !== 'number') {
          fail('integer path parameter has no minimum and maximum: ' + id + ' parameter ' + pm.name);
        }
      } else {
        fail('path parameter must be type string or integer: ' + id + ' parameter ' + pm.name);
      }
    }

    // step 25
    for (const pm of op.params) {
      if (!pm) continue;
      if ((pm.in === 'query' || pm.in === 'header') && pm.schema && pm.schema.type === 'string') {
        if (typeof pm.schema.maxLength !== 'number') {
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
          checkBoundedSchema(schema, id, pointer, failures);
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

  return { results, passCount, failCount };
}

function main() {
  const args = process.argv.slice(1);
  if (args[0] === '--selftest') {
    const { results, passCount, failCount } = runSelftest();
    for (const line of results) {
      console.log(line);
    }
    console.log('selftest: ' + passCount + ' passed, ' + failCount + ' failed (of ' + (passCount + failCount) + ' assertions across 26 named tests)');
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
    doc = JSON.parse(raw);
  } catch (e) {
    const m = /position (\d+)/.exec(e.message);
    let line = 1;
    let col = 1;
    if (m) {
      const pos = parseInt(m[1], 10);
      const upto = raw.slice(0, pos);
      const lns = upto.split('\n');
      line = lns.length;
      col = lns[lns.length - 1].length + 1;
    }
    console.log('parse error at line ' + line + ' column ' + col + ': ' + e.message);
    process.exit(1);
  }

  const result = checkDocument(doc);
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
