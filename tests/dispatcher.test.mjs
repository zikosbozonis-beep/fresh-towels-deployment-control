import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import test from 'node:test';
import { canonicalJson, sha256 } from '../scripts/control-contract.mjs';
import { finishExecution, handleDispatch } from '../dispatcher/worker.mjs';

globalThis.crypto ??= webcrypto;

const now = Date.parse('2026-09-01T10:00:00.000Z');
const controllerSha = '2'.repeat(40);
const sourceSha = '1'.repeat(40);
const env = {
  CONTROLLER_COMMIT_SHA: controllerSha,
  CONTROLLER_REPOSITORY: 'owner/control',
  CONTROLLER_REPOSITORY_ID: '2002',
  GITHUB_APP_ID: '3003',
  GITHUB_APP_INSTALLATION_ID: '4004',
  REQUESTER_APP_ACTOR_ID: '7007',
  SOURCE_REPOSITORY: 'owner/private-app',
  SOURCE_REPOSITORY_ID: '1001',
  SOURCE_WORKFLOW_PATH: '.github/workflows/release-handoff.yml',
};

class FakeD1 {
  constructor() {
    this.rows = new Map();
  }

  prepare(sql) {
    const database = this;
    return {
      bind(...values) {
        return {
          async run() {
            if (sql.startsWith('INSERT')) {
              const [requestId, jti, nonce, digest, sourceRepositoryId, sourceSha, controllerShaValue, runId, runAttempt, claimedAt] = values;
              for (const row of database.rows.values()) {
                if (row.requestId === requestId || row.jti === jti || row.nonce === nonce || row.digest === digest) throw new Error('D1 UNIQUE constraint failed');
              }
              database.rows.set(requestId, { controllerSha: controllerShaValue, digest, jti, nonce, requestId, runAttempt, runId, sourceRepositoryId, sourceSha, state: 'claimed', status: null, updatedAt: claimedAt });
              return { meta: { changes: 1 }, success: true };
            }
            if (sql.startsWith('UPDATE')) {
              if (sql.includes("SET state = 'executing'")) {
                const [executorJti, controllerRunId, controllerRunAttempt, updatedAt, requestId, digest] = values;
                const row = database.rows.get(requestId);
                if (!row || row.state !== 'dispatched' || row.digest !== digest) return { meta: { changes: 0 }, success: true };
                for (const candidate of database.rows.values()) {
                  if (candidate.executorJti === executorJti || candidate.controllerRunId === controllerRunId) throw new Error('D1 UNIQUE constraint failed');
                }
                Object.assign(row, { controllerRunAttempt, controllerRunId, executorJti, state: 'executing', updatedAt });
                return { meta: { changes: 1 }, success: true };
              }
              if (sql.includes('execution_receipt_sha256')) {
                const [state, receipt, updatedAt, requestId, digest, controllerRunId, controllerRunAttempt] = values;
                const row = database.rows.get(requestId);
                if (!row || row.state !== 'executing' || row.digest !== digest || row.controllerRunId !== controllerRunId || row.controllerRunAttempt !== controllerRunAttempt) return { meta: { changes: 0 }, success: true };
                Object.assign(row, { receipt, state, updatedAt });
                return { meta: { changes: 1 }, success: true };
              }
              const [state, status, updatedAt, requestId] = values;
              const row = database.rows.get(requestId);
              if (!row || row.state !== 'claimed') return { meta: { changes: 0 }, success: true };
              Object.assign(row, { state, status, updatedAt });
              return { meta: { changes: 1 }, success: true };
            }
            throw new Error('unexpected D1 statement');
          },
        };
      },
    };
  }
}

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function baseRequest(oidcTokenSha256) {
  return {
    artifact: {
      ciphertextBlobSha1: '4'.repeat(40), ciphertextSha256: 'c'.repeat(64),
      encryptionKeySha256: 'd'.repeat(64), manifestBlobSha1: '5'.repeat(40),
      plaintextBytes: 42, plaintextSha256: 'b'.repeat(64), releaseId: '6006',
      transportCommitSha: '3'.repeat(40),
      transportTag: 'deployment-control/11111111-1111-4111-8111-111111111111',
    },
    controller: { commitSha: controllerSha, repositoryId: '2002' },
    evidence: { immutableRelease: true, manifestSha256: 'e'.repeat(64), oidcTokenSha256 },
    expiresAt: '2026-09-01T10:15:00.000Z', issuedAt: '2026-09-01T10:00:00.000Z',
    nonce: 'A'.repeat(43), operation: 'production-release',
    requestId: '11111111-1111-4111-8111-111111111111',
    schema: 'deployment-control/release-request/v1',
    source: { commitSha: sourceSha, repositoryId: '1001', workflowRunAttempt: 1, workflowRunId: '5005' },
  };
}

function oidcClaims(overrides = {}) {
  const seconds = Math.floor(now / 1000);
  return {
    aud: 'deployment-control-packaging-v1', event_name: 'workflow_dispatch',
    exp: seconds + 300, iat: seconds - 5, iss: 'https://token.actions.githubusercontent.com',
    job_workflow_ref: `owner/control/.github/workflows/package-release.yml@${controllerSha}`,
    job_workflow_sha: controllerSha, jti: 'synthetic-jti-1234567890', nbf: seconds - 5,
    ref: 'refs/heads/main', ref_type: 'branch', repository: 'owner/private-app',
    repository_id: '1001', repository_visibility: 'private', run_attempt: '1',
    run_id: '5005', runner_environment: 'github-hosted', sha: sourceSha,
    sub: 'repo:owner/private-app:ref:refs/heads/main',
    workflow_ref: 'owner/private-app/.github/workflows/release-handoff.yml@refs/heads/main',
    workflow_sha: sourceSha, ...overrides,
  };
}

async function jwt(privateKey, claims, kid = 'test-key') {
  const header = b64url(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }));
  const payload = b64url(JSON.stringify(claims));
  const signature = await webcrypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', privateKey, Buffer.from(`${header}.${payload}`),
  );
  return `${header}.${payload}.${Buffer.from(signature).toString('base64url')}`;
}

async function fixture(claimOverrides = {}, operation = 'production-release') {
  const oidcKeys = await webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const token = await jwt(oidcKeys.privateKey, oidcClaims(claimOverrides));
  const request = baseRequest(sha256(Buffer.from(token)));
  request.operation = operation;
  const encoded = Buffer.from(canonicalJson(request)).toString('base64url');
  const appKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const applicationEnvironment = {
    ...env,
    DISPATCH_STATE: new FakeD1(),
    GITHUB_APP_PRIVATE_KEY: appKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  };
  const jwk = await webcrypto.subtle.exportKey('jwk', oidcKeys.publicKey);
  Object.assign(jwk, { alg: 'RS256', kid: 'test-key', use: 'sig' });
  const calls = [];
  const fetcher = async (url, options = {}) => {
    calls.push({ options, url: String(url) });
    if (String(url).endsWith('/.well-known/openid-configuration')) return Response.json({ issuer: 'https://token.actions.githubusercontent.com', jwks_uri: 'https://token.actions.githubusercontent.com/.well-known/jwks' });
    if (String(url).endsWith('/.well-known/jwks')) return Response.json({ keys: [jwk] });
    if (String(url).includes('/access_tokens')) return Response.json({ repositories: [{ id: 2002 }], token: 'synthetic-installation-token-value' });
    if (String(url).endsWith('/dispatches')) return new Response(null, { status: 204 });
    throw new Error('unexpected network request');
  };
  const makeRequest = () => new Request('https://dispatcher.example/v1/dispatch', {
      body: JSON.stringify({ releaseRequestBase64: encoded }),
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      method: 'POST',
    });
  return { applicationEnvironment, calls, encoded, fetcher, httpRequest: makeRequest(), makeRequest, oidcKeys, token };
}

test('valid GitHub OIDC evidence dispatches with a down-scoped public-only App token', async () => {
  const value = await fixture();
  const response = await handleDispatch(value.httpRequest, value.applicationEnvironment, value.fetcher, now);
  assert.equal(response.status, 202);
  assert.equal(value.calls.length, 4);
  const tokenBody = JSON.parse(value.calls[2].options.body);
  assert.deepEqual(tokenBody, { permissions: { actions: 'write' }, repository_ids: [2002] });
  const dispatch = JSON.parse(value.calls[3].options.body);
  assert.deepEqual(dispatch, { inputs: { release_request_base64: value.encoded }, ref: 'main' });
  assert.equal(value.applicationEnvironment.DISPATCH_STATE.rows.get('11111111-1111-4111-8111-111111111111').state, 'dispatched');
});

test('altered caller identity and altered signatures fail before App token issuance', async () => {
  const wrongWorkflow = await fixture({ workflow_sha: '9'.repeat(40) });
  const rejectedClaim = await handleDispatch(wrongWorkflow.httpRequest, wrongWorkflow.applicationEnvironment, wrongWorkflow.fetcher, now);
  assert.equal(rejectedClaim.status, 401);
  assert.equal(wrongWorkflow.calls.length, 2);

  const tampered = await fixture();
  const body = JSON.parse(await tampered.httpRequest.clone().text());
  const parts = tampered.token.split('.');
  parts[2] = `${parts[2].slice(0, -1)}${parts[2].endsWith('A') ? 'B' : 'A'}`;
  const changed = parts.join('.');
  const request = baseRequest(sha256(Buffer.from(changed)));
  body.releaseRequestBase64 = Buffer.from(canonicalJson(request)).toString('base64url');
  const invalidRequest = new Request('https://dispatcher.example/v1/dispatch', { body: JSON.stringify(body), headers: { authorization: `Bearer ${changed}`, 'content-type': 'application/json' }, method: 'POST' });
  const rejectedSignature = await handleDispatch(invalidRequest, tampered.applicationEnvironment, tampered.fetcher, now);
  assert.equal(rejectedSignature.status, 401);
  assert.equal(tampered.calls.length, 2);
});

test('stale evidence and unexpected public input fail without network activity', async () => {
  const value = await fixture();
  const stale = await handleDispatch(value.httpRequest, value.applicationEnvironment, value.fetcher, now + 16 * 60_000);
  assert.equal(stale.status, 401);
  assert.equal(value.calls.length, 0);
  const injected = new Request('https://dispatcher.example/v1/dispatch', { body: JSON.stringify({ command: 'anything', releaseRequestBase64: value.encoded }), headers: { authorization: `Bearer ${value.token}`, 'content-type': 'application/json' }, method: 'POST' });
  assert.equal((await handleDispatch(injected, value.applicationEnvironment, value.fetcher, now)).status, 401);
});

test('atomic D1 consumption permits one concurrent dispatch and rejects replay', async () => {
  const value = await fixture();
  const responses = await Promise.all([
    handleDispatch(value.makeRequest(), value.applicationEnvironment, value.fetcher, now),
    handleDispatch(value.makeRequest(), value.applicationEnvironment, value.fetcher, now),
  ]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [202, 401]);
  assert.equal(value.calls.filter((call) => call.url.includes('/access_tokens')).length, 1);
  assert.equal(value.calls.filter((call) => call.url.endsWith('/dispatches')).length, 1);
});

test('ambiguous provider failure consumes evidence permanently', async () => {
  const value = await fixture();
  const originalFetcher = value.fetcher;
  const failingFetcher = async (url, options) => {
    if (String(url).endsWith('/dispatches')) {
      value.calls.push({ options, url: String(url) });
      return new Response(null, { status: 503 });
    }
    return originalFetcher(url, options);
  };
  assert.equal((await handleDispatch(value.makeRequest(), value.applicationEnvironment, failingFetcher, now)).status, 401);
  assert.equal(value.applicationEnvironment.DISPATCH_STATE.rows.get('11111111-1111-4111-8111-111111111111').state, 'ambiguous');
  assert.equal((await handleDispatch(value.makeRequest(), value.applicationEnvironment, failingFetcher, now)).status, 401);
  assert.equal(value.calls.filter((call) => call.url.endsWith('/dispatches')).length, 1);
});

function executorClaims(overrides = {}) {
  const seconds = Math.floor(now / 1000);
  return {
    actor_id: '7007', aud: 'deployment-control-executor-v1', environment: 'production',
    event_name: 'workflow_dispatch', exp: seconds + 300, iat: seconds - 5,
    iss: 'https://token.actions.githubusercontent.com', jti: 'executor-jti-1234567890',
    nbf: seconds - 5, ref: 'refs/heads/main', ref_type: 'branch', repository: 'owner/control',
    repository_id: '2002', repository_visibility: 'public', run_attempt: '1',
    run_id: '8008', runner_environment: 'github-hosted', sha: controllerSha,
    sub: 'repo:owner/control:environment:production',
    workflow_ref: 'owner/control/.github/workflows/execute-release.yml@refs/heads/main',
    workflow_sha: controllerSha, ...overrides,
  };
}

test('protected executor OIDC creates one atomic execution claim only', async () => {
  const value = await fixture();
  assert.equal((await handleDispatch(value.makeRequest(), value.applicationEnvironment, value.fetcher, now)).status, 202);
  const executorToken = await jwt(value.oidcKeys.privateKey, executorClaims());
  const makeExecutionRequest = () => new Request('https://dispatcher.example/v1/execute-claim', {
    body: JSON.stringify({ releaseRequestBase64: value.encoded }),
    headers: { authorization: `Bearer ${executorToken}`, 'content-type': 'application/json' },
    method: 'POST',
  });
  const responses = await Promise.all([
    handleDispatch(makeExecutionRequest(), value.applicationEnvironment, value.fetcher, now),
    handleDispatch(makeExecutionRequest(), value.applicationEnvironment, value.fetcher, now),
  ]);
  assert.deepEqual(responses.map((response) => response.status).sort(), [202, 401]);
  assert.equal(value.applicationEnvironment.DISPATCH_STATE.rows.get('11111111-1111-4111-8111-111111111111').state, 'executing');
});

test('the same protected run records one hash-only terminal execution receipt', async () => {
  const value = await fixture();
  assert.equal((await handleDispatch(value.makeRequest(), value.applicationEnvironment, value.fetcher, now)).status, 202);
  const executorToken = await jwt(value.oidcKeys.privateKey, executorClaims());
  const requestFor = (path, extra = {}) => new Request(`https://dispatcher.example${path}`, {
    body: JSON.stringify({ releaseRequestBase64: value.encoded, ...extra }),
    headers: { authorization: `Bearer ${executorToken}`, 'content-type': 'application/json' },
    method: 'POST',
  });
  assert.equal((await handleDispatch(requestFor('/v1/execute-claim'), value.applicationEnvironment, value.fetcher, now)).status, 202);
  const receipt = 'a'.repeat(64);
  assert.equal((await handleDispatch(requestFor('/v1/execute-finish', { outcome: 'executed', providerReceiptSha256: receipt }), value.applicationEnvironment, value.fetcher, now)).status, 202);
  const row = value.applicationEnvironment.DISPATCH_STATE.rows.get('11111111-1111-4111-8111-111111111111');
  assert.equal(row.state, 'executed');
  assert.equal(row.receipt, receipt);
  assert.equal((await handleDispatch(requestFor('/v1/execute-finish', { outcome: 'executed', providerReceiptSha256: receipt }), value.applicationEnvironment, value.fetcher, now)).status, 401);
});

test('executor self/substitution identities fail before execution state changes', async () => {
  const value = await fixture();
  assert.equal((await handleDispatch(value.makeRequest(), value.applicationEnvironment, value.fetcher, now)).status, 202);
  const wrongActor = await jwt(value.oidcKeys.privateKey, executorClaims({ actor_id: '9999' }));
  const request = new Request('https://dispatcher.example/v1/execute-claim', {
    body: JSON.stringify({ releaseRequestBase64: value.encoded }),
    headers: { authorization: `Bearer ${wrongActor}`, 'content-type': 'application/json' },
    method: 'POST',
  });
  assert.equal((await handleDispatch(request, value.applicationEnvironment, value.fetcher, now)).status, 401);
  assert.equal(value.applicationEnvironment.DISPATCH_STATE.rows.get('11111111-1111-4111-8111-111111111111').state, 'dispatched');
});

test('canary completion accepts only the no-provider-mutation terminal state', async () => {
  const database = new FakeD1();
  const request = baseRequest('f'.repeat(64));
  request.operation = 'canary';
  database.rows.set(request.requestId, {
    controllerRunAttempt: 1,
    controllerRunId: '8008',
    digest: 'a'.repeat(64),
    requestId: request.requestId,
    state: 'executing',
  });
  const claims = { run_attempt: '1', run_id: '8008' };
  await assert.rejects(
    finishExecution(request, claims, 'a'.repeat(64), 'executed', 'b'.repeat(64), { DISPATCH_STATE: database }, now),
    /outcome/,
  );
  await finishExecution(request, claims, 'a'.repeat(64), 'canary_verified', 'b'.repeat(64), { DISPATCH_STATE: database }, now);
  assert.equal(database.rows.get(request.requestId).state, 'canary_verified');
});

test('canary executor identity is bound to the reviewed canary environment', async () => {
  const value = await fixture({}, 'canary');
  assert.equal((await handleDispatch(value.makeRequest(), value.applicationEnvironment, value.fetcher, now)).status, 202);
  const executorToken = await jwt(
    value.oidcKeys.privateKey,
    executorClaims({
      environment: 'canary',
      sub: 'repo:owner/control:environment:canary',
    }),
  );
  const request = new Request('https://dispatcher.example/v1/execute-claim', {
    body: JSON.stringify({ releaseRequestBase64: value.encoded }),
    headers: { authorization: `Bearer ${executorToken}`, 'content-type': 'application/json' },
    method: 'POST',
  });
  assert.equal((await handleDispatch(request, value.applicationEnvironment, value.fetcher, now)).status, 202);
});
