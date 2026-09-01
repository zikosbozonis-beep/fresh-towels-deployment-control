import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import test from 'node:test';
import { canonicalJson, sha256 } from '../scripts/control-contract.mjs';
import { handleDispatch } from '../dispatcher/worker.mjs';

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
  SOURCE_REPOSITORY: 'owner/private-app',
  SOURCE_REPOSITORY_ID: '1001',
  SOURCE_WORKFLOW_PATH: '.github/workflows/release-handoff.yml',
};

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

async function fixture(claimOverrides = {}) {
  const oidcKeys = await webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const token = await jwt(oidcKeys.privateKey, oidcClaims(claimOverrides));
  const request = baseRequest(sha256(Buffer.from(token)));
  const encoded = Buffer.from(canonicalJson(request)).toString('base64url');
  const appKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const applicationEnvironment = {
    ...env,
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
  const httpRequest = new Request('https://dispatcher.example/v1/dispatch', {
    body: JSON.stringify({ releaseRequestBase64: encoded }),
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    method: 'POST',
  });
  return { applicationEnvironment, calls, encoded, fetcher, httpRequest, token };
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
