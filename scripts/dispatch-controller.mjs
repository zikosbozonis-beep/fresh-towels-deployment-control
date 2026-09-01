#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  decodeCanonicalBase64Url,
  validateReleaseRequest,
} from './control-contract.mjs';

function required(name, pattern) {
  const value = process.env[name]?.trim();
  if (!value || (pattern && !pattern.test(value))) throw new Error(`${name} is invalid`);
  return value;
}

async function main() {
  const [identityPath, oidcPath, mode = 'dispatch'] = process.argv.slice(2);
  if (!identityPath || !oidcPath) throw new Error('identity and OIDC paths are required');
  if (!['dispatch', 'execute-claim', 'execute-finish'].includes(mode)) throw new Error('dispatcher operation is invalid');
  const identity = JSON.parse(await readFile(resolve(identityPath), 'utf8'));
  if (
    identity.configured !== true ||
    !/^\d+$/.test(identity.repositoryId ?? '') ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(identity.repository ?? '')
  ) {
    throw new Error('controller identity is not bootstrapped');
  }
  const origin = new URL(identity.dispatcherOrigin);
  if (
    origin.protocol !== 'https:' ||
    origin.username ||
    origin.password ||
    origin.pathname !== '/' ||
    origin.search ||
    origin.hash ||
    origin.hostname.endsWith('.invalid')
  ) {
    throw new Error('dispatcher origin is not provisioned');
  }
  const oidc = (await readFile(resolve(oidcPath), 'utf8')).trim();
  if (oidc.length < 100 || oidc.length > 16_384 || oidc.split('.').length !== 3) {
    throw new Error('GitHub OIDC evidence is malformed');
  }
  const releaseRequestBase64 = required(
    'RELEASE_REQUEST_BASE64',
    /^[A-Za-z0-9_-]{100,32768}$/,
  );
  const releaseRequest = JSON.parse(
    decodeCanonicalBase64Url(
      releaseRequestBase64,
      'RELEASE_REQUEST_BASE64',
    ).toString('utf8'),
  );
  const expectedReceipt = validateReleaseRequest(releaseRequest);
  const body = { releaseRequestBase64 };
  if (mode === 'execute-finish') {
    body.outcome = required('EXECUTION_OUTCOME', /^(canary_verified|executed|execution_ambiguous)$/);
    body.providerReceiptSha256 = required('PROVIDER_RECEIPT_SHA256', /^[a-f0-9]{64}$/);
  }
  const endpoint = {
    dispatch: '/v1/dispatch',
    'execute-claim': '/v1/execute-claim',
    'execute-finish': '/v1/execute-finish',
  }[mode];
  const response = await fetch(
    new URL(endpoint, origin),
    {
    method: 'POST',
    headers: {
      authorization: `Bearer ${oidc}`,
      'content-type': 'application/json',
      'user-agent': 'deployment-control-packager',
    },
    body: JSON.stringify(body),
    },
  );
  if (response.status !== 202) {
    throw new Error(`OIDC dispatcher returned ${response.status}`);
  }
  const receipt = await response.json();
  if (
    typeof receipt.requestId !== 'string' ||
    !/^[a-f0-9-]{36}$/.test(receipt.requestId) ||
    typeof receipt.requestDigest !== 'string' ||
    !/^[a-f0-9]{64}$/.test(receipt.requestDigest)
  ) {
    throw new Error('OIDC dispatcher receipt is invalid');
  }
  if (
    receipt.requestId !== expectedReceipt.request.requestId ||
    receipt.requestDigest !== expectedReceipt.digest
  ) {
    throw new Error('OIDC dispatcher receipt differs from the requested release');
  }
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
}

main().catch((error) => {
  console.error(`Controller dispatch stopped: ${error.message}`);
  process.exitCode = 1;
});
