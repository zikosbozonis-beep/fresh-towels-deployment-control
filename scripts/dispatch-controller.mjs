#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

function required(name, pattern) {
  const value = process.env[name]?.trim();
  if (!value || (pattern && !pattern.test(value))) throw new Error(`${name} is invalid`);
  return value;
}

async function main() {
  const [identityPath, oidcPath] = process.argv.slice(2);
  if (!identityPath || !oidcPath) throw new Error('identity and OIDC paths are required');
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
  const response = await fetch(new URL('/v1/dispatch', origin), {
    method: 'POST',
    headers: {
      authorization: `Bearer ${oidc}`,
      'content-type': 'application/json',
      'user-agent': 'deployment-control-packager',
    },
    body: JSON.stringify({ releaseRequestBase64 }),
  });
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
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
}

main().catch((error) => {
  console.error(`Controller dispatch stopped: ${error.message}`);
  process.exitCode = 1;
});
