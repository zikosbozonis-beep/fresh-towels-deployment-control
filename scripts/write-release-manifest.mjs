#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { canonicalJson, sha256 } from './control-contract.mjs';

const shaPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const idPattern = /^[1-9][0-9]{0,19}$/;
const uuidPattern = /^[a-f0-9-]{36}$/;
const noncePattern = /^[A-Za-z0-9_-]{43}$/;

function exact(name, pattern) {
  const value = process.env[name]?.trim();
  if (!value || !pattern.test(value)) throw new Error(`${name} is invalid`);
  return value;
}

async function main() {
  const [identityPath, outputPath] = process.argv.slice(2);
  if (!identityPath || !outputPath) {
    throw new Error('identity and output paths are required');
  }
  const controller = JSON.parse(await readFile(resolve(identityPath), 'utf8'));
  if (
    controller.configured !== true ||
    !idPattern.test(controller.repositoryId ?? '')
  ) {
    throw new Error('controller identity is not bootstrapped');
  }
  const manifest = {
    controller: {
      commitSha: exact('CONTROLLER_SHA', shaPattern),
      repositoryId: controller.repositoryId,
    },
    evidence: {
      oidcTokenSha256: exact('OIDC_TOKEN_SHA256', digestPattern),
    },
    nonce: exact('RELEASE_NONCE', noncePattern),
    payload: {
      bytes: Number(exact('PAYLOAD_BYTES', /^\d{1,10}$/)),
      sha256: exact('PAYLOAD_SHA256', digestPattern),
    },
    requestId: exact('RELEASE_REQUEST_ID', uuidPattern),
    schema: 'deployment-control/private-transport-manifest/v1',
    source: {
      commitSha: exact('SOURCE_SHA', shaPattern),
      repositoryId: exact('SOURCE_REPOSITORY_ID', idPattern),
      workflowRunAttempt: Number(exact('SOURCE_RUN_ATTEMPT', /^\d{1,3}$/)),
      workflowRunId: exact('SOURCE_RUN_ID', idPattern),
    },
  };
  if (
    !Number.isSafeInteger(manifest.payload.bytes) ||
    manifest.payload.bytes < 1 ||
    !Number.isSafeInteger(manifest.source.workflowRunAttempt) ||
    manifest.source.workflowRunAttempt < 1
  ) {
    throw new Error('manifest numeric values are invalid');
  }
  const canonical = canonicalJson(manifest);
  await writeFile(resolve(outputPath), `${canonical}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o400,
  });
  process.stdout.write(`${sha256(Buffer.from(`${canonical}\n`))}\n`);
}

main().catch((error) => {
  console.error(`Release manifest creation stopped: ${error.message}`);
  process.exitCode = 1;
});
