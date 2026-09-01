#!/usr/bin/env node

import { appendFile } from 'node:fs/promises';
import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateReleaseRequest,
} from './control-contract.mjs';

function required(name, pattern) {
  const value = process.env[name]?.trim();
  if (!value || (pattern && !pattern.test(value))) throw new Error(`${name} is invalid`);
  return value;
}

async function main() {
  const encoded = required('RELEASE_REQUEST_BASE64', /^[A-Za-z0-9_-]{100,32768}$/);
  const request = JSON.parse(
    decodeCanonicalBase64Url(encoded, 'RELEASE_REQUEST_BASE64').toString('utf8'),
  );
  const verified = validateReleaseRequest(request, {
    expectedOperation: 'canary',
  });
  const receipt = {
    artifactCiphertextSha256: verified.request.artifact.ciphertextSha256,
    artifactPlaintextSha256: verified.request.artifact.plaintextSha256,
    controllerCommitSha: verified.request.controller.commitSha,
    requestDigest: verified.digest,
    requestId: verified.request.requestId,
    result: 'verified-no-provider-mutation',
    schema: 'deployment-control/canary-receipt/v1',
    sourceCommitSha: verified.request.source.commitSha,
  };
  const digest = sha256(Buffer.from(canonicalJson(receipt)));
  await appendFile(
    required('GITHUB_OUTPUT'),
    `receipt_sha256=${digest}\n`,
    'utf8',
  );
  process.stdout.write('Canary verification receipt prepared.\n');
}

main().catch((error) => {
  console.error(`Canary receipt stopped: ${error.message}`);
  process.exitCode = 1;
});
