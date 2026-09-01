#!/usr/bin/env node

import { appendFile, readFile } from 'node:fs/promises';
import { validateReleaseRequest } from './control-contract.mjs';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main() {
  const [transportPath, manifestPath] = process.argv.slice(2);
  if (!transportPath || !manifestPath) throw new Error('transport and manifest paths are required');
  const transport = JSON.parse(await readFile(transportPath, 'utf8'));
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const now = new Date();
  const request = {
    artifact: {
      ciphertextBlobSha1: transport.ciphertextBlobSha1,
      ciphertextSha256: required('CIPHERTEXT_SHA256'),
      encryptionKeySha256: required('ENCRYPTION_KEY_SHA256'),
      manifestBlobSha1: transport.manifestBlobSha1,
      plaintextBytes: manifest.payload.bytes,
      plaintextSha256: manifest.payload.sha256,
      releaseId: transport.releaseId,
      transportCommitSha: transport.transportCommitSha,
      transportTag: transport.transportTag,
    },
    controller: manifest.controller,
    evidence: {
      immutableRelease: transport.immutableRelease === true,
      manifestSha256: required('MANIFEST_SHA256'),
      oidcTokenSha256: manifest.evidence.oidcTokenSha256,
    },
    expiresAt: new Date(now.getTime() + 30 * 60 * 1000).toISOString(),
    issuedAt: now.toISOString(),
    nonce: manifest.nonce,
    operation: 'production-release',
    requestId: manifest.requestId,
    schema: 'deployment-control/release-request/v1',
    source: manifest.source,
  };
  const verified = validateReleaseRequest(request, {
    expectedControllerRepositoryId: manifest.controller.repositoryId,
    expectedControllerSha: manifest.controller.commitSha,
    expectedSourceRepositoryId: manifest.source.repositoryId,
    now,
  });
  const encoded = Buffer.from(verified.canonical).toString('base64url');
  const output = process.env.GITHUB_OUTPUT?.trim();
  if (output) {
    await appendFile(output, `release_request_base64=${encoded}\nrequest_digest=${verified.digest}\n`, 'utf8');
  }
  process.stdout.write(`${encoded}\n`);
}

main().catch((error) => {
  console.error(`Release request creation stopped: ${error.message}`);
  process.exitCode = 1;
});
