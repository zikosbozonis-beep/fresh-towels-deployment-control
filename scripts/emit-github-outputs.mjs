#!/usr/bin/env node

import { appendFile, readFile } from 'node:fs/promises';

const safePatterns = {
  artifactCiphertextSha256: /^[a-f0-9]{64}$/,
  artifactReleaseId: /^[1-9][0-9]{0,19}$/,
  artifactTransportTag: /^deployment-control\/[a-f0-9-]{36}$/,
  artifactTransportCommitSha: /^[a-f0-9]{40}$/,
  artifactCiphertextBlobSha1: /^[a-f0-9]{40}$/,
  artifactManifestBlobSha1: /^[a-f0-9]{40}$/,
  artifactPlaintextBytes: /^\d{1,10}$/,
  artifactPlaintextSha256: /^[a-f0-9]{64}$/,
  controllerCommitSha: /^[a-f0-9]{40}$/,
  evidenceManifestSha256: /^[a-f0-9]{64}$/,
  evidenceOidcTokenSha256: /^[a-f0-9]{64}$/,
  operation: /^(canary|production-release)$/,
  requestDigest: /^[a-f0-9]{64}$/,
  requestId: /^[a-f0-9-]{36}$/,
  sourceCommitSha: /^[a-f0-9]{40}$/,
  sourceRepositoryId: /^[1-9][0-9]{0,19}$/,
  sourceWorkflowRunId: /^[1-9][0-9]{0,19}$/,
};

async function main() {
  const [inputPath, outputPath] = process.argv.slice(2);
  if (!inputPath || !outputPath) throw new Error('input and GitHub output paths are required');
  const value = JSON.parse(await readFile(inputPath, 'utf8'));
  const lines = [];
  for (const [name, pattern] of Object.entries(safePatterns)) {
    const item = String(value[name] ?? '');
    if (!pattern.test(item)) throw new Error(`unsafe GitHub output ${name}`);
    lines.push(`${name}=${item}`);
  }
  await appendFile(outputPath, `${lines.join('\n')}\n`, 'utf8');
}

main().catch((error) => {
  console.error(`GitHub output emission stopped: ${error.message}`);
  process.exitCode = 1;
});
