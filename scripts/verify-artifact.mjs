#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat } from 'node:fs/promises';
import { resolve } from 'node:path';

const digestPattern = /^[a-f0-9]{64}$/;

async function fileSha256(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

export async function verifyArtifactFile({ expectedBytes, expectedSha256, path }) {
  if (!digestPattern.test(expectedSha256 ?? '')) {
    throw new Error('expected artifact digest is invalid');
  }
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1) {
    throw new Error('expected artifact byte count is invalid');
  }
  const absolute = resolve(path);
  const stat = await lstat(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error('artifact must be one regular, unlinked file');
  }
  if (stat.size !== expectedBytes) throw new Error('artifact byte count changed');
  const digest = await fileSha256(absolute);
  if (digest !== expectedSha256) throw new Error('artifact digest changed');
  const finalStat = await lstat(absolute);
  if (
    finalStat.dev !== stat.dev ||
    finalStat.ino !== stat.ino ||
    finalStat.size !== stat.size ||
    finalStat.mtimeNs !== stat.mtimeNs
  ) {
    throw new Error('artifact identity changed during verification');
  }
  return Object.freeze({ bytes: stat.size, path: absolute, sha256: digest });
}

async function main() {
  const [path, expectedSha256, rawBytes] = process.argv.slice(2);
  const result = await verifyArtifactFile({
    expectedBytes: Number(rawBytes),
    expectedSha256,
    path,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1]?.endsWith('verify-artifact.mjs')) {
  main().catch((error) => {
    console.error(`Artifact rejected: ${error.message}`);
    process.exitCode = 1;
  });
}
