#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

const shaPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9-]{36}$/;

function required(name, pattern) {
  const value = process.env[name]?.trim();
  if (!value || (pattern && !pattern.test(value))) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

async function github(path, options = {}) {
  const response = await fetch(`${required('GITHUB_API_URL')}${path}`, {
    ...options,
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${required('GITHUB_TOKEN')}`,
      'content-type': 'application/json',
      'user-agent': 'deployment-control-packager',
      'x-github-api-version': '2022-11-28',
      ...options.headers,
    },
  });
  if (!response.ok) {
    throw new Error(`GitHub transport API ${path} returned ${response.status}`);
  }
  return response.status === 204 ? null : response.json();
}

async function createBlob(repository, path) {
  const bytes = await readFile(resolve(path));
  const blob = await github(`/repos/${repository}/git/blobs`, {
    method: 'POST',
    body: JSON.stringify({ content: bytes.toString('base64'), encoding: 'base64' }),
  });
  if (!shaPattern.test(blob.sha ?? '')) throw new Error('Git blob identity is invalid');
  return { name: basename(path), sha: blob.sha };
}

async function main() {
  const [ciphertextPath, manifestPath] = process.argv.slice(2);
  if (!ciphertextPath || !manifestPath) throw new Error('ciphertext and manifest paths are required');
  if (basename(ciphertextPath) !== 'release.gpg' || basename(manifestPath) !== 'manifest.json') {
    throw new Error('transport tree filenames are fixed');
  }
  const repository = required(
    'GITHUB_REPOSITORY',
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  );
  const repositoryMetadata = await github(`/repos/${repository}`);
  if (
    String(repositoryMetadata.id) !== required('GITHUB_REPOSITORY_ID', /^\d+$/) ||
    repositoryMetadata.private !== true
  ) {
    throw new Error('transport repository identity or visibility differs');
  }
  const requestId = required('RELEASE_REQUEST_ID', uuidPattern);
  const tag = `deployment-control/${requestId}`;
  const [ciphertext, manifest] = await Promise.all([
    createBlob(repository, ciphertextPath),
    createBlob(repository, manifestPath),
  ]);
  const tree = await github(`/repos/${repository}/git/trees`, {
    method: 'POST',
    body: JSON.stringify({
      tree: [
        { mode: '100644', path: 'manifest.json', sha: manifest.sha, type: 'blob' },
        { mode: '100644', path: 'release.gpg', sha: ciphertext.sha, type: 'blob' },
      ],
    }),
  });
  if (!shaPattern.test(tree.sha ?? '')) throw new Error('Git tree identity is invalid');
  const commit = await github(`/repos/${repository}/git/commits`, {
    method: 'POST',
    body: JSON.stringify({
      message: `Deployment-control transport ${requestId}`,
      parents: [],
      tree: tree.sha,
    }),
  });
  if (!shaPattern.test(commit.sha ?? '')) throw new Error('Orphan commit identity is invalid');
  await github(`/repos/${repository}/git/refs`, {
    method: 'POST',
    body: JSON.stringify({ ref: `refs/tags/${tag}`, sha: commit.sha }),
  });
  const release = await github(`/repos/${repository}/releases`, {
    method: 'POST',
    body: JSON.stringify({
      draft: false,
      generate_release_notes: false,
      name: `Encrypted deployment transport ${requestId}`,
      prerelease: true,
      tag_name: tag,
      target_commitish: commit.sha,
    }),
  });
  const confirmed = await github(`/repos/${repository}/releases/${release.id}`);
  if (
    confirmed.immutable !== true ||
    confirmed.draft !== false ||
    confirmed.tag_name !== tag ||
    !Number.isSafeInteger(confirmed.id)
  ) {
    throw new Error('GitHub immutable Release confirmation failed');
  }
  process.stdout.write(
    `${JSON.stringify({
      ciphertextBlobSha1: ciphertext.sha,
      immutableRelease: true,
      manifestBlobSha1: manifest.sha,
      releaseId: String(confirmed.id),
      transportCommitSha: commit.sha,
      transportTag: tag,
    })}\n`,
  );
}

main().catch((error) => {
  console.error(`Private immutable transport publication stopped: ${error.message}`);
  process.exitCode = 1;
});
