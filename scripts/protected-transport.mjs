#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateReleaseRequest,
} from './control-contract.mjs';

const maximumEnvelopeBytes = 128 * 1024 * 1024;
const shaPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;

function required(environment, name, pattern) {
  const value = environment[name]?.trim();
  if (!value || (pattern && !pattern.test(value))) {
    throw new Error(`${name} is unavailable or invalid`);
  }
  return value;
}

function runGit(repository, arguments_, options = {}) {
  const result = spawnSync('git', ['-C', repository, ...arguments_], {
    encoding: options.encoding ?? 'utf8',
    env: options.environment,
    maxBuffer: maximumEnvelopeBytes + 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`Git plumbing rejected ${arguments_[0]}`);
  }
  return result.stdout;
}

export function parseTree(raw) {
  return raw
    .split('\0')
    .filter(Boolean)
    .map((entry) => {
      const match = /^(\d{6}) (\w+) ([a-f0-9]{40})\t([^\0]+)$/.exec(entry);
      if (!match) throw new Error('Transport tree entry is malformed');
      return { mode: match[1], type: match[2], sha: match[3], name: match[4] };
    });
}

export function validateTransportTree(entries, request) {
  const expected = new Map([
    ['manifest.json', request.artifact.manifestBlobSha1],
    ['release.gpg', request.artifact.ciphertextBlobSha1],
  ]);
  if (!Array.isArray(entries) || entries.length !== 2) {
    throw new Error('Transport tree must contain exactly two entries');
  }
  for (const entry of entries) {
    if (
      entry.mode !== '100644' ||
      entry.type !== 'blob' ||
      !expected.has(entry.name) ||
      expected.get(entry.name) !== entry.sha
    ) {
      throw new Error('Transport tree contains an unexpected entry');
    }
    expected.delete(entry.name);
  }
  if (expected.size !== 0) throw new Error('Transport tree is incomplete');
  return true;
}

function octal(bytes, offset, length, label) {
  const text = new TextDecoder()
    .decode(bytes.subarray(offset, offset + length))
    .replaceAll('\0', '')
    .trim();
  if (!/^[0-7]+$/.test(text)) throw new Error(`Tar ${label} is invalid`);
  return Number.parseInt(text, 8);
}

function tarString(bytes, offset, length) {
  const field = bytes.subarray(offset, offset + length);
  const end = field.indexOf(0);
  return new TextDecoder().decode(end < 0 ? field : field.subarray(0, end));
}

export function parseFixedEnvelope(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 2048 || bytes.length > maximumEnvelopeBytes) {
    throw new Error('Envelope size is invalid');
  }
  const files = new Map();
  let offset = 0;
  let zeroBlocks = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += 512;
      if (zeroBlocks === 2) break;
      continue;
    }
    if (zeroBlocks > 0) throw new Error('Tar data follows a zero block');
    const storedChecksum = octal(header, 148, 8, 'checksum');
    let computedChecksum = 0;
    for (let index = 0; index < 512; index += 1) {
      computedChecksum += index >= 148 && index < 156 ? 32 : header[index];
    }
    if (storedChecksum !== computedChecksum) throw new Error('Tar checksum changed');
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const linkName = tarString(header, 157, 100);
    const type = header[156];
    const mode = octal(header, 100, 8, 'mode');
    const size = octal(header, 124, 12, 'size');
    if (
      prefix ||
      linkName ||
      (type !== 0 && type !== 48) ||
      (mode & 0o111) !== 0 ||
      !['manifest.json', 'payload.bin'].includes(name) ||
      files.has(name) ||
      size < 1 ||
      size > maximumEnvelopeBytes
    ) {
      throw new Error('Tar entry is outside the fixed allowlist');
    }
    offset += 512;
    if (offset + size > bytes.length) throw new Error('Tar entry is truncated');
    files.set(name, bytes.slice(offset, offset + size));
    offset += Math.ceil(size / 512) * 512;
  }
  if (zeroBlocks !== 2 || files.size !== 2) {
    throw new Error('Tar envelope is incomplete');
  }
  if (bytes.subarray(offset).some((byte) => byte !== 0)) {
    throw new Error('Tar envelope has trailing data');
  }
  return files;
}

export function validateManifest(manifestBytes, request) {
  const text = new TextDecoder().decode(manifestBytes);
  const manifest = JSON.parse(text);
  if (`${canonicalJson(manifest)}\n` !== text) {
    throw new Error('Transport manifest is not canonical');
  }
  const expected = {
    controller: request.controller,
    evidence: { oidcTokenSha256: request.evidence.oidcTokenSha256 },
    nonce: request.nonce,
    payload: {
      bytes: request.artifact.plaintextBytes,
      sha256: request.artifact.plaintextSha256,
    },
    requestId: request.requestId,
    schema: 'deployment-control/private-transport-manifest/v1',
    source: request.source,
  };
  if (canonicalJson(manifest) !== canonicalJson(expected)) {
    throw new Error('Transport manifest differs from approved request');
  }
  if (sha256(manifestBytes) !== request.evidence.manifestSha256) {
    throw new Error('Transport manifest digest changed');
  }
  return manifest;
}

async function fetchTransport(request, environment, root) {
  const repository = join(root, 'transport.git');
  await mkdir(repository, { mode: 0o700 });
  const deployKey = join(root, 'deploy-key');
  const sshWrapper = join(root, 'ssh-wrapper');
  await writeFile(deployKey, required(environment, 'PRIVATE_TRANSPORT_DEPLOY_KEY'), {
    flag: 'wx',
    mode: 0o600,
  });
  const knownHosts = fileURLToPath(new URL('../keys/github-known-hosts', import.meta.url));
  const wrapper = `#!/bin/sh\nexec /usr/bin/ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${JSON.stringify(knownHosts)} -i ${JSON.stringify(deployKey)} "$@"\n`;
  await writeFile(sshWrapper, wrapper, { flag: 'wx', mode: 0o700 });
  const gitEnvironment = {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_SSH: sshWrapper,
    HOME: root,
    PATH: process.env.PATH,
  };
  runGit(repository, ['init', '--bare'], { environment: gitEnvironment });
  runGit(
    repository,
    [
      'fetch',
      '--depth=1',
      '--no-tags',
      required(
        environment,
        'PRIVATE_TRANSPORT_GIT_URL',
        /^git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/,
      ),
      `refs/tags/${request.artifact.transportTag}:refs/tags/release`,
    ],
    { environment: gitEnvironment },
  );
  await chmod(deployKey, 0o600);
  await writeFile(deployKey, '', { mode: 0o600 });
  const commit = runGit(repository, ['rev-parse', 'refs/tags/release']).trim();
  if (commit !== request.artifact.transportCommitSha) {
    throw new Error('Transport tag resolves to a different commit');
  }
  if (runGit(repository, ['cat-file', '-t', 'refs/tags/release']).trim() !== 'commit') {
    throw new Error('Transport tag must directly reference one commit');
  }
  const ancestry = runGit(repository, ['rev-list', '--parents', '-n', '1', commit])
    .trim()
    .split(/\s+/);
  if (ancestry.length !== 1 || ancestry[0] !== commit) {
    throw new Error('Transport commit must be parentless');
  }
  const tree = parseTree(runGit(repository, ['ls-tree', '-z', commit]));
  validateTransportTree(tree, request);
  const manifestBytes = runGit(
    repository,
    ['cat-file', 'blob', `${commit}:manifest.json`],
    { encoding: 'buffer' },
  );
  const ciphertextBytes = runGit(
    repository,
    ['cat-file', 'blob', `${commit}:release.gpg`],
    { encoding: 'buffer' },
  );
  if (
    manifestBytes.subarray(0, 42).toString('utf8').includes('git-lfs.github.com') ||
    ciphertextBytes.subarray(0, 42).toString('utf8').includes('git-lfs.github.com')
  ) {
    throw new Error('Git LFS pointers are forbidden');
  }
  if (sha256(ciphertextBytes) !== request.artifact.ciphertextSha256) {
    throw new Error('Ciphertext digest changed');
  }
  validateManifest(manifestBytes, request);
  const ciphertextPath = join(root, 'release.gpg');
  await writeFile(ciphertextPath, ciphertextBytes, { flag: 'wx', mode: 0o400 });
  return { ciphertextPath, manifestBytes };
}

async function decrypt(ciphertextPath, environment, root) {
  const gpgHome = join(root, 'gpg');
  await mkdir(gpgHome, { mode: 0o700 });
  const privateKey = join(root, 'decryption-key.asc');
  const envelopePath = join(root, 'envelope.tar');
  const passphrase = environment.RELEASE_DECRYPTION_PASSPHRASE;
  if (
    typeof passphrase !== 'string' ||
    passphrase.length < 16 ||
    passphrase.length > 1024 ||
    /[\r\n\0]/.test(passphrase)
  ) {
    throw new Error('release decryption passphrase is unavailable or invalid');
  }
  await writeFile(privateKey, required(environment, 'RELEASE_DECRYPTION_PRIVATE_KEY'), {
    flag: 'wx',
    mode: 0o600,
  });
  const cleanEnvironment = {
    GNUPGHOME: gpgHome,
    HOME: root,
    PATH: process.env.PATH,
  };
  const importResult = spawnSync(
    'gpg',
    ['--batch', '--no-tty', '--homedir', gpgHome, '--import', privateKey],
    { encoding: 'utf8', env: cleanEnvironment, windowsHide: true },
  );
  await chmod(privateKey, 0o600);
  await writeFile(privateKey, '', { mode: 0o600 });
  if (importResult.status !== 0) throw new Error('Offline GPG key import failed');
  const decryptResult = spawnSync(
    'gpg',
    [
      '--batch',
      '--no-tty',
      '--homedir',
      gpgHome,
      '--no-auto-key-retrieve',
      '--auto-key-locate',
      'clear',
      '--pinentry-mode',
      'loopback',
      '--passphrase-fd',
      '0',
      '--output',
      envelopePath,
      '--decrypt',
      ciphertextPath,
    ],
    {
      encoding: 'utf8',
      env: cleanEnvironment,
      input: `${passphrase}\n`,
      windowsHide: true,
    },
  );
  if (decryptResult.status !== 0) throw new Error('Offline GPG decryption failed');
  return envelopePath;
}

export async function verifyProtectedTransport(environment = process.env) {
  const encoded = required(environment, 'RELEASE_REQUEST_BASE64', /^[A-Za-z0-9_-]{100,32768}$/);
  const request = JSON.parse(
    decodeCanonicalBase64Url(encoded, 'RELEASE_REQUEST_BASE64').toString('utf8'),
  );
  validateReleaseRequest(request, {
    expectedControllerRepositoryId: required(
      environment,
      'EXPECTED_CONTROLLER_REPOSITORY_ID',
      decimalPattern,
    ),
    expectedControllerSha: required(environment, 'GITHUB_SHA', shaPattern),
    expectedSourceRepositoryId: required(
      environment,
      'EXPECTED_SOURCE_REPOSITORY_ID',
      decimalPattern,
    ),
  });
  const root = await mkdtemp(join(tmpdir(), 'deployment-control-transport-'));
  try {
    const encryptionPublicKey = await readFile(
      fileURLToPath(new URL('../keys/release-encryption-public.asc', import.meta.url)),
    );
    if (sha256(encryptionPublicKey) !== request.artifact.encryptionKeySha256) {
      throw new Error('Pinned encryption public key digest differs');
    }
    const transport = await fetchTransport(request, environment, root);
    const envelopePath = await decrypt(transport.ciphertextPath, environment, root);
    const files = parseFixedEnvelope(await readFile(envelopePath));
    const manifest = files.get('manifest.json');
    if (!manifest || !Buffer.from(manifest).equals(transport.manifestBytes)) {
      throw new Error('Encrypted and transport manifests differ');
    }
    validateManifest(manifest, request);
    const payload = files.get('payload.bin');
    if (!payload) throw new Error('Envelope payload is incomplete');
    if (
      payload.length !== request.artifact.plaintextBytes ||
      sha256(payload) !== request.artifact.plaintextSha256
    ) {
      throw new Error('Plaintext capsule digest changed');
    }
    const outputDirectory = resolve(
      required(environment, 'VERIFIED_PAYLOAD_OUTPUT_DIRECTORY'),
    );
    await mkdir(outputDirectory, { recursive: false, mode: 0o700 });
    const output = join(outputDirectory, 'release-capsule.bin');
    await writeFile(output, payload, { flag: 'wx', mode: 0o400 });
    return Object.freeze({ output, request });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

if (process.argv[1]?.endsWith('protected-transport.mjs')) {
  verifyProtectedTransport().then(
    () => process.stdout.write('Protected transport verified.\n'),
    (error) => {
      console.error(`Protected transport rejected: ${error.message}`);
      process.exitCode = 1;
    },
  );
}
