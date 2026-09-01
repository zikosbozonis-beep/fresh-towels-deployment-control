#!/usr/bin/env node

import { lstat, readFile, readdir } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';

const forbiddenBasenames = new Set([
  '.env',
  '.npmrc',
  '.pypirc',
  'credentials',
  'credentials.json',
  'id_rsa',
  'id_ed25519',
]);
const forbiddenExtensions = new Set([
  '.7z',
  '.age',
  '.bak',
  '.db',
  '.dump',
  '.gpg',
  '.gz',
  '.key',
  '.p12',
  '.pem',
  '.pfx',
  '.sqlite',
  '.sqlite3',
  '.sql',
  '.tar',
  '.tgz',
  '.zip',
]);
const ignoredDirectories = new Set(['.git', 'node_modules', 'coverage']);
const maximumPublicFileBytes = 512 * 1024;

const credentialPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
  /\bgh[opsu]_[A-Za-z0-9_]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
  /\bre_[A-Za-z0-9_-]{24,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{30,}\b/,
  /(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'][^$<{][^"']{15,}["']/i,
];

function extensionOf(path) {
  const name = path.split('/').at(-1).toLowerCase();
  const dot = name.lastIndexOf('.');
  return dot < 0 ? '' : name.slice(dot);
}

async function recursivelyList(root, current = root) {
  const result = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    if (ignoredDirectories.has(entry.name)) continue;
    const path = resolve(current, entry.name);
    if (entry.isDirectory()) result.push(...(await recursivelyList(root, path)));
    else result.push(path);
  }
  return result;
}

async function publicFiles(root) {
  const discovered = await recursivelyList(root);
  const tracked = spawnSync('git', ['-C', root, 'ls-files', '-z'], {
    encoding: 'utf8',
    windowsHide: true,
  });
  if (tracked.status !== 0) return discovered;
  const trackedPaths = tracked.stdout
    .split('\0')
    .filter(Boolean)
    .map((path) => resolve(root, path));
  return [...new Set([...discovered, ...trackedPaths])];
}

function pathIsAllowlisted(path) {
  const rootFiles = new Set([
    '.gitattributes',
    '.gitignore',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'controller-identity.json',
    'package.json',
  ]);
  if (rootFiles.has(path)) return true;
  return /^(?:dispatcher\/(?:[A-Za-z0-9_.-]+\.(?:mjs|jsonc)|migrations\/[0-9]{4}_[A-Za-z0-9_.-]+\.sql)|docs\/[A-Za-z0-9_.-]+\.md|schemas\/[A-Za-z0-9_.-]+\.json|scripts\/[A-Za-z0-9_.-]+\.mjs|tests\/[A-Za-z0-9_.-]+\.test\.mjs|\.github\/workflows\/[A-Za-z0-9_.-]+\.yml|keys\/(?:README\.md|github-known-hosts|release-encryption-public\.asc|release-encryption-(?:subkey-)?fingerprint\.txt))$/.test(
    path,
  );
}

export async function scanPublicSurface(rootPath) {
  const root = resolve(rootPath);
  const findings = [];
  for (const path of await publicFiles(root)) {
    const name = path.split(/[\\/]/).at(-1);
    const normalized = relative(root, path).split(sep).join('/');
    if (!pathIsAllowlisted(normalized)) {
      findings.push(`${normalized}: path is outside the public allowlist`);
      continue;
    }
    const stat = await lstat(path);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
      findings.push(`${normalized}: public entries must be regular, unlinked files`);
      continue;
    }
    if (stat.size > maximumPublicFileBytes) {
      findings.push(`${normalized}: exceeds the public file-size limit`);
      continue;
    }
    if (
      forbiddenBasenames.has(name.toLowerCase()) ||
      (forbiddenExtensions.has(extensionOf(normalized)) &&
        !/^dispatcher\/migrations\/[0-9]{4}_[A-Za-z0-9_.-]+\.sql$/.test(normalized)) ||
      /(^|\/)\.env(?:\.|$)/i.test(normalized)
    ) {
      findings.push(`${normalized}: forbidden public file type or name`);
      continue;
    }
    const bytes = await readFile(path);
    if (bytes.includes(0)) {
      findings.push(`${normalized}: binary content is not allowed`);
      continue;
    }
    const text = bytes.toString('utf8');
    for (const pattern of credentialPatterns) {
      if (pattern.test(text)) {
        findings.push(`${normalized}: resembles credential or private-key material`);
        break;
      }
    }
    if (/\b(?:name|phone|email|message|company)\b\s*:\s*["'][^"']+["']/i.test(text) &&
        /lead|customer|submission/i.test(normalized)) {
      findings.push(`${normalized}: resembles customer or lead data`);
    }
  }
  if (findings.length > 0) {
    throw new Error(`PUBLIC_BOUNDARY_VIOLATION\n${findings.join('\n')}`);
  }
  return Object.freeze({ files: (await publicFiles(root)).length, root });
}

async function main() {
  const root = process.argv[2] ?? '.';
  const result = await scanPublicSurface(root);
  process.stdout.write(`Public boundary passed for ${result.files} files.\n`);
}

if (process.argv[1]?.endsWith('public-boundary-scan.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
