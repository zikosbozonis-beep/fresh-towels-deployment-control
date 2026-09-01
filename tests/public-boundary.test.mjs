import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { scanPublicSurface } from '../scripts/public-boundary-scan.mjs';

test('accepts generic public source and metadata', async () => {
  const root = await mkdtemp(join(tmpdir(), 'public-surface-safe-'));
  try {
    await mkdir(join(root, 'scripts'));
    await writeFile(join(root, 'README.md'), '# Generic controller\n');
    await writeFile(join(root, 'scripts', 'check.mjs'), 'export const digest = "a";\n');
    const result = await scanPublicSurface(root);
    assert.equal(result.files, 2);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('rejects credentials, databases, archives and private keys', async () => {
  for (const [filename, content] of [
    ['release.zip', 'bytes'],
    ['leads.sqlite', 'bytes'],
    ['credential.txt', ['github', 'pat', 'A'.repeat(40)].join('_')],
    [
      'private.txt',
      ['-----BEGIN', 'PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE', 'KEY-----'].join(' '),
    ],
  ]) {
    const root = await mkdtemp(join(tmpdir(), 'public-surface-attack-'));
    try {
      await writeFile(join(root, filename), content);
      await assert.rejects(scanPublicSurface(root), /PUBLIC_BOUNDARY_VIOLATION/);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  }
});
