import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJson, sha256 } from '../scripts/control-contract.mjs';
import { parseFixedEnvelope, validateManifest, validateTransportTree } from '../scripts/protected-transport.mjs';

function tarOctal(value, width) {
  return `${value.toString(8).padStart(width - 1, '0')}\0`;
}

function tar(entries) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data);
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    header.write(tarOctal(entry.mode ?? 0o400, 8), 100, 8, 'ascii');
    header.write(tarOctal(0, 8), 108, 8, 'ascii');
    header.write(tarOctal(0, 8), 116, 8, 'ascii');
    header.write(tarOctal(data.length, 12), 124, 12, 'ascii');
    header.write(tarOctal(0, 12), 136, 12, 'ascii');
    header.fill(32, 148, 156);
    header[156] = (entry.type ?? '0').charCodeAt(0);
    header.write('ustar\0', 257, 6, 'binary');
    header.write('00', 263, 2, 'ascii');
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    chunks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function request(manifestBytes) {
  return {
    artifact: {
      ciphertextBlobSha1: '4'.repeat(40), ciphertextSha256: 'c'.repeat(64),
      encryptionKeySha256: 'd'.repeat(64), manifestBlobSha1: '5'.repeat(40),
      plaintextBytes: 7, plaintextSha256: sha256(Buffer.from('payload')),
      releaseId: '6006', transportCommitSha: '3'.repeat(40),
      transportTag: 'deployment-control/11111111-1111-4111-8111-111111111111',
    },
    controller: { commitSha: '2'.repeat(40), repositoryId: '2002' },
    evidence: { immutableRelease: true, manifestSha256: sha256(manifestBytes), oidcTokenSha256: 'f'.repeat(64) },
    expiresAt: '2026-09-01T10:15:00.000Z', issuedAt: '2026-09-01T10:00:00.000Z',
    nonce: 'A'.repeat(43), operation: 'production-release',
    requestId: '11111111-1111-4111-8111-111111111111',
    schema: 'deployment-control/release-request/v1',
    source: { commitSha: '1'.repeat(40), repositoryId: '1001', workflowRunAttempt: 1, workflowRunId: '3003' },
  };
}

function manifest() {
  return {
    controller: { commitSha: '2'.repeat(40), repositoryId: '2002' },
    evidence: { oidcTokenSha256: 'f'.repeat(64) }, nonce: 'A'.repeat(43),
    payload: { bytes: 7, sha256: sha256(Buffer.from('payload')) },
    requestId: '11111111-1111-4111-8111-111111111111',
    schema: 'deployment-control/private-transport-manifest/v1',
    source: { commitSha: '1'.repeat(40), repositoryId: '1001', workflowRunAttempt: 1, workflowRunId: '3003' },
  };
}

test('transport tree permits only two exact regular non-executable blobs', () => {
  const value = request(Buffer.from('x'));
  const valid = [
    { mode: '100644', name: 'manifest.json', sha: '5'.repeat(40), type: 'blob' },
    { mode: '100644', name: 'release.gpg', sha: '4'.repeat(40), type: 'blob' },
  ];
  assert.equal(validateTransportTree(valid, value), true);
  for (const changed of [
    [...valid, { mode: '100644', name: 'extra', sha: '6'.repeat(40), type: 'blob' }],
    [{ ...valid[0], mode: '120000' }, valid[1]],
    [{ ...valid[0], mode: '160000', type: 'commit' }, valid[1]],
    [{ ...valid[0], sha: '9'.repeat(40) }, valid[1]],
  ]) assert.throws(() => validateTransportTree(changed, value), /tree/);
});

test('fixed envelope rejects traversal, links, executable entries, extras and trailing data', () => {
  const good = tar([{ data: `${canonicalJson(manifest())}\n`, name: 'manifest.json' }, { data: 'payload', name: 'payload.bin' }]);
  const files = parseFixedEnvelope(good);
  assert.equal(Buffer.from(files.get('payload.bin')).toString(), 'payload');
  for (const changed of [
    tar([{ data: 'x', name: '../manifest.json' }, { data: 'payload', name: 'payload.bin' }]),
    tar([{ data: 'x', name: 'manifest.json', type: '2' }, { data: 'payload', name: 'payload.bin' }]),
    tar([{ data: 'x', mode: 0o700, name: 'manifest.json' }, { data: 'payload', name: 'payload.bin' }]),
    tar([{ data: 'x', name: 'manifest.json' }, { data: 'payload', name: 'payload.bin' }, { data: 'x', name: 'extra' }]),
    Buffer.concat([good, Buffer.from('nonzero')]),
  ]) assert.throws(() => parseFixedEnvelope(changed), /Tar|envelope/);
});

test('canonical encrypted manifest must match every approved identity and digest', () => {
  const bytes = Buffer.from(`${canonicalJson(manifest())}\n`);
  const value = request(bytes);
  assert.equal(validateManifest(bytes, value).requestId, value.requestId);
  const changed = structuredClone(manifest());
  changed.source.commitSha = '9'.repeat(40);
  assert.throws(() => validateManifest(Buffer.from(`${canonicalJson(changed)}\n`), value), /differs|digest/);
});
