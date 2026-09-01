import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateApprovalHistory,
  validateDispatchContext,
  validateReleaseRequest,
} from '../scripts/control-contract.mjs';
import { verifyArtifactFile } from '../scripts/verify-artifact.mjs';

const now = new Date('2026-09-01T10:00:00.000Z');

function request(overrides = {}) {
  const base = {
    artifact: {
      ciphertextBlobSha1: '4'.repeat(40),
      ciphertextSha256: 'c'.repeat(64),
      encryptionKeySha256: 'd'.repeat(64),
      manifestBlobSha1: '5'.repeat(40),
      plaintextBytes: 42,
      plaintextSha256: 'b'.repeat(64),
      releaseId: '6006',
      transportCommitSha: '3'.repeat(40),
      transportTag: 'deployment-control/11111111-1111-4111-8111-111111111111',
    },
    controller: {
      commitSha: '2'.repeat(40),
      repositoryId: '2002',
    },
    evidence: {
      immutableRelease: true,
      manifestSha256: 'e'.repeat(64),
      oidcTokenSha256: 'f'.repeat(64),
    },
    expiresAt: '2026-09-01T10:15:00.000Z',
    issuedAt: '2026-09-01T10:00:00.000Z',
    nonce: 'A'.repeat(43),
    operation: 'production-release',
    requestId: '11111111-1111-4111-8111-111111111111',
    schema: 'deployment-control/release-request/v1',
    source: {
      commitSha: '1'.repeat(40),
      repositoryId: '1001',
      workflowRunAttempt: 1,
      workflowRunId: '3003',
    },
  };
  return { ...base, ...overrides };
}

const expected = {
  expectedControllerRepositoryId: '2002',
  expectedControllerSha: '2'.repeat(40),
  expectedSourceRepositoryId: '1001',
  now,
};

test('accepts one canonical, short-lived exact-SHA request', () => {
  const value = request();
  const result = validateReleaseRequest(value, expected);
  assert.equal(result.digest, sha256(Buffer.from(canonicalJson(value))));
  assert.equal(result.request.source.commitSha, '1'.repeat(40));
});

test('rejects alternate base64url pad-bit spellings of identical bytes', () => {
  assert.deepEqual(decodeCanonicalBase64Url('_w'), Buffer.from([0xff]));
  assert.deepEqual(Buffer.from('_x', 'base64url'), Buffer.from([0xff]));
  assert.throws(() => decodeCanonicalBase64Url('_x'), /not canonical/);
});

test('rejects mutable refs, altered repository identity and unknown fields', () => {
  const mutable = request();
  mutable.source.commitSha = 'main';
  assert.throws(() => validateReleaseRequest(mutable, expected), /commitSha/);

  const wrongRepository = request();
  wrongRepository.source.repositoryId = '9999';
  assert.throws(
    () => validateReleaseRequest(wrongRepository, expected),
    /trusted context/,
  );

  const injected = request();
  injected.command = 'arbitrary';
  assert.throws(() => validateReleaseRequest(injected, expected), /unexpected/);
});

test('rejects stale, future and overlong evidence windows', () => {
  assert.throws(
    () =>
      validateReleaseRequest(request(), {
        ...expected,
        now: new Date('2026-09-01T10:15:00.000Z'),
      }),
    /stale/,
  );
  assert.throws(
    () =>
      validateReleaseRequest(
        request({
          issuedAt: '2026-09-01T10:02:00.000Z',
          expiresAt: '2026-09-01T10:17:00.000Z',
        }),
        expected,
      ),
    /not yet valid/,
  );
  assert.throws(
    () =>
      validateReleaseRequest(
        request({ expiresAt: '2026-09-01T10:31:00.000Z' }),
        expected,
      ),
    /validity window/,
  );
});

test('rejects unauthorized initiators, unprotected refs and controller drift', () => {
  const context = {
    actorId: '44',
    checkedOutSha: '2'.repeat(40),
    controllerSha: '2'.repeat(40),
    eventName: 'workflow_dispatch',
    expectedRequesterActorId: '44',
    ref: 'refs/heads/main',
    refProtected: 'true',
    senderType: 'Bot',
  };
  assert.equal(validateDispatchContext(context), true);
  assert.throws(
    () => validateDispatchContext({ ...context, actorId: '45' }),
    /configured GitHub App/,
  );
  assert.throws(
    () => validateDispatchContext({ ...context, refProtected: 'false' }),
    /refProtected/,
  );
  assert.throws(
    () => validateDispatchContext({ ...context, checkedOutSha: '3'.repeat(40) }),
    /drifted/,
  );
});

test('requires one independent owner approval and rejects self-review', () => {
  const history = [
    {
      environments: [{ name: 'production' }],
      state: 'approved',
      user: { id: 99 },
    },
  ];
  assert.deepEqual(
    validateApprovalHistory(history, {
      environmentName: 'production',
      expectedReviewerActorId: '99',
      requesterActorId: '44',
    }),
    { reviewerActorId: '99', state: 'approved' },
  );
  assert.throws(
    () =>
      validateApprovalHistory(history, {
        environmentName: 'production',
        expectedReviewerActorId: '99',
        requesterActorId: '99',
      }),
    /distinct/,
  );
  assert.throws(
    () =>
      validateApprovalHistory([], {
        environmentName: 'production',
        expectedReviewerActorId: '99',
        requesterActorId: '44',
      }),
    /approval/,
  );
});

test('detects artifact substitution after approval', async () => {
  const root = await mkdtemp(join(tmpdir(), 'control-artifact-'));
  const path = join(root, 'release.age');
  try {
    const original = Buffer.from('synthetic encrypted artifact');
    await writeFile(path, original, { flag: 'wx', mode: 0o400 });
    await verifyArtifactFile({
      expectedBytes: original.length,
      expectedSha256: sha256(original),
      path,
    });
    await chmod(path, 0o600);
    await writeFile(path, Buffer.from('substituted encrypted artifact'));
    await assert.rejects(
      verifyArtifactFile({
        expectedBytes: original.length,
        expectedSha256: sha256(original),
        path,
      }),
      /changed/,
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test('schema and validator field sets remain aligned', async () => {
  const schema = JSON.parse(
    await readFile(new URL('../schemas/release-request-v1.schema.json', import.meta.url)),
  );
  assert.deepEqual([...schema.required].sort(), Object.keys(request()).sort());
});
