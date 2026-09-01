import { createHash } from 'node:crypto';

const sha256Pattern = /^[a-f0-9]{64}$/;
const sha1Pattern = /^[a-f0-9]{40}$/;
const decimalIdPattern = /^[1-9][0-9]{0,19}$/;
const uuidV4Pattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const noncePattern = /^[A-Za-z0-9_-]{43}$/;

const topKeys = [
  'schema',
  'requestId',
  'nonce',
  'issuedAt',
  'expiresAt',
  'operation',
  'source',
  'controller',
  'artifact',
  'evidence',
];
const sourceKeys = [
  'repositoryId',
  'commitSha',
  'workflowRunId',
  'workflowRunAttempt',
];
const controllerKeys = ['repositoryId', 'commitSha'];
const artifactKeys = [
  'releaseId',
  'transportTag',
  'transportCommitSha',
  'ciphertextBlobSha1',
  'manifestBlobSha1',
  'ciphertextSha256',
  'plaintextSha256',
  'plaintextBytes',
  'encryptionKeySha256',
];
const evidenceKeys = ['immutableRelease', 'manifestSha256', 'oidcTokenSha256'];

function assertPlainObject(value, label) {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label} must be a plain object`);
  }
}

function assertExactKeys(value, expected, label) {
  assertPlainObject(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} contains missing or unexpected fields`);
  }
}

function assertString(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new Error(`${label} is not exact`);
  }
}

function parseCanonicalInstant(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC instant`);
  }
  return timestamp;
}

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function validateReleaseRequest(request, options = {}) {
  assertExactKeys(request, topKeys, 'request');
  if (request.schema !== 'deployment-control/release-request/v1') {
    throw new Error('request schema is unsupported');
  }
  assertString(request.requestId, uuidV4Pattern, 'requestId');
  assertString(request.nonce, noncePattern, 'nonce');
  if (!['canary', 'production-release'].includes(request.operation)) {
    throw new Error('operation is not allowlisted');
  }

  assertExactKeys(request.source, sourceKeys, 'source');
  assertString(request.source.repositoryId, decimalIdPattern, 'source repositoryId');
  assertString(request.source.commitSha, sha1Pattern, 'source commitSha');
  assertString(request.source.workflowRunId, decimalIdPattern, 'source workflowRunId');
  if (
    !Number.isSafeInteger(request.source.workflowRunAttempt) ||
    request.source.workflowRunAttempt < 1 ||
    request.source.workflowRunAttempt > 100
  ) {
    throw new Error('source workflowRunAttempt is invalid');
  }

  assertExactKeys(request.controller, controllerKeys, 'controller');
  assertString(
    request.controller.repositoryId,
    decimalIdPattern,
    'controller repositoryId',
  );
  assertString(request.controller.commitSha, sha1Pattern, 'controller commitSha');

  assertExactKeys(request.artifact, artifactKeys, 'artifact');
  assertString(request.artifact.releaseId, decimalIdPattern, 'artifact releaseId');
  if (request.artifact.transportTag !== `deployment-control/${request.requestId}`) {
    throw new Error('artifact transportTag is not bound to requestId');
  }
  assertString(
    request.artifact.transportCommitSha,
    sha1Pattern,
    'artifact transportCommitSha',
  );
  assertString(
    request.artifact.ciphertextBlobSha1,
    sha1Pattern,
    'artifact ciphertextBlobSha1',
  );
  assertString(
    request.artifact.manifestBlobSha1,
    sha1Pattern,
    'artifact manifestBlobSha1',
  );
  if (request.artifact.ciphertextBlobSha1 === request.artifact.manifestBlobSha1) {
    throw new Error('transport blobs must be distinct');
  }
  assertString(
    request.artifact.ciphertextSha256,
    sha256Pattern,
    'artifact ciphertextSha256',
  );
  assertString(
    request.artifact.plaintextSha256,
    sha256Pattern,
    'artifact plaintextSha256',
  );
  assertString(
    request.artifact.encryptionKeySha256,
    sha256Pattern,
    'artifact encryptionKeySha256',
  );
  if (
    !Number.isSafeInteger(request.artifact.plaintextBytes) ||
    request.artifact.plaintextBytes < 1 ||
    request.artifact.plaintextBytes > 1_073_741_824
  ) {
    throw new Error('artifact plaintextBytes is invalid');
  }

  assertExactKeys(request.evidence, evidenceKeys, 'evidence');
  if (request.evidence.immutableRelease !== true) {
    throw new Error('immutable private Release evidence is required');
  }
  assertString(
    request.evidence.manifestSha256,
    sha256Pattern,
    'evidence manifestSha256',
  );
  assertString(
    request.evidence.oidcTokenSha256,
    sha256Pattern,
    'evidence oidcTokenSha256',
  );

  const issuedAt = parseCanonicalInstant(request.issuedAt, 'issuedAt');
  const expiresAt = parseCanonicalInstant(request.expiresAt, 'expiresAt');
  const now = options.now instanceof Date ? options.now.getTime() : Date.now();
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 30 * 60 * 1000) {
    throw new Error('request validity window is invalid');
  }
  if (issuedAt > now + 60_000 || now >= expiresAt) {
    throw new Error('request is stale or not yet valid');
  }

  const expected = [
    ['source repositoryId', request.source.repositoryId, options.expectedSourceRepositoryId],
    [
      'controller repositoryId',
      request.controller.repositoryId,
      options.expectedControllerRepositoryId,
    ],
    ['controller commitSha', request.controller.commitSha, options.expectedControllerSha],
    ['operation', request.operation, options.expectedOperation],
  ];
  for (const [label, actual, wanted] of expected) {
    if (wanted !== undefined && String(actual) !== String(wanted)) {
      throw new Error(`${label} differs from the trusted context`);
    }
  }

  const canonical = canonicalJson(request);
  return Object.freeze({
    canonical,
    digest: sha256(Buffer.from(canonical, 'utf8')),
    request: structuredClone(request),
  });
}

export function validateDispatchContext(context) {
  const required = {
    eventName: 'workflow_dispatch',
    senderType: 'Bot',
    ref: 'refs/heads/main',
    refProtected: 'true',
  };
  for (const [field, expected] of Object.entries(required)) {
    if (String(context[field] ?? '') !== expected) {
      throw new Error(`${field} must equal ${expected}`);
    }
  }
  assertString(String(context.actorId ?? ''), decimalIdPattern, 'actorId');
  assertString(
    String(context.expectedRequesterActorId ?? ''),
    decimalIdPattern,
    'expectedRequesterActorId',
  );
  if (String(context.actorId) !== String(context.expectedRequesterActorId)) {
    throw new Error('requester actor is not the configured GitHub App');
  }
  assertString(String(context.controllerSha ?? ''), sha1Pattern, 'controllerSha');
  assertString(String(context.checkedOutSha ?? ''), sha1Pattern, 'checkedOutSha');
  if (context.controllerSha !== context.checkedOutSha) {
    throw new Error('checked-out controller SHA drifted');
  }
  return true;
}

export function validateApprovalHistory(history, options) {
  if (!Array.isArray(history)) throw new Error('approval history must be an array');
  const requesterId = String(options.requesterActorId ?? '');
  const reviewerId = String(options.expectedReviewerActorId ?? '');
  assertString(requesterId, decimalIdPattern, 'requesterActorId');
  assertString(reviewerId, decimalIdPattern, 'expectedReviewerActorId');
  if (requesterId === reviewerId) {
    throw new Error('requester and reviewer identities must be distinct');
  }
  const approvals = history.filter(
    (entry) =>
      entry &&
      entry.state === 'approved' &&
      String(entry.user?.id ?? '') === reviewerId &&
      Array.isArray(entry.environments) &&
      entry.environments.some(
        (environment) => environment?.name === options.environmentName,
      ),
  );
  if (approvals.length !== 1) {
    throw new Error('one exact independent environment approval is required');
  }
  if (String(approvals[0].user.id) === requesterId) {
    throw new Error('self-review is forbidden');
  }
  return Object.freeze({ reviewerActorId: reviewerId, state: 'approved' });
}
