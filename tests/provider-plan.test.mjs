import assert from "node:assert/strict";
import test from "node:test";

import {
  createProviderOperationPlan,
  finalizeProviderOperation,
  validateProviderOperationPlan,
} from "../scripts/provider-plan.mjs";

function release() {
  return {
    requestId: "11111111-1111-4111-8111-111111111111",
    releaseId: "a".repeat(64),
    applicationCommitSha: "1".repeat(40),
    controllerCommitSha: "2".repeat(40),
    artifactSha256: "b".repeat(64),
    plaintextSha256: "c".repeat(64),
    uploadArtifactSha256: "d".repeat(64),
    evidenceSha256: "e".repeat(64),
  };
}

function operation(overrides = {}) {
  return {
    provider: "cloudflare",
    action: "cloudflare.account.verify",
    resource: {
      kind: "account",
      name: "fresh-towels-account",
      identitySha256: "f".repeat(64),
    },
    desiredStateSha256: "9".repeat(64),
    mutation: false,
    ...overrides,
  };
}

const now = new Date("2026-09-01T15:00:00.000Z");

test("builds a short-lived exact-release-bound typed provider plan", () => {
  const value = createProviderOperationPlan({
    environment: "canary",
    release: release(),
    operations: [
      operation(),
      operation({
        provider: "resend",
        action: "resend.domain.inspect",
        resource: {
          kind: "sending-domain",
          name: "freshtowels.gr",
          identitySha256: "8".repeat(64),
        },
        desiredStateSha256: "7".repeat(64),
      }),
    ],
    issuedAt: "2026-09-01T15:00:00.000Z",
    validUntil: "2026-09-01T15:15:00.000Z",
  });
  assert.equal(value.operations.length, 2);
  assert.match(value.operations[0].operationId, /^[a-f0-9]{64}$/);
  assert.match(value.operations[0].idempotencyKey, /^[a-f0-9]{64}$/);
  assert.equal(validateProviderOperationPlan(value, { expectedRelease: release(), now }), value);
});

test("operation identity and idempotency change with every release-critical field", () => {
  const baseRelease = release();
  const base = finalizeProviderOperation(baseRelease, { ...operation(), sequence: 1 });
  const mutations = [
    { ...baseRelease, releaseId: "0".repeat(64) },
    { ...baseRelease, applicationCommitSha: "3".repeat(40) },
    { ...baseRelease, controllerCommitSha: "4".repeat(40) },
  ];
  for (const changedRelease of mutations) {
    const changed = finalizeProviderOperation(changedRelease, { ...operation(), sequence: 1 });
    assert.notEqual(changed.operationId, base.operationId);
    assert.notEqual(changed.idempotencyKey, base.idempotencyKey);
  }
  const changedState = finalizeProviderOperation(baseRelease, {
    ...operation({ desiredStateSha256: "0".repeat(64) }),
    sequence: 1,
  });
  assert.notEqual(changedState.operationId, base.operationId);
  assert.notEqual(changedState.idempotencyKey, base.idempotencyKey);
});

test("rejects mutations in canary and provider/action/resource mismatches", () => {
  assert.throws(
    () =>
      createProviderOperationPlan({
        environment: "canary",
        release: release(),
        operations: [
          operation({
            action: "cloudflare.d1.database.ensure",
            resource: {
              kind: "d1-database",
              name: "disposable-canary",
              identitySha256: "8".repeat(64),
            },
            mutation: true,
          }),
        ],
        issuedAt: "2026-09-01T15:00:00.000Z",
        validUntil: "2026-09-01T15:15:00.000Z",
      }),
    /cannot authorize mutations/,
  );
  assert.throws(
    () =>
      createProviderOperationPlan({
        environment: "canary",
        release: release(),
        operations: [
          operation({
            provider: "resend",
            action: "resend.domain.verify",
            resource: {
              kind: "sending-domain",
              name: "notify.freshtowels.gr",
              identitySha256: "8".repeat(64),
            },
            mutation: true,
          }),
        ],
        issuedAt: "2026-09-01T15:00:00.000Z",
        validUntil: "2026-09-01T15:15:00.000Z",
      }),
    /cannot authorize mutations/,
  );
  for (const changed of [
    operation({ provider: "resend" }),
    operation({ resource: { kind: "dns-record", name: "wrong", identitySha256: "f".repeat(64) } }),
    operation({ mutation: true }),
    operation({ resource: { kind: "account", name: "email@example.com", identitySha256: "f".repeat(64) } }),
  ]) {
    assert.throws(
      () =>
        createProviderOperationPlan({
          environment: "production",
          release: release(),
          operations: [changed],
          issuedAt: "2026-09-01T15:00:00.000Z",
          validUntil: "2026-09-01T15:15:00.000Z",
        }),
      /contract/,
    );
  }
});

test("rejects stale plans, release drift, reordered operations and injected fields", () => {
  const plan = createProviderOperationPlan({
    environment: "production",
    release: release(),
    operations: [operation()],
    issuedAt: "2026-09-01T15:00:00.000Z",
    validUntil: "2026-09-01T15:15:00.000Z",
  });
  assert.throws(
    () =>
      validateProviderOperationPlan(plan, {
        expectedRelease: release(),
        now: new Date("2026-09-01T15:15:00.000Z"),
      }),
    /stale/,
  );
  assert.throws(
    () =>
      validateProviderOperationPlan(plan, {
        expectedRelease: { ...release(), artifactSha256: "0".repeat(64) },
        now,
      }),
    /differs/,
  );
  const changed = structuredClone(plan);
  changed.operations[0].sequence = 2;
  assert.throws(() => validateProviderOperationPlan(changed, { now }), /contract/);
  const injected = structuredClone(plan);
  injected.command = "arbitrary";
  assert.throws(() => validateProviderOperationPlan(injected, { now }), /unexpected/);
});
