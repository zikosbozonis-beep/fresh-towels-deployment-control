import { sha256 } from "./control-contract.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const safeNamePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;

export const providerActionContracts = Object.freeze({
  "cloudflare.account.verify": Object.freeze({
    provider: "cloudflare",
    resourceKind: "account",
    mutation: false,
  }),
  "cloudflare.d1.database.ensure": Object.freeze({
    provider: "cloudflare",
    resourceKind: "d1-database",
    mutation: true,
  }),
  "cloudflare.d1.migration.apply": Object.freeze({
    provider: "cloudflare",
    resourceKind: "d1-migration",
    mutation: true,
  }),
  "cloudflare.worker.version.upload": Object.freeze({
    provider: "cloudflare",
    resourceKind: "worker-version",
    mutation: true,
  }),
  "cloudflare.worker.version.verify": Object.freeze({
    provider: "cloudflare",
    resourceKind: "worker-version",
    mutation: false,
  }),
  "cloudflare.worker.version.promote": Object.freeze({
    provider: "cloudflare",
    resourceKind: "worker-deployment",
    mutation: true,
  }),
  "cloudflare.access.application.ensure": Object.freeze({
    provider: "cloudflare",
    resourceKind: "access-application",
    mutation: true,
  }),
  "cloudflare.access.policy.ensure": Object.freeze({
    provider: "cloudflare",
    resourceKind: "access-policy",
    mutation: true,
  }),
  "cloudflare.zone.worker-route.ensure": Object.freeze({
    provider: "cloudflare",
    resourceKind: "worker-route",
    mutation: true,
  }),
  "cloudflare.zone.dns-record.ensure": Object.freeze({
    provider: "cloudflare",
    resourceKind: "dns-record",
    mutation: true,
  }),
  "resend.domain.inspect": Object.freeze({
    provider: "resend",
    resourceKind: "sending-domain",
    mutation: false,
  }),
  "resend.domain.verify": Object.freeze({
    provider: "resend",
    resourceKind: "sending-domain",
    mutation: true,
  }),
  "resend.webhook.ensure": Object.freeze({
    provider: "resend",
    resourceKind: "webhook",
    mutation: true,
  }),
  "resend.email.probe": Object.freeze({
    provider: "resend",
    resourceKind: "delivery-probe",
    mutation: true,
  }),
});

function exactPlainObject(value, keys, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains missing or unexpected fields`);
  }
}

function canonicalInstant(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${label} is not canonical UTC`);
  }
  return timestamp;
}

function operationId(release, operation, environment) {
  return sha256(
    Buffer.from(
      [
        release.releaseId,
        environment,
        release.applicationCommitSha,
        release.controllerCommitSha,
        operation.sequence,
        operation.provider,
        operation.action,
        operation.resource.kind,
        operation.resource.identitySha256,
        operation.desiredStateSha256,
      ].join("\0"),
      "utf8",
    ),
  );
}

function idempotencyKey(release, operation, environment) {
  return sha256(
    Buffer.from(
      [
        "deployment-control/provider-operation/v1",
        release.releaseId,
        environment,
        operation.operationId,
        operation.desiredStateSha256,
      ].join("\0"),
      "utf8",
    ),
  );
}

function validateReleaseBinding(release, expectedRelease) {
  exactPlainObject(
    release,
    [
      "requestId",
      "releaseId",
      "applicationCommitSha",
      "controllerCommitSha",
      "artifactSha256",
      "plaintextSha256",
      "uploadArtifactSha256",
      "evidenceSha256",
    ],
    "provider plan release binding",
  );
  if (
    !uuidPattern.test(release.requestId) ||
    !digestPattern.test(release.releaseId) ||
    !commitPattern.test(release.applicationCommitSha) ||
    !commitPattern.test(release.controllerCommitSha) ||
    !digestPattern.test(release.artifactSha256) ||
    !digestPattern.test(release.plaintextSha256) ||
    !digestPattern.test(release.uploadArtifactSha256) ||
    !digestPattern.test(release.evidenceSha256)
  ) {
    throw new Error("provider plan release binding is malformed");
  }
  if (expectedRelease) {
    for (const key of Object.keys(release)) {
      if (expectedRelease[key] !== release[key]) {
        throw new Error(`provider plan release ${key} differs from approved evidence`);
      }
    }
  }
}

function validateOperation(operation, release, environment, index) {
  exactPlainObject(
    operation,
    [
      "sequence",
      "operationId",
      "provider",
      "action",
      "resource",
      "desiredStateSha256",
      "idempotencyKey",
      "mutation",
    ],
    "provider operation",
  );
  exactPlainObject(operation.resource, ["kind", "name", "identitySha256"], "provider resource");
  const contract = providerActionContracts[operation.action];
  if (
    !contract ||
    operation.sequence !== index + 1 ||
    operation.provider !== contract.provider ||
    operation.resource.kind !== contract.resourceKind ||
    operation.mutation !== contract.mutation ||
    !safeNamePattern.test(operation.resource.name) ||
    operation.resource.name.includes("@") ||
    !digestPattern.test(operation.resource.identitySha256) ||
    !digestPattern.test(operation.desiredStateSha256)
  ) {
    throw new Error(`provider operation ${index + 1} violates its action contract`);
  }
  if (environment === "canary" && operation.mutation) {
    throw new Error("canary provider plans cannot authorize mutations");
  }
  if (operation.operationId !== operationId(release, operation, environment)) {
    throw new Error("provider operation identity is not release-bound");
  }
  if (
    operation.idempotencyKey !==
    idempotencyKey(release, operation, environment)
  ) {
    throw new Error("provider operation idempotency key is not release-bound");
  }
}

export function finalizeProviderOperation(
  release,
  input,
  environment = "production",
) {
  if (!["canary", "production"].includes(environment)) {
    throw new Error("provider operation environment is invalid");
  }
  const operation = {
    sequence: input.sequence,
    operationId: "",
    provider: input.provider,
    action: input.action,
    resource: input.resource,
    desiredStateSha256: input.desiredStateSha256,
    idempotencyKey: "",
    mutation: input.mutation,
  };
  operation.operationId = operationId(release, operation, environment);
  operation.idempotencyKey = idempotencyKey(
    release,
    operation,
    environment,
  );
  return Object.freeze(operation);
}

export function validateProviderOperationPlan(plan, { expectedRelease, now = new Date() } = {}) {
  exactPlainObject(
    plan,
    ["schema", "environment", "issuedAt", "validUntil", "release", "operations"],
    "provider operation plan",
  );
  if (
    plan.schema !== "deployment-control/provider-operation-plan/v1" ||
    !["canary", "production"].includes(plan.environment) ||
    !Array.isArray(plan.operations) ||
    plan.operations.length < 1 ||
    plan.operations.length > 64
  ) {
    throw new Error("provider operation plan declaration is invalid");
  }
  const issuedAt = canonicalInstant(plan.issuedAt, "provider plan issuedAt");
  const validUntil = canonicalInstant(plan.validUntil, "provider plan validUntil");
  const current = now.valueOf();
  if (
    validUntil <= issuedAt ||
    validUntil - issuedAt > 30 * 60 * 1000 ||
    current < issuedAt - 60_000 ||
    current >= validUntil
  ) {
    throw new Error("provider operation plan validity window is stale or unsafe");
  }
  validateReleaseBinding(plan.release, expectedRelease);
  const ids = new Set();
  for (const [index, operation] of plan.operations.entries()) {
    validateOperation(operation, plan.release, plan.environment, index);
    if (ids.has(operation.operationId)) throw new Error("provider operation is duplicated");
    ids.add(operation.operationId);
  }
  return Object.freeze(plan);
}

export function createProviderOperationPlan({
  environment,
  release,
  operations,
  issuedAt,
  validUntil,
  now = new Date(issuedAt),
}) {
  const finalized = operations.map((operation, index) =>
    finalizeProviderOperation(
      release,
      { ...operation, sequence: index + 1 },
      environment,
    ),
  );
  const plan = {
    schema: "deployment-control/provider-operation-plan/v1",
    environment,
    issuedAt,
    validUntil,
    release,
    operations: finalized,
  };
  return validateProviderOperationPlan(plan, { expectedRelease: release, now });
}
