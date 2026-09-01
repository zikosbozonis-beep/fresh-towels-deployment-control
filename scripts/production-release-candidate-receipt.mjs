import { canonicalJson, sha256 } from "./control-contract.mjs";
import { serializeProductionCandidateE2eReceipt } from "./production-candidate-e2e.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
}

function exactObject(value, keys, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(label + " must be a plain object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(label + " contains missing or unexpected fields");
  }
}

function instant(value, label) {
  const timestamp = Date.parse(value);
  if (
    typeof value !== "string" ||
    !Number.isFinite(timestamp) ||
    new Date(timestamp).toISOString() !== value
  ) {
    throw new Error(label + " is not canonical UTC");
  }
  return timestamp;
}

function database(value, label) {
  exactObject(
    value,
    [
      "appliedMigrations",
      "databaseId",
      "databaseName",
      "jurisdiction",
      "leadCount",
      "schemaSha256",
      "schemaVersion",
    ],
    label,
  );
  if (
    !uuidPattern.test(value.databaseId ?? "") ||
    typeof value.databaseName !== "string" ||
    value.jurisdiction !== "eu" ||
    !Array.isArray(value.appliedMigrations) ||
    !Number.isSafeInteger(value.leadCount) ||
    value.leadCount !== 0 ||
    !Number.isSafeInteger(value.schemaVersion) ||
    value.schemaVersion < 1 ||
    !digestPattern.test(value.schemaSha256 ?? "")
  ) {
    throw new Error(label + " is invalid");
  }
  for (const migration of value.appliedMigrations) {
    exactObject(migration, ["name", "version"], label + " migration");
    if (
      !Number.isSafeInteger(migration.version) ||
      migration.version < 1 ||
      !/^\d{4}_[a-z0-9_]+\.sql$/.test(migration.name ?? "")
    ) {
      throw new Error(label + " migration is invalid");
    }
  }
  return value;
}

function recoveryProof(value) {
  exactObject(
    value,
    [
      "decryptionProofSha256",
      "encryptedBackupSha256",
      "encryptedCustodyBindingVersionSha256",
      "encryptedCustodyCiphertextSha256",
      "encryptedCustodyDecryptionProofSha256",
      "encryptedCustodySha256",
      "encryptionKeySha256",
      "plaintextBackupSha256",
      "plaintextRetained",
      "primaryDatabaseIdSha256",
      "primarySchemaSha256",
      "recoveryDatabaseIdSha256",
      "recoveryLeadCount",
      "recoverySchemaSha256",
      "timeTravelBookmarkSha256",
    ],
    "production recovery proof",
  );
  if (
    value.plaintextRetained !== false ||
    value.recoveryLeadCount !== 0 ||
    Object.entries(value).some(
      ([key, item]) => key.endsWith("Sha256") && !digestPattern.test(item ?? ""),
    )
  ) {
    throw new Error("production recovery proof is invalid");
  }
  return value;
}

function validateBody(body) {
  exactObject(
    body,
    [
      "candidate",
      "completedAt",
      "databases",
      "environment",
      "provider",
      "receiptType",
      "release",
      "schema",
      "worker",
    ],
    "production release candidate receipt",
  );
  if (
    body.schema !==
      "deployment-control/production-release-candidate-receipt/v1" ||
    body.receiptType !== "fresh-towels-production-release-candidate" ||
    body.environment !== "production"
  ) {
    throw new Error("production release candidate receipt identity changed");
  }
  const completedAt = instant(body.completedAt, "production release completion");
  exactObject(
    body.release,
    [
      "applicationCommitSha",
      "applicationRepositoryId",
      "brokerRequestId",
      "buildArtifactSha256",
      "controllerCommitSha",
      "controllerRepositoryId",
      "productionInfrastructureReceiptSha256",
      "productionReleaseCompletedAt",
      "productionReleaseStateSha256",
      "protectedExecutionRunId",
      "releaseId",
      "uploadArtifactSha256",
    ],
    "production release identity",
  );
  if (
    !digestPattern.test(body.release.releaseId ?? "") ||
    !commitPattern.test(body.release.applicationCommitSha ?? "") ||
    !commitPattern.test(body.release.controllerCommitSha ?? "") ||
    !decimalPattern.test(body.release.applicationRepositoryId ?? "") ||
    !decimalPattern.test(body.release.controllerRepositoryId ?? "") ||
    !uuidPattern.test(body.release.brokerRequestId ?? "") ||
    !decimalPattern.test(body.release.protectedExecutionRunId ?? "") ||
    [
      body.release.buildArtifactSha256,
      body.release.uploadArtifactSha256,
      body.release.productionInfrastructureReceiptSha256,
      body.release.productionReleaseStateSha256,
    ].some((value) => !digestPattern.test(value ?? "")) ||
    instant(
      body.release.productionReleaseCompletedAt,
      "bound production release completion",
    ) !== completedAt
  ) {
    throw new Error("production release identity is invalid");
  }
  exactObject(body.provider, ["cloudflare", "resend", "stateSha256"], "provider state");
  if (
    !digestPattern.test(body.provider.stateSha256 ?? "") ||
    digest({ cloudflare: body.provider.cloudflare, resend: body.provider.resend }) !==
      body.provider.stateSha256
  ) {
    throw new Error("production provider state digest changed");
  }
  exactObject(
    body.databases,
    ["primary", "recovery", "recoveryProof"],
    "production database evidence",
  );
  const primary = database(body.databases.primary, "primary production D1");
  const recovery = database(body.databases.recovery, "recovery production D1");
  const proof = recoveryProof(body.databases.recoveryProof);
  if (
    primary.databaseId === recovery.databaseId ||
    primary.schemaVersion !== recovery.schemaVersion ||
    primary.schemaSha256 !== recovery.schemaSha256 ||
    proof.primaryDatabaseIdSha256 !==
      sha256(Buffer.from(primary.databaseId, "utf8")) ||
    proof.recoveryDatabaseIdSha256 !==
      sha256(Buffer.from(recovery.databaseId, "utf8")) ||
    proof.primarySchemaSha256 !== primary.schemaSha256 ||
    proof.recoverySchemaSha256 !== recovery.schemaSha256
  ) {
    throw new Error("production recovery evidence differs from D1 state");
  }
  exactObject(
    body.worker,
    [
      "deploymentStateSha256",
      "name",
      "triggerStateSha256",
      "versionId",
      "versionStateSha256",
    ],
    "production Worker evidence",
  );
  if (
    body.worker.name !== "fresh-towels-production" ||
    !uuidPattern.test(body.worker.versionId ?? "") ||
    [
      body.worker.versionStateSha256,
      body.worker.deploymentStateSha256,
      body.worker.triggerStateSha256,
    ].some((value) => !digestPattern.test(value ?? ""))
  ) {
    throw new Error("production Worker evidence is invalid");
  }
  // The serializer is also the exact candidate self-digest/PII boundary.
  serializeProductionCandidateE2eReceipt(body.candidate);
  if (
    body.candidate.release.applicationCommitSha !==
      body.release.applicationCommitSha ||
    body.candidate.release.controllerCommitSha !==
      body.release.controllerCommitSha ||
    body.candidate.release.artifactSha256 !== body.release.uploadArtifactSha256 ||
    body.candidate.release.executionRequestId !== body.release.brokerRequestId ||
    body.candidate.release.infrastructureReceiptSha256 !==
      body.release.productionInfrastructureReceiptSha256 ||
    body.candidate.release.productionReleaseStateSha256 !==
      body.release.productionReleaseStateSha256 ||
    body.candidate.worker.versionId !== body.worker.versionId ||
    body.candidate.routes.rollbackVerified !== true ||
    body.candidate.leadFlow.finalStatusSha256 !==
      sha256(Buffer.from("archived", "utf8")) ||
    body.candidate.leadFlow.duplicateEffectCount !== 1 ||
    body.candidate.leadFlow.leadCount !== 1 ||
    body.candidate.resend.messageIdSha256 !==
      body.candidate.leadFlow.providerMessageIdSha256 ||
    instant(body.candidate.completedAt, "candidate completion") > completedAt
  ) {
    throw new Error("production candidate evidence differs from release state");
  }
  return body;
}

export function createProductionReleaseCandidateReceipt(input) {
  const body = validateBody(structuredClone(input));
  const receipt = Object.freeze({ ...body, receiptSha256: digest(body) });
  const bytes = Buffer.from(canonicalJson(receipt) + "\n", "utf8");
  return Object.freeze({ bytes, receipt, receiptSha256: receipt.receiptSha256 });
}

export function validateProductionReleaseCandidateReceipt(value) {
  exactObject(
    value,
    [
      "candidate",
      "completedAt",
      "databases",
      "environment",
      "provider",
      "receiptSha256",
      "receiptType",
      "release",
      "schema",
      "worker",
    ],
    "production release candidate receipt",
  );
  const { receiptSha256, ...body } = value;
  if (!digestPattern.test(receiptSha256 ?? "") || digest(body) !== receiptSha256) {
    throw new Error("production release candidate receipt digest changed");
  }
  validateBody(body);
  return Object.freeze(structuredClone(value));
}

export const productionReleaseCandidateReceiptConstants = Object.freeze({
  schema: "deployment-control/production-release-candidate-receipt/v1",
  receiptType: "fresh-towels-production-release-candidate",
});
