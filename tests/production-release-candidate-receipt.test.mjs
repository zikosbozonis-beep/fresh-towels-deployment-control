import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../scripts/control-contract.mjs";
import {
  createProductionReleaseCandidateReceipt,
  validateProductionReleaseCandidateReceipt,
} from "../scripts/production-release-candidate-receipt.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const digest = (value) => sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
const d = (character) => character.repeat(64);
const app = "a".repeat(40);
const controller = "b".repeat(40);
const requestId = "11111111-1111-4111-8111-111111111111";
const workerVersionId = "22222222-2222-4222-8222-222222222222";
const primaryId = "33333333-3333-4333-8333-333333333333";
const recoveryId = "44444444-4444-4444-8444-444444444444";
const completedAt = "2026-09-01T12:05:00.000Z";

function candidate() {
  const body = {
    schema: "deployment-control/production-candidate-e2e/v1",
    receiptType: "fresh-towels-production-candidate-e2e",
    environment: "production-candidate-e2e",
    completedAt: "2026-09-01T12:04:59.000Z",
    release: {
      applicationCommitSha: app,
      artifactSha256: d("1"),
      controllerCommitSha: controller,
      executionClaimSha256: d("2"),
      executionRequestId: requestId,
      infrastructureReceiptSha256: d("3"),
      productionReleaseStateSha256: d("4"),
      releaseBindingSha256: d("5"),
    },
    worker: {
      stateSha256: d("6"),
      versionId: workerVersionId,
      workerNameSha256: sha256(Buffer.from("fresh-towels-production")),
    },
    routes: {
      activeStateSha256: d("7"),
      candidatePatternsSha256: d("8"),
      preCutoverStateSha256: d("9"),
      preStateSha256: d("0"),
      rollbackVerified: true,
    },
    accessUnauthorized: {
      challengeSha256: d("a"),
      responseBodySha256: d("b"),
      status: 302,
    },
    leadFlow: {
      d1StateSha256: d("c"),
      deliveryEventIdSha256: d("d"),
      deliveryStateSha256: d("e"),
      duplicateEffectCount: 1,
      finalStatusSha256: sha256(Buffer.from("archived")),
      leadCount: 1,
      leadIdSha256: d("f"),
      outboxIdSha256: d("1"),
      outboxStateSha256: d("2"),
      providerMessageIdSha256: d("3"),
      syntheticMarkerSha256: d("4"),
      testRunIdSha256: d("5"),
    },
    resend: {
      deliveryStateSha256: d("6"),
      messageIdSha256: d("3"),
      recipientSha256: d("7"),
      senderSha256: d("8"),
    },
    lifecycle: {
      finalStateSha256: d("9"),
      transitionSha256s: [d("a"), d("b"), d("c")],
    },
  };
  return { ...body, receiptSha256: digest(body) };
}

function database(id, name) {
  return {
    appliedMigrations: [{ name: "0001_leads.sql", version: 1 }],
    databaseId: id,
    databaseName: name,
    jurisdiction: "eu",
    leadCount: 0,
    schemaSha256: d("d"),
    schemaVersion: 1,
  };
}

function input() {
  const providerBody = {
    cloudflare: { accountId: "c".repeat(32), zoneId: "d".repeat(32) },
    resend: { domainId: "resend-domain" },
  };
  return {
    candidate: candidate(),
    completedAt,
    databases: {
      primary: database(primaryId, "fresh-towels-leads-prod"),
      recovery: database(recoveryId, "fresh-towels-leads-prod-recovery"),
      recoveryProof: {
        decryptionProofSha256: d("1"),
        encryptedBackupSha256: d("2"),
        encryptedCustodyBindingVersionSha256: d("3"),
        encryptedCustodyCiphertextSha256: d("4"),
        encryptedCustodyDecryptionProofSha256: d("5"),
        encryptedCustodySha256: d("6"),
        encryptionKeySha256: d("7"),
        plaintextBackupSha256: d("8"),
        plaintextRetained: false,
        primaryDatabaseIdSha256: sha256(Buffer.from(primaryId)),
        primarySchemaSha256: d("d"),
        recoveryDatabaseIdSha256: sha256(Buffer.from(recoveryId)),
        recoveryLeadCount: 0,
        recoverySchemaSha256: d("d"),
        timeTravelBookmarkSha256: d("9"),
      },
    },
    environment: "production",
    provider: { ...providerBody, stateSha256: digest(providerBody) },
    receiptType: "fresh-towels-production-release-candidate",
    release: {
      applicationCommitSha: app,
      applicationRepositoryId: "1350923567",
      brokerRequestId: requestId,
      buildArtifactSha256: d("0"),
      controllerCommitSha: controller,
      controllerRepositoryId: "1353294568",
      productionInfrastructureReceiptSha256: d("3"),
      productionReleaseCompletedAt: completedAt,
      productionReleaseStateSha256: d("4"),
      protectedExecutionRunId: "33524599999",
      releaseId: d("f"),
      uploadArtifactSha256: d("1"),
    },
    schema: "deployment-control/production-release-candidate-receipt/v1",
    worker: {
      deploymentStateSha256: d("2"),
      name: "fresh-towels-production",
      triggerStateSha256: d("3"),
      versionId: workerVersionId,
      versionStateSha256: d("4"),
    },
  };
}

test("creates and validates an exact private candidate package bound to the production release", () => {
  const value = createProductionReleaseCandidateReceipt(input());
  assert.match(value.receiptSha256, /^[a-f0-9]{64}$/);
  assert.equal(value.receipt.receiptSha256, value.receiptSha256);
  assert.deepEqual(
    validateProductionReleaseCandidateReceipt(value.receipt),
    value.receipt,
  );
  assert.equal(sha256(value.bytes), sha256(Buffer.from(canonicalJson(value.receipt) + "\n")));
  assert.match(value.bytes.toString("utf8"), new RegExp(workerVersionId));
  assert.match(value.bytes.toString("utf8"), new RegExp(requestId));
});

test("rejects a substituted Worker version or non-archived candidate", () => {
  const wrongWorker = input();
  wrongWorker.worker.versionId = "55555555-5555-4555-8555-555555555555";
  assert.throws(
    () => createProductionReleaseCandidateReceipt(wrongWorker),
    /candidate evidence differs/,
  );
  const unarchived = input();
  unarchived.candidate.leadFlow.finalStatusSha256 = sha256(Buffer.from("new"));
  const { receiptSha256: _ignored, ...candidateBody } = unarchived.candidate;
  unarchived.candidate.receiptSha256 = digest(candidateBody);
  assert.throws(
    () => createProductionReleaseCandidateReceipt(unarchived),
    /candidate evidence differs/,
  );
});

test("rejects package digest tampering and a completion chronology inversion", () => {
  const value = createProductionReleaseCandidateReceipt(input()).receipt;
  assert.throws(
    () => validateProductionReleaseCandidateReceipt({ ...value, receiptSha256: d("0") }),
    /digest changed/,
  );
  const future = input();
  future.candidate.completedAt = "2026-09-01T12:06:00.000Z";
  const { receiptSha256: _ignored, ...candidateBody } = future.candidate;
  future.candidate.receiptSha256 = digest(candidateBody);
  assert.throws(
    () => createProductionReleaseCandidateReceipt(future),
    /candidate evidence differs/,
  );
});
