import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  productionCandidateRoutes,
  validateProductionCutoverInput,
} from "../scripts/production-cutover-adapter.mjs";
import { createProductionReleaseCandidateReceipt } from "../scripts/production-release-candidate-receipt.mjs";
import { deriveProductionCutoverInput } from "../scripts/run-production-cutover.mjs";

const digest = (value) => sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
const d = (character) => character.repeat(64);
const applicationCommitSha = "a".repeat(40);
const controllerCommitSha = "b".repeat(40);
const requestId = "11111111-1111-4111-8111-111111111111";
const workerVersionId = "22222222-2222-4222-8222-222222222222";
const accessApplicationId = "33333333-3333-4333-8333-333333333333";
const primaryId = "44444444-4444-4444-8444-444444444444";
const recoveryId = "55555555-5555-4555-8555-555555555555";
const releaseCompletedAt = "2026-09-01T12:05:00.000Z";
const adminIdentity = "owner-admin@example.net";

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

function candidate() {
  const body = {
    schema: "deployment-control/production-candidate-e2e/v1",
    receiptType: "fresh-towels-production-candidate-e2e",
    environment: "production-candidate-e2e",
    completedAt: "2026-09-01T12:04:59.000Z",
    release: {
      applicationCommitSha,
      artifactSha256: d("1"),
      controllerCommitSha,
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
      candidatePatternsSha256: digest(productionCandidateRoutes),
      preCutoverStateSha256: digest([
        "freshtowels.gr/api/internal/*",
        "freshtowels.gr/internal/leads",
        "freshtowels.gr/internal/leads/*",
      ]),
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
      recipientSha256: sha256(Buffer.from("info@freshtowels.gr")),
      senderSha256: sha256(
        Buffer.from("notifications@notify.freshtowels.gr"),
      ),
    },
    lifecycle: {
      finalStateSha256: d("9"),
      transitionSha256s: [d("a"), d("b"), d("c")],
    },
  };
  return { ...body, receiptSha256: digest(body) };
}

function privateReceipt() {
  const cloudflare = {
    accountId: "c".repeat(32),
    zoneId: "d".repeat(32),
    zoneName: "freshtowels.gr",
    zoneStatus: "active",
    dnsInventoryCount: 17,
    dnsInventorySha256: d("e"),
    access: {
      applicationId: accessApplicationId,
      applicationDomain: "freshtowels.gr/internal/leads",
      adminIdentitySha256: sha256(Buffer.from(adminIdentity)),
      policyDecision: "allow",
      extraPolicyCount: 0,
    },
  };
  const resend = {
    domain: "notify.freshtowels.gr",
    domainStatus: "verified",
    sendingCapability: "enabled",
    senderAddress: "notifications@notify.freshtowels.gr",
    webhookEndpointSha256: sha256(
      Buffer.from("https://freshtowels.gr/api/webhooks/resend"),
    ),
    webhookStatus: "enabled",
  };
  const providerBody = { cloudflare, resend };
  return createProductionReleaseCandidateReceipt({
    candidate: candidate(),
    completedAt: releaseCompletedAt,
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
      applicationCommitSha,
      applicationRepositoryId: "1350923567",
      brokerRequestId: requestId,
      buildArtifactSha256: d("0"),
      controllerCommitSha,
      controllerRepositoryId: "1353294568",
      productionInfrastructureReceiptSha256: d("3"),
      productionReleaseCompletedAt: releaseCompletedAt,
      productionReleaseStateSha256: d("4"),
      protectedExecutionRunId: "33524599990",
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
  }).receipt;
}

function capsule() {
  return {
    application: {
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1350923567",
      commitSha: applicationCommitSha,
    },
    controller: {
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      commitSha: controllerCommitSha,
    },
    createdAt: "2026-09-01T12:06:00.000Z",
    validUntil: "2026-09-01T14:06:00.000Z",
    cutover: {
      prerequisite: {
        requestId,
        runId: "33524599990",
        receiptSha256: d("4"),
        completedAt: releaseCompletedAt,
      },
    },
  };
}

function releaseRequest() {
  return {
    requestId: "66666666-6666-4666-8666-666666666666",
    source: { commitSha: applicationCommitSha },
    controller: { commitSha: controllerCommitSha },
  };
}

test("derives cutover only from the exact encrypted private release package and owner Access event", () => {
  const receipt = privateReceipt();
  const input = deriveProductionCutoverInput({
    accessAudit: { eventSha256: d("9") },
    capsule: capsule(),
    privateReceipt: receipt,
    releaseRequest: releaseRequest(),
  });
  validateProductionCutoverInput(input, {
    now: new Date("2026-09-01T12:07:00.000Z"),
  });
  assert.equal(input.worker.versionId, workerVersionId);
  assert.equal(input.candidate.e2eEvidenceSha256, receipt.candidate.receiptSha256);
  assert.equal(
    input.candidate.productionReleaseCandidateReceiptSha256,
    receipt.receiptSha256,
  );
  assert.equal(
    input.candidate.routesStateSha256,
    receipt.candidate.routes.preCutoverStateSha256,
  );
});

test("rejects a substituted production prerequisite before any provider mutation", () => {
  const receipt = privateReceipt();
  const changed = capsule();
  changed.cutover.prerequisite.runId = "33524599991";
  assert.throws(
    () =>
      deriveProductionCutoverInput({
        accessAudit: { eventSha256: d("9") },
        capsule: changed,
        privateReceipt: receipt,
        releaseRequest: releaseRequest(),
      }),
    /prerequisite differs/,
  );
});

test("runner materializes the exact custody receipt before constructing provider clients", async () => {
  const source = await readFile(
    new URL("../scripts/run-production-cutover.mjs", import.meta.url),
    "utf8",
  );
  const materialize = source.indexOf("materializeProductionReleaseReceipt()");
  const validate = source.indexOf("parsePrivateReceipt(receiptMaterial)");
  const cloudflare = source.indexOf("createCloudflareHttpAdapter(options)");
  const execute = source.indexOf("executeProductionCutoverAdapter)");
  assert.ok(materialize >= 0 && validate > materialize && cloudflare > validate);
  assert.ok(execute >= 0);
  assert.doesNotMatch(source, /npm\s+(?:run\s+)?build|vite\s+build/);
  assert.doesNotMatch(
    source,
    /console\.(?:log|error)\([^\n]*(?:TOKEN|PRIVATE_KEY|PASSPHRASE|error\.message)/,
  );
  assert.match(source, /hash-only evidence written/);
  assert.match(source, /receipt_sha256=/);
});
