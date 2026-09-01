import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  persistProductionDnsStageEvidence,
  validateHashOnlyProductionDnsStageEvidence,
  validateProtectedDnsStageEnvironment,
} from "../scripts/run-production-dns-stage.mjs";

function trusted() {
  return {
    expectedCapsuleSha256: "a".repeat(64),
    protectedExecution: {
      brokerRequestId: "55555555-5555-4555-8555-555555555555",
      capsuleRequestSha256: "b".repeat(64),
      runId: "40000000001",
    },
    releaseRequest: {
      requestId: "55555555-5555-4555-8555-555555555555",
      source: { commitSha: "2".repeat(40), workflowRunId: "39000000001", workflowRunAttempt: 1 },
      controller: { commitSha: "3".repeat(40) },
    },
  };
}

function evidence(value = trusted()) {
  const body = {
    schema: "deployment-control/production-dns-stage-evidence/v1",
    operation: "production-dns-stage",
    requestId: value.releaseRequest.requestId,
    capsuleRequestSha256: value.protectedExecution.capsuleRequestSha256,
    applicationCommitSha: value.releaseRequest.source.commitSha,
    controllerCommitSha: value.releaseRequest.controller.commitSha,
    applicationRunId: value.releaseRequest.source.workflowRunId,
    applicationRunAttempt: value.releaseRequest.source.workflowRunAttempt,
    protectedExecutionRunId: value.protectedExecution.runId,
    capsuleSha256: value.expectedCapsuleSha256,
    cloudflareZoneStateSha256: "c".repeat(64),
    dnsInventorySha256: "d".repeat(64),
    resendVerificationRecordsSha256: "e".repeat(64),
    providerStateSha256: "f".repeat(64),
    privateReceiptSha256: "1".repeat(64),
    encryptedCustodyProofSha256: "4".repeat(64),
    result: "verified",
    completedAt: "2026-09-01T17:01:00.000Z",
  };
  return { ...body, receiptSha256: sha256(Buffer.from(canonicalJson(body) + "\n")) };
}

test("DNS-stage runner accepts only exact hash-only evidence", () => {
  const value = trusted();
  assert.equal(validateHashOnlyProductionDnsStageEvidence(evidence(value), value), true);
  assert.throws(
    () => validateHashOnlyProductionDnsStageEvidence({ ...evidence(value), zoneId: "b".repeat(32) }, value),
    /evidence-shape/,
  );
  assert.throws(
    () => validateHashOnlyProductionDnsStageEvidence({ ...evidence(value), dnsInventorySha256: "0".repeat(64) }, value),
    /integrity/,
  );
});

test("DNS-stage runner requires the protected exact-main workflow identity", () => {
  const environment = {
    GITHUB_SHA: "3".repeat(40),
    GITHUB_RUN_ID: "40000000001",
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_PROTECTED: "true",
    GITHUB_REPOSITORY: "zikosbozonis-beep/fresh-towels-deployment-control",
    GITHUB_REPOSITORY_ID: "1353294568",
    GITHUB_WORKFLOW_REF: "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/execute-release.yml@refs/heads/main",
    GITHUB_WORKFLOW_SHA: "3".repeat(40),
  };
  assert.equal(validateProtectedDnsStageEnvironment(environment).runId, "40000000001");
  assert.throws(
    () => validateProtectedDnsStageEnvironment({ ...environment, GITHUB_REF_PROTECTED: "false" }),
    /protected-execution-environment/,
  );
});

test("DNS-stage runner persists canonical public evidence and only the receipt output", async () => {
  const root = await mkdtemp(join(tmpdir(), "ft-dns-stage-runner-"));
  try {
    const value = trusted();
    const item = evidence(value);
    const outputPath = join(root, "evidence.json");
    const githubOutput = join(root, "github-output.txt");
    await persistProductionDnsStageEvidence({ evidence: item, githubOutput, outputPath, trusted: value });
    assert.equal(await readFile(outputPath, "utf8"), canonicalJson(item) + "\n");
    assert.equal(await readFile(githubOutput, "utf8"), "receipt_sha256=" + item.receiptSha256 + "\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
