import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import { createAmbiguousReceipt } from "../scripts/create-ambiguous-receipt.mjs";
import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";

function request() {
  const now = Date.now();
  return {
    artifact: {
      ciphertextBlobSha1: "4".repeat(40),
      ciphertextSha256: "5".repeat(64),
      encryptionKeySha256: "6".repeat(64),
      manifestBlobSha1: "7".repeat(40),
      plaintextBytes: 100,
      plaintextSha256: "8".repeat(64),
      releaseId: "9009",
      transportCommitSha: "9".repeat(40),
      transportTag: "deployment-control/11111111-1111-4111-8111-111111111111",
    },
    controller: { commitSha: "2".repeat(40), repositoryId: "2002" },
    evidence: {
      immutableRelease: true,
      manifestSha256: "a".repeat(64),
      oidcTokenSha256: "b".repeat(64),
    },
    expiresAt: new Date(now + 10 * 60_000).toISOString(),
    issuedAt: new Date(now - 1_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
    operation: "production-release",
    requestId: "11111111-1111-4111-8111-111111111111",
    schema: "deployment-control/release-request/v1",
    source: {
      commitSha: "1".repeat(40),
      repositoryId: "1001",
      workflowRunAttempt: 1,
      workflowRunId: "8008",
    },
  };
}

test("ambiguous finalization receipt is deterministic and contains only non-secret execution identity", () => {
  const release = request();
  const encoded = Buffer.from(canonicalJson(release)).toString("base64url");
  const environment = {
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_RUN_ID: "33524599999",
    RELEASE_REQUEST_BASE64: encoded,
  };
  const first = createAmbiguousReceipt(environment);
  const second = createAmbiguousReceipt(environment);
  assert.deepEqual(first, second);
  assert.equal(first.receipt.outcome, "execution_ambiguous");
  assert.equal(first.receipt.requestId, release.requestId);
  assert.equal(first.receipt.controllerRunId, environment.GITHUB_RUN_ID);
  assert.equal(first.receipt.controllerRunAttempt, 2);
  assert.equal(first.receiptSha256, sha256(Buffer.from(canonicalJson(first.receipt))));
  assert.deepEqual(Object.keys(first.receipt).sort(), [
    "controllerRunAttempt",
    "controllerRunId",
    "outcome",
    "requestId",
    "requestSha256",
    "schema",
  ]);
  assert.equal(JSON.stringify(first).includes(encoded), false);
});

test("ambiguous finalization receipt rejects malformed public execution identity", () => {
  assert.throws(
    () =>
      createAmbiguousReceipt({
        GITHUB_RUN_ATTEMPT: "1",
        GITHUB_RUN_ID: "1",
        RELEASE_REQUEST_BASE64: "not-canonical",
      }),
    /base64url|canonical|JSON/,
  );
});
