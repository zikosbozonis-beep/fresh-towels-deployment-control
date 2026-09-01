import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash, generateKeyPairSync, sign, webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  ciphertextCustodyPaths,
  handleCiphertextCustody,
} from "../dispatcher/ciphertext-custody.mjs";
import { handleDispatch } from "../dispatcher/worker.mjs";
import { canonicalJson } from "../scripts/control-contract.mjs";

globalThis.crypto ??= webcrypto;

const now = Date.parse("2026-09-01T10:00:00.000Z");
const bootstrapRequestId = "11111111-1111-4111-8111-111111111111";
const releaseRequestId = "22222222-2222-4222-8222-222222222222";
const cutoverRequestId = "33333333-3333-4333-8333-333333333333";
const sourceSha = "1".repeat(40);
const controllerSha = "2".repeat(40);
const requestDigest = "3".repeat(64);
const encryptionKeySha256 = "4".repeat(64);
const capsuleRequestSha256 = "5".repeat(64);
const targetSha256 = "6".repeat(64);
const resourceIdentitySha256 = "7".repeat(64);
const prerequisiteReceiptSha256 = "8".repeat(64);
const dispatcherEnvironment = {
  CONTROLLER_COMMIT_SHA: controllerSha,
  CONTROLLER_REPOSITORY: "owner/control",
  CONTROLLER_REPOSITORY_ID: "2002",
  CONTROLLER_REPOSITORY_OWNER_ID: "9009",
  REQUESTER_APP_ACTOR_ID: "7007",
  SOURCE_REPOSITORY: "owner/private-app",
  SOURCE_REPOSITORY_ID: "1001",
  SOURCE_REPOSITORY_OWNER_ID: "9009",
  SOURCE_WORKFLOW_PATH: ".github/workflows/release-handoff.yml",
};

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function executorReleaseRequest() {
  return {
    artifact: {
      ciphertextBlobSha1: "4".repeat(40),
      ciphertextSha256: "5".repeat(64),
      encryptionKeySha256,
      manifestBlobSha1: "6".repeat(40),
      plaintextBytes: 100,
      plaintextSha256: "7".repeat(64),
      releaseId: "9009",
      transportCommitSha: "8".repeat(40),
      transportTag: `deployment-control/${bootstrapRequestId}`,
    },
    controller: { commitSha: controllerSha, repositoryId: "2002" },
    evidence: {
      immutableRelease: true,
      manifestSha256: "9".repeat(64),
      oidcTokenSha256: "a".repeat(64),
    },
    expiresAt: "2026-09-01T10:15:00.000Z",
    issuedAt: "2026-09-01T10:00:00.000Z",
    nonce: "A".repeat(43),
    operation: "production-bootstrap",
    requestId: bootstrapRequestId,
    schema: "deployment-control/release-request/v1",
    source: {
      commitSha: sourceSha,
      repositoryId: "1001",
      workflowRunAttempt: 1,
      workflowRunId: "6006",
    },
  };
}

function executorClaims(overrides = {}) {
  const seconds = Math.floor(now / 1000);
  return {
    actor_id: "7007",
    aud: "deployment-control-executor-v1",
    environment: "production",
    event_name: "workflow_dispatch",
    exp: seconds + 300,
    iat: seconds - 5,
    iss: "https://token.actions.githubusercontent.com",
    job_workflow_ref: `owner/control/.github/workflows/execute-release.yml@${controllerSha}`,
    jti: "custody-executor-jti-123456789",
    nbf: seconds - 5,
    ref: "refs/heads/main",
    ref_type: "branch",
    repository: "owner/control",
    repository_id: "2002",
    repository_owner_id: "9009",
    repository_visibility: "public",
    run_attempt: "1",
    run_id: "7007",
    runner_environment: "github-hosted",
    sha: controllerSha,
    sub: "repo:owner@9009/control@2002:environment:production",
    workflow_ref: "owner/control/.github/workflows/execute-release.yml@refs/heads/main",
    workflow_sha: controllerSha,
    ...overrides,
  };
}

function signedJwt(privateKey, claims) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "custody-key", typ: "JWT" }))
    .toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const content = `${header}.${payload}`;
  return `${content}.${sign("RSA-SHA256", Buffer.from(content), privateKey).toString("base64url")}`;
}

class SqliteD1 {
  constructor(database) {
    this.database = database;
  }

  prepare(sql) {
    const database = this.database;
    return {
      bind(...values) {
        return {
          async first() {
            return database.prepare(sql).get(...values);
          },
          async run() {
            const result = database.prepare(sql).run(...values);
            return { meta: { changes: result.changes }, success: true };
          },
        };
      },
    };
  }
}

async function migratedDatabase() {
  const database = new DatabaseSync(":memory:");
  for (const name of [
    "0001_dispatch_consumption.sql",
    "0002_operation_prerequisites.sql",
    "0003_ciphertext_custody.sql",
  ]) {
    database.exec(
      await readFile(new URL(`../dispatcher/migrations/${name}`, import.meta.url), "utf8"),
    );
  }
  return database;
}

function request(
  operation = "production-bootstrap",
  requestId = bootstrapRequestId,
  approvedEncryptionKeySha256 = encryptionKeySha256,
) {
  return {
    artifact: { encryptionKeySha256: approvedEncryptionKeySha256 },
    controller: { commitSha: controllerSha, repositoryId: "2002" },
    operation,
    requestId,
    source: { commitSha: sourceSha, repositoryId: "1001" },
  };
}

function claims(runId = "7007") {
  return { run_attempt: "1", run_id: runId };
}

function context(overrides = {}) {
  return {
    applicationCommitSha: sourceSha,
    brokerRequestId: bootstrapRequestId,
    capsuleRequestSha256,
    resourceIdentitySha256,
    targetSha256,
    ...overrides,
  };
}

function storeBody(ciphertext, overrides = {}) {
  const plaintext = Buffer.from("synthetic-provider-secret-never-persisted");
  return {
    binding: "RESEND_API_KEY",
    ciphertextBase64Url: ciphertext.toString("base64url"),
    ciphertextSha256: sha256(ciphertext),
    context: context(),
    encryptionKeySha256,
    payloadKind: "secret",
    plaintextBytes: plaintext.length,
    plaintextSha256: sha256(plaintext),
    releaseRequestBase64: "synthetic-release-request",
    ...overrides,
  };
}

function recoveryStoreBody(ciphertext, overrides = {}) {
  const plaintext = Buffer.from("synthetic-initial-d1-recovery-snapshot");
  return {
    binding: "PRODUCTION_D1_INITIAL_RECOVERY",
    ciphertextBase64Url: ciphertext.toString("base64url"),
    ciphertextSha256: sha256(ciphertext),
    context: {
      applicationCommitSha: sourceSha,
      brokerRequestId: releaseRequestId,
      capsuleRequestSha256,
      controllerCommitSha: controllerSha,
    },
    encryptionKeySha256,
    payloadKind: "private_receipt",
    plaintextBytes: plaintext.length,
    plaintextSha256: sha256(plaintext),
    releaseRequestBase64: "synthetic-production-release-request",
    ...overrides,
  };
}

function releaseCandidateStoreBody(ciphertext, overrides = {}) {
  const plaintext = Buffer.from("synthetic-private-production-release-candidate-receipt");
  return {
    binding: "PRODUCTION_RELEASE_CANDIDATE_RECEIPT",
    ciphertextBase64Url: ciphertext.toString("base64url"),
    ciphertextSha256: sha256(ciphertext),
    context: {
      applicationCommitSha: sourceSha,
      brokerRequestId: releaseRequestId,
      capsuleRequestSha256,
      controllerCommitSha: controllerSha,
    },
    encryptionKeySha256,
    payloadKind: "private_receipt",
    plaintextBytes: plaintext.length,
    plaintextSha256: sha256(plaintext),
    releaseRequestBase64: "synthetic-production-release-request",
    ...overrides,
  };
}

function seedExecution(database, {
  operation = "production-bootstrap",
  prerequisiteRequestId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  requestId = bootstrapRequestId,
  runId = "7007",
  digest = requestDigest,
} = {}) {
  database.prepare(`INSERT INTO dispatch_consumptions (
    request_id, oidc_jti_sha256, nonce_sha256, request_sha256, operation,
    source_repository_id, source_commit_sha, controller_commit_sha,
    source_workflow_run_id, source_workflow_run_attempt,
    executor_jti_sha256, controller_workflow_run_id,
    controller_workflow_run_attempt, execution_receipt_sha256,
    prerequisite_request_id, prerequisite_receipt_sha256,
    state, dispatch_http_status, claimed_at, updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, 'executing', 204, ?, ?)`).run(
    requestId,
    sha256(Buffer.from(requestId + ":oidc")),
    sha256(Buffer.from(requestId + ":nonce")),
    digest,
    operation,
    "1001",
    sourceSha,
    controllerSha,
    "6006",
    1,
    sha256(Buffer.from(requestId + ":executor")),
    runId,
    1,
    prerequisiteRequestId,
    prerequisiteReceiptSha256,
    now,
    now,
  );
}

async function custody(database, path, body, {
  operation = "production-bootstrap",
  requestId = bootstrapRequestId,
  runId = "7007",
  digest = requestDigest,
  approvedEncryptionKeySha256 = encryptionKeySha256,
} = {}) {
  return handleCiphertextCustody({
    body,
    claims: claims(runId),
    environment: { DISPATCH_STATE: new SqliteD1(database) },
    now,
    path,
    request: request(operation, requestId, approvedEncryptionKeySha256),
    requestDigest: digest,
  });
}

test("custody migration stores ciphertext only and preserves append-only audit metadata", async () => {
  const database = await migratedDatabase();
  try {
    const columns = database.prepare("PRAGMA table_info(ciphertext_custody_objects)").all();
    assert.ok(columns.some((column) => column.name === "ciphertext_base64url"));
    assert.equal(columns.some((column) => /secret|plaintext_value/i.test(column.name)), false);
    assert.equal(
      database.prepare("PRAGMA foreign_key_list(ciphertext_custody_grants)").all().length,
      2,
    );
  } finally {
    database.close();
  }
});

test("store-read-confirm-inspect is exact-release bound and never persists plaintext", async () => {
  const database = await migratedDatabase();
  try {
    seedExecution(database);
    const ciphertext = Buffer.from("opaque-gpg-ciphertext-for-custody-test");
    const body = storeBody(ciphertext);
    const stored = await custody(database, ciphertextCustodyPaths.store, body);
    assert.equal(stored.state, "pending");
    assert.equal(stored.resourceIdentitySha256, resourceIdentitySha256);

    const pending = await custody(database, ciphertextCustodyPaths.read, {
      binding: body.binding,
      expectedCiphertextSha256: stored.ciphertextSha256,
      expectedPlaintextSha256: stored.plaintextSha256,
      releaseRequestBase64: body.releaseRequestBase64,
    });
    assert.equal(pending.ciphertextBase64Url, ciphertext.toString("base64url"));
    assert.equal(pending.state, "pending");

    const proof = sha256(Buffer.from("fresh-gnupg-home-byte-proof"));
    const confirmed = await custody(database, ciphertextCustodyPaths.confirm, {
      binding: body.binding,
      custodySha256: stored.custodySha256,
      decryptionProofSha256: proof,
      expectedCiphertextSha256: stored.ciphertextSha256,
      expectedPlaintextSha256: stored.plaintextSha256,
      releaseRequestBase64: body.releaseRequestBase64,
    });
    assert.equal(confirmed.stored, true);
    assert.match(confirmed.bindingVersionSha256, /^[a-f0-9]{64}$/);

    const inspected = await custody(database, ciphertextCustodyPaths.inspect, {
      binding: body.binding,
      context: body.context,
      payloadKind: "secret",
      releaseRequestBase64: body.releaseRequestBase64,
    });
    assert.deepEqual(inspected, {
      bindingVersionSha256: confirmed.bindingVersionSha256,
      present: true,
      resourceIdentitySha256,
    });
    assert.deepEqual(
      await custody(
        database,
        ciphertextCustodyPaths.inspect,
        {
          binding: body.binding,
          context: body.context,
          payloadKind: "secret",
          releaseRequestBase64: body.releaseRequestBase64,
        },
        { approvedEncryptionKeySha256: "f".repeat(64) },
      ),
      {
        bindingVersionSha256: null,
        present: false,
        resourceIdentitySha256: null,
      },
    );

    const row = database.prepare("SELECT * FROM ciphertext_custody_objects").get();
    assert.equal(row.state, "active");
    assert.equal(row.decryption_proof_sha256, proof);
    assert.equal(row.ciphertext_base64url, ciphertext.toString("base64url"));
    assert.equal(JSON.stringify(row).includes("synthetic-provider-secret-never-persisted"), false);
  } finally {
    database.close();
  }
});

test("a production release can read only the active custody grant of its exact bootstrap prerequisite", async () => {
  const database = await migratedDatabase();
  try {
    seedExecution(database);
    const body = storeBody(Buffer.from("encrypted-production-binding"));
    const stored = await custody(database, ciphertextCustodyPaths.store, body);

    seedExecution(database, {
      operation: "production-release",
      prerequisiteRequestId: bootstrapRequestId,
      requestId: releaseRequestId,
      runId: "8008",
      digest: "9".repeat(64),
    });
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.read,
        {
          binding: body.binding,
          expectedCiphertextSha256: stored.ciphertextSha256,
          expectedPlaintextSha256: stored.plaintextSha256,
          releaseRequestBase64: body.releaseRequestBase64,
        },
        {
          operation: "production-release",
          requestId: releaseRequestId,
          runId: "8008",
          digest: "9".repeat(64),
        },
      ),
      /exact approved object/,
    );

    await custody(database, ciphertextCustodyPaths.confirm, {
      binding: body.binding,
      custodySha256: stored.custodySha256,
      decryptionProofSha256: "a".repeat(64),
      expectedCiphertextSha256: stored.ciphertextSha256,
      expectedPlaintextSha256: stored.plaintextSha256,
      releaseRequestBase64: body.releaseRequestBase64,
    });
    const read = await custody(
      database,
      ciphertextCustodyPaths.read,
      {
        binding: body.binding,
        expectedCiphertextSha256: stored.ciphertextSha256,
        expectedPlaintextSha256: stored.plaintextSha256,
        releaseRequestBase64: body.releaseRequestBase64,
      },
      {
        operation: "production-release",
        requestId: releaseRequestId,
        runId: "8008",
        digest: "9".repeat(64),
      },
    );
    assert.equal(read.state, "active");
    const resolved = await custody(
      database,
      ciphertextCustodyPaths.resolve,
      {
        binding: body.binding,
        releaseRequestBase64: body.releaseRequestBase64,
      },
      {
        operation: "production-release",
        requestId: releaseRequestId,
        runId: "8008",
        digest: "9".repeat(64),
      },
    );
    assert.equal(resolved.custodySha256, stored.custodySha256);
    assert.equal(resolved.ciphertextSha256, stored.ciphertextSha256);
    assert.equal(Object.hasOwn(resolved, "ciphertextBase64Url"), false);
    await assert.rejects(
      custody(database, ciphertextCustodyPaths.resolve, {
        binding: body.binding,
        releaseRequestBase64: body.releaseRequestBase64,
      }),
      /restricted to/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.read,
        {
          binding: body.binding,
          expectedCiphertextSha256: stored.ciphertextSha256,
          expectedPlaintextSha256: stored.plaintextSha256,
          releaseRequestBase64: body.releaseRequestBase64,
        },
        {
          operation: "production-release",
          requestId: releaseRequestId,
          runId: "8008",
          digest: "9".repeat(64),
          approvedEncryptionKeySha256: "e".repeat(64),
        },
      ),
      /exact approved object/,
    );

    database.prepare(
      "UPDATE dispatch_consumptions SET prerequisite_request_id = ? WHERE request_id = ?",
    ).run("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", releaseRequestId);
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.read,
        {
          binding: body.binding,
          expectedCiphertextSha256: stored.ciphertextSha256,
          expectedPlaintextSha256: stored.plaintextSha256,
          releaseRequestBase64: body.releaseRequestBase64,
        },
        {
          operation: "production-release",
          requestId: releaseRequestId,
          runId: "8008",
          digest: "9".repeat(64),
        },
      ),
      /exact approved object/,
    );
  } finally {
    database.close();
  }
});

test("a production release can store and activate only its exact encrypted D1 recovery receipt", async () => {
  const database = await migratedDatabase();
  try {
    seedExecution(database, {
      operation: "production-release",
      prerequisiteRequestId: bootstrapRequestId,
      requestId: releaseRequestId,
      runId: "8008",
      digest: "9".repeat(64),
    });
    const body = recoveryStoreBody(Buffer.from("opaque-encrypted-initial-d1-recovery"));
    const release = {
      operation: "production-release",
      requestId: releaseRequestId,
      runId: "8008",
      digest: "9".repeat(64),
    };
    const stored = await custody(database, ciphertextCustodyPaths.store, body, release);
    assert.equal(stored.state, "pending");
    assert.equal(stored.resourceIdentitySha256, body.plaintextSha256);

    const pending = await custody(
      database,
      ciphertextCustodyPaths.read,
      {
        binding: body.binding,
        expectedCiphertextSha256: stored.ciphertextSha256,
        expectedPlaintextSha256: stored.plaintextSha256,
        releaseRequestBase64: body.releaseRequestBase64,
      },
      release,
    );
    assert.equal(pending.state, "pending");
    const confirmed = await custody(
      database,
      ciphertextCustodyPaths.confirm,
      {
        binding: body.binding,
        custodySha256: stored.custodySha256,
        decryptionProofSha256: "a".repeat(64),
        expectedCiphertextSha256: stored.ciphertextSha256,
        expectedPlaintextSha256: stored.plaintextSha256,
        releaseRequestBase64: body.releaseRequestBase64,
      },
      release,
    );
    assert.equal(confirmed.stored, true);
    assert.equal(
      database.prepare("SELECT state FROM ciphertext_custody_objects").get().state,
      "active",
    );

    await assert.rejects(
      custody(database, ciphertextCustodyPaths.resolve, {
        binding: body.binding,
        releaseRequestBase64: body.releaseRequestBase64,
      }, release),
      /bootstrap-issued bindings/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        storeBody(Buffer.from("encrypted-runtime-secret"), {
          context: context({ brokerRequestId: releaseRequestId }),
        }),
        release,
      ),
      /exact production recovery receipt/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        recoveryStoreBody(Buffer.from("wrong-private-receipt"), {
          binding: "PRODUCTION_INFRASTRUCTURE_RECEIPT",
        }),
        release,
      ),
      /exact production recovery receipt/,
    );
  } finally {
    database.close();
  }
});

async function activeProductionReleaseCandidate() {
  const database = await migratedDatabase();
  seedExecution(database, {
    operation: "production-release",
    prerequisiteRequestId: bootstrapRequestId,
    requestId: releaseRequestId,
    runId: "8008",
    digest: "9".repeat(64),
  });
  const body = releaseCandidateStoreBody(
    Buffer.from("opaque-encrypted-production-release-candidate"),
  );
  const release = {
    operation: "production-release",
    requestId: releaseRequestId,
    runId: "8008",
    digest: "9".repeat(64),
  };
  const stored = await custody(database, ciphertextCustodyPaths.store, body, release);
  await custody(
    database,
    ciphertextCustodyPaths.confirm,
    {
      binding: body.binding,
      custodySha256: stored.custodySha256,
      decryptionProofSha256: "a".repeat(64),
      expectedCiphertextSha256: stored.ciphertextSha256,
      expectedPlaintextSha256: stored.plaintextSha256,
      releaseRequestBase64: body.releaseRequestBase64,
    },
    release,
  );
  database.prepare(
    `UPDATE dispatch_consumptions
        SET state = 'executed', execution_receipt_sha256 = ?, updated_at = ?
      WHERE request_id = ?`,
  ).run(prerequisiteReceiptSha256, now, releaseRequestId);
  return { body, database, stored };
}

function seedCutover(database, {
  prerequisiteRequestId = releaseRequestId,
  requestId = cutoverRequestId,
} = {}) {
  seedExecution(database, {
    operation: "production-cutover",
    prerequisiteRequestId,
    requestId,
    runId: "9009",
    digest: "b".repeat(64),
  });
}

const cutoverExecution = Object.freeze({
  operation: "production-cutover",
  requestId: cutoverRequestId,
  runId: "9009",
  digest: "b".repeat(64),
});

test("cutover resolves and reads only the active private receipt granted by its exact production-release prerequisite", async () => {
  const { body, database, stored } = await activeProductionReleaseCandidate();
  try {
    seedCutover(database);
    const resolved = await custody(
      database,
      ciphertextCustodyPaths.resolve,
      { binding: body.binding, releaseRequestBase64: "synthetic-production-cutover-request" },
      cutoverExecution,
    );
    assert.equal(resolved.binding, "PRODUCTION_RELEASE_CANDIDATE_RECEIPT");
    assert.equal(resolved.payloadKind, "private_receipt");
    assert.equal(resolved.custodySha256, stored.custodySha256);
    assert.equal(Object.hasOwn(resolved, "ciphertextBase64Url"), false);

    const read = await custody(
      database,
      ciphertextCustodyPaths.read,
      {
        binding: body.binding,
        expectedCiphertextSha256: resolved.ciphertextSha256,
        expectedPlaintextSha256: resolved.plaintextSha256,
        releaseRequestBase64: "synthetic-production-cutover-request",
      },
      cutoverExecution,
    );
    assert.equal(read.state, "active");
    assert.equal(read.custodySha256, stored.custodySha256);
    assert.equal(
      JSON.stringify({ read, resolved }).includes(
        "synthetic-private-production-release-candidate-receipt",
      ),
      false,
    );
    assert.equal(
      JSON.stringify(database.prepare("SELECT * FROM ciphertext_custody_objects").get()).includes(
        "synthetic-private-production-release-candidate-receipt",
      ),
      false,
    );
  } finally {
    database.close();
  }
});

test("cutover custody rejects cross-release, stale, wrong-receipt and binding-substitution access", async (t) => {
  await t.test("binding substitution", async () => {
    const { database } = await activeProductionReleaseCandidate();
    try {
      seedCutover(database);
      for (const binding of [
        "PRODUCTION_D1_INITIAL_RECOVERY",
        "PRODUCTION_INFRASTRUCTURE_RECEIPT",
        "RESEND_API_KEY",
      ]) {
        await assert.rejects(
          custody(
            database,
            ciphertextCustodyPaths.resolve,
            { binding, releaseRequestBase64: "synthetic-production-cutover-request" },
            cutoverExecution,
          ),
          /exact production-release candidate receipt/,
        );
      }
    } finally {
      database.close();
    }
  });

  await t.test("cross-release prerequisite", async () => {
    const { database } = await activeProductionReleaseCandidate();
    try {
      const otherReleaseRequestId = "44444444-4444-4444-8444-444444444444";
      seedExecution(database, {
        operation: "production-release",
        prerequisiteRequestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        requestId: otherReleaseRequestId,
        runId: "8118",
        digest: "c".repeat(64),
      });
      database.prepare(
        `UPDATE dispatch_consumptions
            SET state = 'executed', execution_receipt_sha256 = ?, updated_at = ?
          WHERE request_id = ?`,
      ).run(prerequisiteReceiptSha256, now, otherReleaseRequestId);
      seedCutover(database, { prerequisiteRequestId: otherReleaseRequestId });
      await assert.rejects(
        custody(
          database,
          ciphertextCustodyPaths.resolve,
          {
            binding: "PRODUCTION_RELEASE_CANDIDATE_RECEIPT",
            releaseRequestBase64: "synthetic-production-cutover-request",
          },
          cutoverExecution,
        ),
        /exact prerequisite/,
      );
    } finally {
      database.close();
    }
  });

  await t.test("wrong prerequisite receipt", async () => {
    const { database } = await activeProductionReleaseCandidate();
    try {
      seedCutover(database);
      database.prepare(
        "UPDATE dispatch_consumptions SET prerequisite_receipt_sha256 = ? WHERE request_id = ?",
      ).run("f".repeat(64), cutoverRequestId);
      await assert.rejects(
        custody(
          database,
          ciphertextCustodyPaths.resolve,
          {
            binding: "PRODUCTION_RELEASE_CANDIDATE_RECEIPT",
            releaseRequestBase64: "synthetic-production-cutover-request",
          },
          cutoverExecution,
        ),
        /exact prerequisite/,
      );
    } finally {
      database.close();
    }
  });

  await t.test("stale prerequisite", async () => {
    const { database } = await activeProductionReleaseCandidate();
    try {
      database.prepare("UPDATE dispatch_consumptions SET updated_at = ? WHERE request_id = ?").run(
        now - 24 * 60 * 60 * 1000 - 1,
        releaseRequestId,
      );
      seedCutover(database);
      await assert.rejects(
        custody(
          database,
          ciphertextCustodyPaths.resolve,
          {
            binding: "PRODUCTION_RELEASE_CANDIDATE_RECEIPT",
            releaseRequestBase64: "synthetic-production-cutover-request",
          },
          cutoverExecution,
        ),
        /exact prerequisite/,
      );
    } finally {
      database.close();
    }
  });
});

test("only production release can create the cutover candidate receipt", async () => {
  const database = await migratedDatabase();
  try {
    seedExecution(database);
    const body = releaseCandidateStoreBody(Buffer.from("forbidden-bootstrap-candidate"), {
      context: {
        applicationCommitSha: sourceSha,
        brokerRequestId: bootstrapRequestId,
        capsuleRequestSha256,
        controllerCommitSha: controllerSha,
      },
    });
    await assert.rejects(
      custody(database, ciphertextCustodyPaths.store, body),
      /exact production recovery receipt or candidate receipt/,
    );
  } finally {
    database.close();
  }
});

test("tampering, wrong release identity, and unallowlisted bindings fail closed", async () => {
  const database = await migratedDatabase();
  try {
    seedExecution(database);
    const ciphertext = Buffer.from("encrypted-adversarial-payload");
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        storeBody(ciphertext, { ciphertextSha256: "f".repeat(64) }),
      ),
      /ciphertext digest differs/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        storeBody(ciphertext, { encryptionKeySha256: "e".repeat(64) }),
      ),
      /encryption key differs/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        storeBody(ciphertext, { context: context({ applicationCommitSha: "f".repeat(40) }) }),
      ),
      /context differs/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        storeBody(ciphertext, { binding: "UNBOUNDED_PROVIDER_SECRET" }),
      ),
      /exact allowlist/,
    );
    await assert.rejects(
      custody(
        database,
        ciphertextCustodyPaths.store,
        storeBody(ciphertext),
        { operation: "production-release" },
      ),
      /exact production recovery receipt/,
    );
  } finally {
    database.close();
  }
});

test("revocation zeroes ciphertext while retaining non-secret audit digests", async () => {
  const database = await migratedDatabase();
  try {
    seedExecution(database);
    const body = storeBody(Buffer.from("encrypted-secret-to-revoke"));
    const stored = await custody(database, ciphertextCustodyPaths.store, body);
    const revoked = await custody(database, ciphertextCustodyPaths.revoke, {
      binding: body.binding,
      custodySha256: stored.custodySha256,
      expectedCiphertextSha256: stored.ciphertextSha256,
      expectedPlaintextSha256: stored.plaintextSha256,
      releaseRequestBase64: body.releaseRequestBase64,
    });
    assert.deepEqual(revoked, { custodySha256: stored.custodySha256, revoked: true });
    const row = database.prepare("SELECT * FROM ciphertext_custody_objects").get();
    assert.equal(row.state, "revoked");
    assert.equal(row.ciphertext_base64url, null);
    assert.equal(row.ciphertext_sha256, stored.ciphertextSha256);
    await assert.rejects(
      custody(database, ciphertextCustodyPaths.read, {
        binding: body.binding,
        expectedCiphertextSha256: stored.ciphertextSha256,
        expectedPlaintextSha256: stored.plaintextSha256,
        releaseRequestBase64: body.releaseRequestBase64,
      }),
      /exact approved object/,
    );
  } finally {
    database.close();
  }
});

test("public custody routes require the exact protected-executor OIDC identity", async () => {
  const database = await migratedDatabase();
  try {
    const release = executorReleaseRequest();
    const canonical = canonicalJson(release);
    const digest = sha256(Buffer.from(canonical));
    seedExecution(database, { digest });
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" });
    Object.assign(jwk, { alg: "RS256", kid: "custody-key", use: "sig" });
    const fetcher = async (url) => {
      if (String(url).endsWith("/.well-known/openid-configuration")) {
        return Response.json({
          issuer: "https://token.actions.githubusercontent.com",
          jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks",
        });
      }
      if (String(url).endsWith("/.well-known/jwks")) {
        return Response.json({ keys: [jwk] });
      }
      throw new Error("unexpected network request");
    };
    const releaseRequestBase64 = Buffer.from(canonical).toString("base64url");
    const body = {
      binding: "RESEND_API_KEY",
      context: context(),
      payloadKind: "secret",
      releaseRequestBase64,
    };
    const environment = {
      ...dispatcherEnvironment,
      DISPATCH_STATE: new SqliteD1(database),
    };
    const valid = await handleDispatch(
      new Request("https://dispatcher.example/v1/custody/inspect", {
        method: "POST",
        headers: {
          authorization: `Bearer ${signedJwt(privateKey, executorClaims())}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      }),
      environment,
      fetcher,
      now,
    );
    assert.equal(valid.status, 202);
    assert.equal((await valid.json()).present, false);

    const substituted = await handleDispatch(
      new Request("https://dispatcher.example/v1/custody/inspect", {
        method: "POST",
        headers: {
          authorization: `Bearer ${signedJwt(
            privateKey,
            executorClaims({ environment: "canary" }),
          )}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      }),
      environment,
      fetcher,
      now,
    );
    assert.equal(substituted.status, 401);
    assert.deepEqual(await substituted.json(), { error: "dispatch_rejected" });
  } finally {
    database.close();
  }
});
