import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  assertDisposableProviderCanaryName,
  deriveTrustedProviderCanaryInput,
  deriveProviderCanaryResourceName,
  ProviderCanaryError,
  persistProviderCanaryReceipt,
  runProviderCanary,
  validateProviderCanaryReceipt,
} from "../scripts/provider-canary.mjs";
import {
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "../scripts/provider-adapter.mjs";

const accountId = "0123456789abcdef".repeat(2);
const targetDomain = "notify.freshtowels.gr";
const databaseId = "11111111-1111-4111-8111-111111111111";
const versionId = "22222222-2222-4222-8222-222222222222";
const workerId = "33333333333333333333333333333333";
const providerEtag = "4".repeat(64);

function trustedProviderCanaryFixture() {
  const createdAt = "2026-09-01T17:00:00.000Z";
  const application = {
    repository: "zikosbozonis-beep/fresh-towels-website",
    repositoryId: "1001",
    ref: "refs/heads/main",
    commitSha: "b".repeat(40),
    workflowRef:
      "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
    workflowSha: "b".repeat(40),
    runId: "5005",
    runAttempt: 1,
  };
  const controller = {
    repository: "zikosbozonis-beep/fresh-towels-deployment-control",
    commitSha: "c".repeat(40),
    workflowRef:
      `zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@${"c".repeat(40)}`,
  };
  const safeguards = {
    cleanupRequired: true,
    productionAccessMutationAuthorized: false,
    productionD1MutationAuthorized: false,
    productionDnsMutationAuthorized: false,
    productionEmailAuthorized: false,
    productionTrafficMutationAuthorized: false,
  };
  const targets = {
    cloudflare: { accountId, jurisdiction: "eu" },
    resend: { domain: targetDomain, mutationAuthorized: false },
  };
  const canaryId = sha256(
    Buffer.from(
      canonicalJson({
        applicationCommitSha: application.commitSha,
        controllerCommitSha: controller.commitSha,
        createdAt,
        runAttempt: "1",
        runId: application.runId,
        safeguards,
        targets,
      }),
    ),
  );
  const capsule = {
    application,
    capsuleType: "fresh-towels-provider-canary-capsule",
    controller,
    createdAt,
    operation: "provider-canary",
    providerCanary: {
      canaryId,
      intent: "verify-real-provider-adapter-on-disposable-non-production-resources",
      safeguards,
      targets,
    },
    schemaVersion: 1,
    validUntil: "2026-09-01T19:00:00.000Z",
  };
  const capsuleBytes = Buffer.from(`${canonicalJson(capsule)}\n`);
  const request = {
    artifact: {
      ciphertextBlobSha1: "4".repeat(40),
      ciphertextSha256: "d".repeat(64),
      encryptionKeySha256: "5".repeat(64),
      manifestBlobSha1: "6".repeat(40),
      plaintextBytes: capsuleBytes.byteLength,
      plaintextSha256: sha256(capsuleBytes),
      releaseId: "6006",
      transportCommitSha: "7".repeat(40),
      transportTag: "deployment-control/33333333-3333-4333-8333-333333333333",
    },
    controller: { commitSha: controller.commitSha, repositoryId: "2002" },
    evidence: {
      immutableRelease: true,
      manifestSha256: "0".repeat(64),
      oidcTokenSha256: "8".repeat(64),
    },
    expiresAt: "2026-09-01T17:15:00.000Z",
    issuedAt: createdAt,
    nonce: "A".repeat(43),
    operation: "provider-canary",
    requestId: "33333333-3333-4333-8333-333333333333",
    schema: "deployment-control/release-request/v1",
    source: {
      commitSha: application.commitSha,
      repositoryId: application.repositoryId,
      workflowRunAttempt: application.runAttempt,
      workflowRunId: application.runId,
    },
  };
  return {
    capsule,
    capsuleBytes,
    encodedRequest: Buffer.from(canonicalJson(request)).toString("base64url"),
  };
}

function release(overrides = {}) {
  return {
    requestId: "33333333-3333-4333-8333-333333333333",
    releaseId: "a".repeat(64),
    applicationCommitSha: "b".repeat(40),
    controllerCommitSha: "c".repeat(40),
    artifactSha256: "d".repeat(64),
    plaintextSha256: "e".repeat(64),
    uploadArtifactSha256: "f".repeat(64),
    evidenceSha256: "0".repeat(64),
    ...overrides,
  };
}

function providerResponse(provider, result, sequence) {
  return {
    provider,
    providerRequestId: `request-${sequence}`,
    status: 200,
    result,
    pagination: { complete: true },
    responseSha256: sha256(Buffer.from(`${provider}:${sequence}`)),
  };
}

function cloudflareFixture(options = {}) {
  const state = {
    database: options.preexistingDatabase
      ? { jurisdiction: "eu", name: options.preexistingDatabase, uuid: databaseId }
      : null,
    worker: options.preexistingWorker
      ? { id: workerId, name: options.preexistingWorker, versionId: null }
      : null,
    sequence: 0,
    calls: [],
  };
  const client = {
    async request(input) {
      state.calls.push(input);
      state.sequence += 1;
      const respond = (result, pagination) => ({
        ...providerResponse("cloudflare", result, state.sequence),
        ...(pagination ? { pagination } : {}),
      });
      if (input.path === `/accounts/${accountId}` && input.method === "GET") {
        return respond({ id: options.wrongAccount ?? accountId, name: "Account" });
      }
      if (input.path === `/accounts/${accountId}/d1/database` && input.method === "GET") {
        return respond(
          state.database === null ? [] : [state.database],
          { complete: options.incompleteD1Pagination !== true },
        );
      }
      if (input.path === `/accounts/${accountId}/d1/database` && input.method === "POST") {
        const createdId = options.substituteD1Create ? "44444444-4444-4444-8444-444444444444" : databaseId;
        state.database = { jurisdiction: "eu", name: input.body.name, uuid: databaseId };
        if (options.ambiguousD1Create) {
          throw new ProviderTransportAmbiguousError("synthetic-create-timeout");
        }
        return respond({ ...state.database, uuid: createdId });
      }
      const databaseGet = input.path.match(
        new RegExp(`^/accounts/${accountId}/d1/database/([a-f0-9-]{36})$`),
      );
      if (databaseGet && input.method === "GET") {
        if (state.database === null || state.database.uuid !== databaseGet[1]) {
          throw new ProviderRejectedError(404);
        }
        return respond(state.database);
      }
      if (
        input.path === `/accounts/${accountId}/d1/database/${databaseId}/query` &&
        input.method === "POST"
      ) {
        return respond([{ success: true, results: [{ provider_canary_value: 1 }] }]);
      }
      if (
        input.path === `/accounts/${accountId}/d1/database/${databaseId}` &&
        input.method === "DELETE"
      ) {
        if (!options.retainD1OnDelete) state.database = null;
        if (options.ambiguousD1Delete) {
          throw new ProviderTransportAmbiguousError("synthetic-delete-timeout");
        }
        return respond({});
      }
      const versionsPath = /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/([^/]+)\/versions$/;
      const versionDetailPath = /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/([^/]+)\/versions\/([a-f0-9-]{36})$/;
      const settingsPath = /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/([^/]+)\/settings$/;
      const workerCollectionPath = new RegExp(`^/accounts/${accountId}/workers/workers$`);
      const workerDetailPath = new RegExp(
        `^/accounts/${accountId}/workers/workers/([a-z0-9-]+)$`,
      );
      const workerEnvelope = () => ({
        id: options.substituteWorkerContainerId ? "4".repeat(32) : state.worker.id,
        name: options.substituteWorkerContainerName ? "ft-provider-canary-substituted" : state.worker.name,
        deployed_on: options.workerContainerDeployed
          ? "2026-09-01T17:00:00.000Z"
          : null,
        subdomain: {
          enabled: options.workerSubdomainEnabled ?? false,
          previews_enabled: options.workerPreviewsEnabled ?? false,
          preview_url_suffix: `-${state.worker.name}.example.workers.dev`,
          url: `https://${state.worker.name}.example.workers.dev`,
        },
        tags: options.substituteWorkerTags
          ? ["unexpected"]
          : ["fresh-towels-provider-canary"],
      });
      const versionEnvelope = ({ detail = false } = {}) => ({
        annotations: {
          "workers/message": options.substituteWorkerAnnotations
            ? "provider-canary:substituted"
            : `provider-canary:${release().applicationCommitSha}:${sha256(
                Buffer.from(
                  'export default { fetch() { return new Response("provider-canary"); } };\n',
                  "utf8",
                ),
              )}`,
          "workers/tag": release().releaseId.slice(0, 32),
          "workers/triggered_by": "upload",
        },
        id: versionId,
        resources: {
          bindings: [],
          script: {
            etag: detail && options.substituteWorkerContent ? "0".repeat(64) : providerEtag,
          },
          script_runtime: {
            compatibility_date: options.substituteWorkerCompatibilityDate
              ? "2026-08-30"
              : "2026-08-31",
          },
        },
      });
      let match = input.path.match(workerCollectionPath);
      if (match && input.method === "POST") {
        state.worker = { id: workerId, name: input.body.name, versionId: null };
        if (options.ambiguousWorkerContainerCreate) {
          throw new ProviderTransportAmbiguousError("synthetic-worker-container-create-timeout");
        }
        return respond(workerEnvelope());
      }
      match = input.path.match(workerDetailPath);
      if (match && input.method === "GET") {
        if (
          state.worker === null ||
          ![state.worker.id, state.worker.name].includes(match[1])
        ) {
          throw new ProviderRejectedError(404);
        }
        return respond(workerEnvelope());
      }
      if (match && input.method === "DELETE") {
        if (
          state.worker === null ||
          ![state.worker.id, state.worker.name].includes(match[1])
        ) {
          throw new ProviderRejectedError(404);
        }
        if (!options.retainWorkerOnDelete) state.worker = null;
        if (options.ambiguousWorkerDelete) {
          throw new ProviderTransportAmbiguousError("synthetic-worker-delete-timeout");
        }
        return respond({});
      }
      match = input.path.match(versionsPath);
      if (match && input.method === "GET") {
        if (state.worker === null || state.worker.name !== match[1]) {
          throw new ProviderRejectedError(404);
        }
        return respond({ items: [{ id: state.worker.versionId, metadata: {}, number: 1 }] });
      }
      if (match && input.method === "POST") {
        if (state.worker === null || state.worker.name !== match[1]) {
          throw new ProviderRejectedError(404);
        }
        state.worker.versionId = versionId;
        if (options.ambiguousWorkerCreate) {
          throw new ProviderTransportAmbiguousError("synthetic-worker-create-timeout");
        }
        return respond(versionEnvelope());
      }
      match = input.path.match(versionDetailPath);
      if (match && input.method === "GET") {
        if (
          state.worker === null ||
          state.worker.name !== match[1] ||
          state.worker.versionId !== match[2]
        ) {
          throw new ProviderRejectedError(404);
        }
        return respond({ ...versionEnvelope({ detail: true }), metadata: { source: "api" }, number: 1 });
      }
      match = input.path.match(settingsPath);
      if (match && input.method === "GET") {
        if (
          state.worker === null ||
          state.worker.name !== match[1] ||
          state.worker.versionId === null
        ) {
          throw new ProviderRejectedError(404);
        }
        const moduleSha256 = sha256(
          Buffer.from(
            'export default { fetch() { return new Response("provider-canary"); } };\n',
            "utf8",
          ),
        );
        return respond({
          annotations: {
            "workers/message": options.substituteWorkerAnnotations
              ? "provider-canary:substituted"
              : `provider-canary:${release().applicationCommitSha}:${moduleSha256}`,
            "workers/tag": release().releaseId.slice(0, 32),
          },
          bindings: [],
          compatibility_date: "2026-08-31",
          compatibility_flags: [],
        });
      }
      throw new Error(`unexpected synthetic Cloudflare request: ${input.method} ${input.path}`);
    },
  };
  return { client, state };
}

function resendFixture(options = {}) {
  let sequence = 0;
  const client = {
    calls: [],
    async request(input) {
      client.calls.push(input);
      sequence += 1;
      assert.equal(input.method, "GET");
      assert.equal(input.path, "/domains");
      if (options.error) throw options.error;
      const domainName = options.domainName ?? targetDomain;
      return providerResponse(
        "resend",
        {
          object: "list",
          has_more: options.hasMore ?? false,
          data: [
            {
              id: "55555555-5555-4555-8555-555555555555",
              name: domainName,
              status: options.domainStatus ?? "not_started",
              region: "eu-west-1",
              capabilities: {
                sending: options.sendingCapability ?? "enabled",
                receiving: "disabled",
              },
            },
          ],
        },
        sequence,
      );
    },
  };
  return client;
}

async function execute(options = {}) {
  const cf = cloudflareFixture(options.cloudflare);
  const boundRelease = release(options.release);
  const receipt = await runProviderCanary({
    release: boundRelease,
    expectedRelease: options.expectedRelease ?? boundRelease,
    expectedCloudflareAccountId: accountId,
    expectedResendDomain: targetDomain,
    cloudflareClient: cf.client,
    resendClient: resendFixture(options.resend),
    now: () => new Date("2026-09-01T17:00:00.000Z"),
  });
  return { cf, receipt };
}

test("provider Canary execution derives every target and release field from the validated signed capsule", () => {
  const fixture = trustedProviderCanaryFixture();
  const trusted = deriveTrustedProviderCanaryInput({
    capsuleBytes: fixture.capsuleBytes,
    encodedRequest: fixture.encodedRequest,
    expectedControllerRepositoryId: "2002",
    expectedControllerSha: "c".repeat(40),
    expectedSourceRepositoryId: "1001",
    now: new Date("2026-09-01T17:01:00.000Z"),
  });
  assert.equal(trusted.expectedCloudflareAccountId, accountId);
  assert.equal(trusted.expectedResendDomain, targetDomain);
  assert.equal(trusted.release.applicationCommitSha, "b".repeat(40));
  assert.equal(trusted.release.controllerCommitSha, "c".repeat(40));
  assert.equal(trusted.release.releaseId, fixture.capsule.providerCanary.canaryId);
  assert.equal(trusted.release.plaintextSha256, sha256(fixture.capsuleBytes));
});

test("provider Canary rejects capsule, digest, and controller substitutions before provider access", () => {
  const fixture = trustedProviderCanaryFixture();
  const changed = Buffer.from(fixture.capsuleBytes);
  changed[changed.byteLength - 2] ^= 1;
  assert.throws(
    () =>
      deriveTrustedProviderCanaryInput({
        capsuleBytes: changed,
        encodedRequest: fixture.encodedRequest,
        expectedControllerRepositoryId: "2002",
        expectedControllerSha: "c".repeat(40),
        expectedSourceRepositoryId: "1001",
        now: new Date("2026-09-01T17:01:00.000Z"),
      }),
    /trusted-provider-canary-binding/,
  );
  assert.throws(
    () =>
      deriveTrustedProviderCanaryInput({
        capsuleBytes: fixture.capsuleBytes,
        encodedRequest: fixture.encodedRequest,
        expectedControllerRepositoryId: "2002",
        expectedControllerSha: "9".repeat(40),
        expectedSourceRepositoryId: "1001",
        now: new Date("2026-09-01T17:01:00.000Z"),
      }),
    /trusted-provider-canary-binding/,
  );
});

test("provider Canary persists canonical evidence and emits the exact terminal receipt digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "provider-canary-receipt-"));
  try {
    const { receipt } = await execute();
    const outputPath = join(directory, "receipt.json");
    const githubOutput = join(directory, "github-output.txt");
    await persistProviderCanaryReceipt({
      outputPath,
      receipt,
      expectedRelease: release(),
      githubOutput,
    });
    assert.equal(await readFile(outputPath, "utf8"), `${canonicalJson(receipt)}\n`);
    assert.equal(
      await readFile(githubOutput, "utf8"),
      `receipt_sha256=${receipt.receiptSha256}\n`,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("bounded provider canary verifies account, creates/queries/deletes EU D1, verifies/deletes an undeployed Worker version, and reads Resend", async () => {
  const { cf, receipt } = await execute();
  assert.equal(validateProviderCanaryReceipt(receipt, release()), true);
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
  assert.ok(cf.state.calls.some((call) => call.method === "POST" && call.path.endsWith("/d1/database")));
  assert.ok(cf.state.calls.some((call) => call.method === "POST" && call.path.endsWith("/query")));
  const workerContainerCreateIndex = cf.state.calls.findIndex(
    (call) => call.method === "POST" && call.path.endsWith("/workers/workers"),
  );
  const workerVersionCreateIndex = cf.state.calls.findIndex(
    (call) => call.method === "POST" && call.path.endsWith("/versions"),
  );
  assert.ok(workerContainerCreateIndex >= 0);
  assert.ok(workerVersionCreateIndex > workerContainerCreateIndex);
  assert.deepEqual(cf.state.calls[workerContainerCreateIndex].body, {
    name: deriveProviderCanaryResourceName(release()),
    subdomain: { enabled: false, previews_enabled: false },
    tags: ["fresh-towels-provider-canary"],
  });
  assert.ok(cf.state.calls.some((call) => call.method === "POST" && call.path.endsWith("/versions")));
  const workerUpload = cf.state.calls.find(
    (call) => call.method === "POST" && call.path.endsWith("/versions"),
  );
  const workerUploadText = Buffer.from(workerUpload.bodyBytes).toString("utf8");
  assert.ok(workerUploadText.includes('"workers/message"'));
  assert.ok(workerUploadText.includes('"workers/tag"'));
  assert.ok(!workerUploadText.includes("workers/commit_sha"));
  assert.ok(
    !cf.state.calls.some((call) =>
      /dns_records|workers\/routes|deployments|\/subdomain$/.test(call.path),
    ),
  );
  assert.ok(Object.keys(receipt).filter((key) => key.includes("State")).every((key) => /^[a-f0-9]{64}$/.test(receipt[key])));
  assert.ok(!JSON.stringify(receipt).includes(targetDomain));
  assert.ok(!JSON.stringify(receipt).includes(accountId));
});

test("Cloudflare version upload cannot create a missing Worker parent", async () => {
  const cf = cloudflareFixture();
  await assert.rejects(
    cf.client.request({
      method: "POST",
      path: `/accounts/${accountId}/workers/scripts/${deriveProviderCanaryResourceName(release())}/versions`,
    }),
    (error) => error instanceof ProviderRejectedError && error.status === 404,
  );
  assert.equal(cf.state.worker, null);
});

test("Worker parent identity, deployment and subdomain drift fail closed and are cleaned", async () => {
  for (const cloudflare of [
    { substituteWorkerContainerName: true },
    { substituteWorkerTags: true },
    { workerContainerDeployed: true },
    { workerSubdomainEnabled: true },
    { workerPreviewsEnabled: true },
  ]) {
    const cf = cloudflareFixture(cloudflare);
    await assert.rejects(
      runProviderCanary({
        release: release(),
        expectedRelease: release(),
        expectedCloudflareAccountId: accountId,
        expectedResendDomain: targetDomain,
        cloudflareClient: cf.client,
        resendClient: resendFixture(),
      }),
      (error) =>
        error instanceof ProviderCanaryError &&
        ["worker-container-substitution", "disposable-cleanup-not-proven"].includes(error.code),
    );
    assert.ok(!cf.state.calls.some((call) => /dns_records|workers\/routes|deployments/.test(call.path)));
  }
});

test("Cloudflare authentication, scope, identity, network and response failures are provider-specific and never call Resend", async () => {
  const cases = [
    [new ProviderRejectedError(401), "cloudflare-auth-failed"],
    [new ProviderRejectedError(403), "cloudflare-scope-failed"],
    [new ProviderRejectedError(404), "cloudflare-resource-mismatch"],
    [new ProviderTransportAmbiguousError("network-or-timeout"), "cloudflare-network-failure"],
    [new Error("synthetic secret-bearing provider body"), "cloudflare-response-invalid"],
  ];
  for (const [providerError, expectedCode] of cases) {
    const resend = resendFixture();
    await assert.rejects(
      runProviderCanary({
        release: release(),
        expectedRelease: release(),
        expectedCloudflareAccountId: accountId,
        expectedResendDomain: targetDomain,
        cloudflareClient: { async request() { throw providerError; } },
        resendClient: resend,
      }),
      (error) =>
        error instanceof ProviderCanaryError &&
        error.code === expectedCode &&
        !error.message.includes("secret-bearing"),
    );
    assert.equal(resend.calls.length, 0);
  }
});

test("Resend authentication, scope, identity, network and response failures are provider-specific after Cloudflare cleanup", async () => {
  const cases = [
    [
      new ProviderRejectedError(401, { providerErrorCode: "invalid_api_key" }),
      "resend-auth-failed",
    ],
    [
      new ProviderRejectedError(403, { providerErrorCode: "restricted_api_key" }),
      "resend-scope-failed",
    ],
    [new ProviderRejectedError(404), "resend-resource-mismatch"],
    [new ProviderTransportAmbiguousError("network-or-timeout"), "resend-network-failure"],
    [new Error("synthetic secret-bearing provider body"), "resend-response-invalid"],
  ];
  for (const [providerError, expectedCode] of cases) {
    const cf = cloudflareFixture();
    const resend = resendFixture({ error: providerError });
    await assert.rejects(
      runProviderCanary({
        release: release(),
        expectedRelease: release(),
        expectedCloudflareAccountId: accountId,
        expectedResendDomain: targetDomain,
        cloudflareClient: cf.client,
        resendClient: resend,
      }),
      (error) =>
        error instanceof ProviderCanaryError &&
        error.code === expectedCode &&
        !error.message.includes("secret-bearing"),
    );
    assert.equal(resend.calls.length, 1);
    assert.equal(resend.calls[0].method, "GET");
    assert.equal(resend.calls[0].path, "/domains");
    assert.equal(cf.state.database, null);
    assert.equal(cf.state.worker, null);
  }
});

test("wrong Cloudflare account identity fails before any disposable mutation", async () => {
  const cf = cloudflareFixture({ wrongAccount: "9".repeat(32) });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "cloudflare-account-substitution",
  );
  assert.equal(cf.state.calls.length, 1);
});

test("incomplete D1 pagination fails before any disposable mutation", async () => {
  const cf = cloudflareFixture({ incompleteD1Pagination: true });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "d1-list-incomplete",
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("substituted Worker bytes fail the exact script hash and are cleaned", async () => {
  const cf = cloudflareFixture({ substituteWorkerContent: true });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) =>
      error instanceof ProviderCanaryError &&
      error.code === "worker-version-detail-substitution",
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("substituted Worker compatibility date fails closed and is cleaned", async () => {
  const cf = cloudflareFixture({ substituteWorkerCompatibilityDate: true });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) =>
      error instanceof ProviderCanaryError &&
      error.code === "worker-version-detail-substitution",
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("substituted Worker annotations fail closed and are cleaned", async () => {
  const cf = cloudflareFixture({ substituteWorkerAnnotations: true });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) =>
      error instanceof ProviderCanaryError &&
      error.code === "worker-version-detail-substitution",
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("Resend read canary records an exact transitional domain without claiming sending readiness", async () => {
  const cf = cloudflareFixture();
  const receipt = await runProviderCanary({
    release: release(),
    expectedRelease: release(),
    expectedCloudflareAccountId: accountId,
    expectedResendDomain: targetDomain,
    cloudflareClient: cf.client,
    resendClient: resendFixture({ sendingCapability: "disabled" }),
  });
  assert.match(receipt.resendDomainStateSha256, /^[a-f0-9]{64}$/);
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("Resend read canary rejects an unknown domain lifecycle state", async () => {
  const cf = cloudflareFixture();
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture({ domainStatus: "unexpected_state" }),
    }),
    (error) =>
      error instanceof ProviderCanaryError && error.code === "resend-domain-state-envelope",
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("resource names are exact release-derived disposable names and production-looking names are rejected", () => {
  assert.equal(
    deriveProviderCanaryResourceName(release()),
    `ft-provider-canary-${"a".repeat(12)}-${"c".repeat(7)}`,
  );
  assert.equal(assertDisposableProviderCanaryName(`ft-provider-canary-${"a".repeat(12)}-${"c".repeat(7)}`), true);
  for (const name of [
    "fresh-towels-prod",
    "fresh-towels-production",
    `ft-provider-canary-${"a".repeat(12)}-production`,
    `ft-provider-canary-${"a".repeat(12)}-${"c".repeat(6)}x-extra`,
  ]) {
    assert.throws(
      () => assertDisposableProviderCanaryName(name),
      (error) => error instanceof ProviderCanaryError && error.code === "unsafe-disposable-resource-name",
    );
  }
});

test("release/controller/artifact substitution is rejected before provider access", async () => {
  const cf = cloudflareFixture();
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release({ artifactSha256: "9".repeat(64) }),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "release-binding-substitution",
  );
  assert.equal(cf.state.calls.length, 0);
});

test("ambiguous create results are reconciled exactly once without blind retry", async () => {
  const { cf, receipt } = await execute({
    cloudflare: {
      ambiguousD1Create: true,
      ambiguousWorkerContainerCreate: true,
      ambiguousWorkerCreate: true,
    },
  });
  assert.equal(validateProviderCanaryReceipt(receipt, release()), true);
  assert.equal(
    cf.state.calls.filter((call) => call.method === "POST" && call.path.endsWith("/d1/database")).length,
    1,
  );
  assert.equal(
    cf.state.calls.filter(
      (call) => call.method === "POST" && call.path.endsWith("/workers/workers"),
    ).length,
    1,
  );
  assert.equal(
    cf.state.calls.filter((call) => call.method === "POST" && call.path.endsWith("/versions")).length,
    1,
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("ambiguous delete results pass only after authoritative absence is observed", async () => {
  const { cf, receipt } = await execute({
    cloudflare: { ambiguousD1Delete: true, ambiguousWorkerDelete: true },
  });
  assert.equal(validateProviderCanaryReceipt(receipt, release()), true);
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
  assert.equal(
    cf.state.calls.filter((call) => call.method === "DELETE" && call.path.includes("/d1/database/")).length,
    1,
  );
  assert.equal(
    cf.state.calls.filter((call) => call.method === "DELETE" && call.path.includes("/workers/workers/")).length,
    1,
  );
});

test("resource substitution is rejected and a created disposable D1 is still reconciled and cleaned", async () => {
  const cf = cloudflareFixture({ substituteD1Create: true });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "d1-create-substitution",
  );
  assert.equal(cf.state.database, null);
});

test("Resend target substitution fails closed after all disposable Cloudflare resources are cleaned", async () => {
  const cf = cloudflareFixture();
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture({ domainName: "unexpected.example" }),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "resend-domain-substitution",
  );
  assert.equal(cf.state.database, null);
  assert.equal(cf.state.worker, null);
});

test("a pre-existing same-name resource is treated as an ambiguous prior execution and is never mutated", async () => {
  const name = deriveProviderCanaryResourceName(release());
  const cf = cloudflareFixture({ preexistingDatabase: name });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "d1-previous-execution-ambiguous",
  );
  assert.equal(cf.state.database.name, name);
  assert.ok(!cf.state.calls.some((call) => call.method === "DELETE"));
});

test("cleanup failure overrides success and fails the canary closed", async () => {
  const cf = cloudflareFixture({ retainWorkerOnDelete: true });
  await assert.rejects(
    runProviderCanary({
      release: release(),
      expectedRelease: release(),
      expectedCloudflareAccountId: accountId,
      expectedResendDomain: targetDomain,
      cloudflareClient: cf.client,
      resendClient: resendFixture(),
    }),
    (error) => error instanceof ProviderCanaryError && error.code === "disposable-cleanup-not-proven",
  );
  assert.equal(cf.state.database, null);
  assert.notEqual(cf.state.worker, null);
});

test("receipt tampering is rejected and no provider credential-shaped value is present", async () => {
  const { receipt } = await execute();
  assert.throws(
    () => validateProviderCanaryReceipt({ ...receipt, d1DeletedStateSha256: "9".repeat(64) }, release()),
    (error) => error instanceof ProviderCanaryError && error.code === "provider-canary-receipt-binding",
  );
  const serialized = JSON.stringify(receipt);
  assert.ok(!serialized.includes("Bearer"));
  assert.ok(!serialized.includes("token"));
  assert.ok(!serialized.includes("@"));
});
