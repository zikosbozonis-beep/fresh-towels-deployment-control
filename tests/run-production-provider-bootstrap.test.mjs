import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  createGitHubOidcTokenProvider,
  deriveTrustedProductionBootstrapInput,
  persistProductionBootstrapEvidence,
  ProductionBootstrapRunnerError,
  runTrustedProductionProviderBootstrap,
  validateHashOnlyProductionBootstrapEvidence,
  validateProtectedBootstrapEnvironment,
} from "../scripts/run-production-provider-bootstrap.mjs";

const fixedNow = new Date("2026-09-01T17:00:00.000Z");
const requestId = "55555555-5555-4555-8555-555555555555";
const adminIdentity = "owner-admin@example.net";
const applicationSha = "2".repeat(40);
const controllerSha = "3".repeat(40);

function digest(value) {
  return sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function targets() {
  return {
    cloudflare: {
      accountId: "a".repeat(32),
      zone: { id: "b".repeat(32), name: "freshtowels.gr", type: "full" },
      workerName: "fresh-towels-production",
      workersDevSubdomain: null,
      d1: {
        jurisdiction: "eu",
        primary: {
          id: "11111111-1111-4111-8111-111111111111",
          name: "fresh-towels-leads-prod",
        },
        recovery: {
          id: "22222222-2222-4222-8222-222222222222",
          name: "fresh-towels-leads-prod-recovery",
        },
      },
      access: {
        organization: { name: "Fresh Towels", teamDomain: null, sessionDuration: "8h" },
        identityProvider: {
          id: "66666666-6666-4666-8666-666666666666",
          name: "Fresh Towels owner OTP",
          type: "onetimepin",
        },
        application: {
          id: "33333333-3333-4333-8333-333333333333",
          name: "Fresh Towels Leads",
          domain: "freshtowels.gr/internal/leads",
          destinations: [
            { type: "public", uri: "freshtowels.gr/api/internal/*" },
            { type: "public", uri: "freshtowels.gr/internal/leads" },
            { type: "public", uri: "freshtowels.gr/internal/leads/*" },
          ],
          type: "self_hosted",
          sessionDuration: "8h",
          httpOnlyCookieAttribute: true,
          sameSiteCookieAttribute: "strict",
          enableBindingCookie: true,
          pathCookieAttribute: false,
          allowIframe: false,
          allowAuthenticateViaWarp: false,
          skipInterstitial: false,
          optionsPreflightBypass: false,
          appLauncherVisible: false,
          autoRedirectToIdentity: true,
        },
        policy: {
          id: "44444444-4444-4444-8444-444444444444",
          name: "Fresh Towels owner access",
          decision: "allow",
          precedence: 1,
          adminIdentitySha256: sha256(Buffer.from(adminIdentity)),
        },
      },
    },
    resend: {
      domain: { id: "domain_123", name: "notify.freshtowels.gr", region: "eu-west-1" },
      senderAddress: "notifications@notify.freshtowels.gr",
      webhook: {
        id: "webhook_123",
        endpoint: "https://freshtowels.gr/api/webhooks/resend",
        events: ["email.sent", "email.delivered", "email.bounced", "email.complained", "email.delivery_delayed", "email.failed", "email.suppressed"],
        secretBinding: "RESEND_WEBHOOK_SECRET",
      },
      sendingKey: {
        id: "key_123",
        name: "Fresh Towels Production Worker",
        permission: "sending_access",
        secretBinding: "RESEND_API_KEY",
      },
    },
  };
}

function capsule() {
  const value = {
    application: {
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1350923567",
      ref: "refs/heads/main",
      commitSha: applicationSha,
      workflowRef:
        "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
      workflowSha: applicationSha,
      runId: "39000000001",
      runAttempt: 1,
    },
    bootstrap: {
      requestId: "0".repeat(64),
      intent: "provision-production-identities-and-issue-credential-free-receipt",
      dnsStage: {
        requestId: "77777777-7777-4777-8777-777777777777",
        receiptSha256: "8".repeat(64),
        runId: "33524593667",
      },
      stableEvidence: {
        redirectCandidateEvidenceSha256: "9".repeat(64),
        privacyOperationsEvidenceSha256: "a".repeat(64),
        legacyWordPressRecoveryEvidenceSha256: "b".repeat(64),
      },
      targets: targets(),
      safeguards: {
        credentialsPresent: false,
        applicationBuildAuthorized: false,
        applicationArtifactPresent: false,
        productionTrafficMutationAuthorized: false,
        productionDnsMutationAuthorized: false,
        providerBootstrapMutationAuthorized: true,
      },
    },
    capsuleType: "fresh-towels-production-bootstrap-capsule",
    controller: {
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      commitSha: controllerSha,
      workflowRef:
        "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@" +
        controllerSha,
    },
    createdAt: "2026-09-01T16:59:00.000Z",
    operation: "production-bootstrap",
    schemaVersion: 1,
    validUntil: "2026-09-01T18:59:00.000Z",
  };
  value.bootstrap.requestId = digest({
    createdAt: value.createdAt,
    application: value.application,
    controller: value.controller,
    dnsStage: value.bootstrap.dnsStage,
    stableEvidence: value.bootstrap.stableEvidence,
    targets: value.bootstrap.targets,
  });
  return value;
}

function releaseRequest(capsuleBytes) {
  return {
    schema: "deployment-control/release-request/v1",
    requestId,
    nonce: "n".repeat(43),
    issuedAt: "2026-09-01T16:59:30.000Z",
    expiresAt: "2026-09-01T17:29:30.000Z",
    operation: "production-bootstrap",
    source: {
      repositoryId: "1350923567",
      commitSha: applicationSha,
      workflowRunId: "39000000001",
      workflowRunAttempt: 1,
    },
    controller: { repositoryId: "1353294568", commitSha: controllerSha },
    artifact: {
      releaseId: "39000000001",
      transportTag: `deployment-control/${requestId}`,
      transportCommitSha: "4".repeat(40),
      ciphertextBlobSha1: "5".repeat(40),
      manifestBlobSha1: "6".repeat(40),
      ciphertextSha256: "7".repeat(64),
      plaintextSha256: sha256(capsuleBytes),
      plaintextBytes: capsuleBytes.byteLength,
      encryptionKeySha256: "8".repeat(64),
    },
    evidence: {
      immutableRelease: true,
      manifestSha256: "9".repeat(64),
      oidcTokenSha256: "a".repeat(64),
    },
  };
}

function trustedInput(overrides = {}) {
  const capsuleValue = overrides.capsule ?? capsule();
  const capsuleBytes = overrides.capsuleBytes ?? Buffer.from(`${canonicalJson(capsuleValue)}\n`);
  const request = overrides.request ?? releaseRequest(capsuleBytes);
  const encodedRequest =
    overrides.encodedRequest ?? Buffer.from(canonicalJson(request)).toString("base64url");
  return deriveTrustedProductionBootstrapInput({
    adminIdentity,
    capsuleBytes,
    encodedRequest,
    expectedBrokerRequestId: requestId,
    expectedCapsuleRequestSha256: capsuleValue.bootstrap.requestId,
    expectedControllerSha: controllerSha,
    githubRunId: "40000000001",
    protectedExecutionRunId: "40000000001",
    now: fixedNow,
    ...overrides.input,
  });
}

function evidence(trusted) {
  const body = {
    schema: "deployment-control/production-provider-bootstrap-evidence/v1",
    operation: "production-bootstrap",
    requestId: trusted.releaseRequest.requestId,
    capsuleRequestSha256: trusted.protectedExecution.capsuleRequestSha256,
    applicationCommitSha: trusted.releaseRequest.source.commitSha,
    controllerCommitSha: trusted.releaseRequest.controller.commitSha,
    applicationRunId: trusted.releaseRequest.source.workflowRunId,
    applicationRunAttempt: trusted.releaseRequest.source.workflowRunAttempt,
    protectedExecutionRunId: trusted.protectedExecution.runId,
    capsuleSha256: trusted.expectedCapsuleSha256,
    privateReceiptSha256: "b".repeat(64),
    encryptedCustodyProofSha256: "c".repeat(64),
    providerStateSha256: "d".repeat(64),
    wordpressFallbackSha256: "e".repeat(64),
    result: "verified",
    completedAt: "2026-09-01T17:01:00.000Z",
  };
  return { ...body, receiptSha256: digest(body) };
}

test("derives a canonical production-bootstrap input bound to the release request and protected run", () => {
  const trusted = trustedInput();
  assert.equal(trusted.releaseRequest.requestId, requestId);
  assert.equal(trusted.protectedExecution.brokerRequestId, requestId);
  assert.equal(trusted.protectedExecution.runId, "40000000001");
  assert.equal(trusted.expectedCapsuleSha256, sha256(trusted.capsuleBytes));
});

test("rejects semantically equivalent but non-canonical release-request bytes", () => {
  const value = capsule();
  const capsuleBytes = Buffer.from(`${canonicalJson(value)}\n`);
  const request = releaseRequest(capsuleBytes);
  assert.throws(
    () =>
      trustedInput({
        capsule: value,
        capsuleBytes,
        encodedRequest: Buffer.from(JSON.stringify(request, null, 2)).toString("base64url"),
      }),
    (error) =>
      error instanceof ProductionBootstrapRunnerError &&
      error.code === "release-request-canonicalization",
  );
});

test("rejects protected execution substitution before provider dependencies are constructed", () => {
  assert.throws(
    () => trustedInput({ input: { protectedExecutionRunId: "40000000002" } }),
    (error) =>
      error instanceof ProductionBootstrapRunnerError &&
      error.code === "protected-execution-provenance",
  );
  assert.throws(
    () =>
      trustedInput({
        input: { expectedBrokerRequestId: "99999999-9999-4999-8999-999999999999" },
      }),
    /protected-execution-provenance/,
  );
});

test("rejects any capsule byte or release identity substitution", () => {
  const value = capsule();
  const bytes = Buffer.from(`${canonicalJson(value)}\n `);
  assert.throws(() => trustedInput({ capsule: value, capsuleBytes: bytes }), /canonicalization/);

  const exactBytes = Buffer.from(`${canonicalJson(value)}\n`);
  const request = releaseRequest(exactBytes);
  request.source.commitSha = "f".repeat(40);
  assert.throws(
    () => trustedInput({ capsule: value, capsuleBytes: exactBytes, request }),
    /bootstrap-release-request-substitution/,
  );
});

test("accepts only canonical hash-only evidence and writes the receipt digest to GITHUB_OUTPUT", async () => {
  const trusted = trustedInput();
  const receipt = evidence(trusted);
  assert.equal(validateHashOnlyProductionBootstrapEvidence(receipt, trusted), true);
  const root = await mkdtemp(join(tmpdir(), "bootstrap-runner-test-"));
  try {
    const output = join(root, "receipt.json");
    const githubOutput = join(root, "github-output.txt");
    await writeFile(githubOutput, "existing=safe\n", "utf8");
    await persistProductionBootstrapEvidence({
      evidence: receipt,
      githubOutput,
      outputPath: output,
      trusted,
    });
    assert.equal(await readFile(output, "utf8"), `${canonicalJson(receipt)}\n`);
    assert.equal(
      await readFile(githubOutput, "utf8"),
      `existing=safe\nreceipt_sha256=${receipt.receiptSha256}\n`,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects provider identifiers or any other additional public evidence field", () => {
  const trusted = trustedInput();
  assert.throws(
    () =>
      validateHashOnlyProductionBootstrapEvidence(
        { ...evidence(trusted), cloudflareZoneId: "not-public" },
        trusted,
      ),
    /bootstrap-evidence-shape/,
  );
  const late = evidence(trusted);
  late.completedAt = trusted.capsule.validUntil;
  const { receiptSha256: _ignored, ...lateBody } = late;
  late.receiptSha256 = digest(lateBody);
  assert.throws(
    () => validateHashOnlyProductionBootstrapEvidence(late, trusted),
    /bootstrap-evidence-binding/,
  );
});

test("binds execution to the protected main workflow SHA and exact GitHub run", () => {
  const environment = {
    GITHUB_ACTIONS: "true",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_PROTECTED: "true",
    GITHUB_REPOSITORY: "zikosbozonis-beep/fresh-towels-deployment-control",
    GITHUB_REPOSITORY_ID: "1353294568",
    GITHUB_RUN_ATTEMPT: "1",
    GITHUB_RUN_ID: "40000000001",
    GITHUB_SHA: controllerSha,
    GITHUB_WORKFLOW_REF:
      "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/execute-release.yml@refs/heads/main",
    GITHUB_WORKFLOW_SHA: controllerSha,
  };
  assert.deepEqual(validateProtectedBootstrapEnvironment(environment), {
    controllerSha,
    runAttempt: 1,
    runId: "40000000001",
  });
  assert.throws(
    () =>
      validateProtectedBootstrapEnvironment({
        ...environment,
        GITHUB_WORKFLOW_SHA: "f".repeat(40),
      }),
    /protected-execution-environment/,
  );
  assert.throws(
    () =>
      validateProtectedBootstrapEnvironment({
        ...environment,
        GITHUB_REF_PROTECTED: "false",
      }),
    /protected-execution-environment/,
  );
});

test("passes only trusted bindings and injectable protected sinks to the bootstrap core", async () => {
  const trusted = trustedInput();
  const expected = evidence(trusted);
  const cloudflareClient = { request() {} };
  const resendClient = { request() {} };
  const resendRuntimeClientFactory = () => ({ request() {} });
  const secretSink = { inspect() {}, store() {} };
  const privateReceiptSink = { store() {} };
  const dnsStageReceiptBytes = Buffer.from("synthetic-dns-stage-receipt");
  let observed;
  const actual = await runTrustedProductionProviderBootstrap({
    cloudflareClient,
    executeBootstrap: async (input) => {
      observed = input;
      return expected;
    },
    dnsStageReceiptBytes,
    privateReceiptSink,
    resendClient,
    resendRuntimeClientFactory,
    secretSink,
    trusted,
  });
  assert.equal(actual, expected);
  assert.equal(observed.adminIdentity, adminIdentity);
  assert.equal(observed.cloudflareClient, cloudflareClient);
  assert.equal(observed.resendClient, resendClient);
  assert.equal(observed.resendRuntimeClientFactory, resendRuntimeClientFactory);
  assert.equal(observed.secretSink, secretSink);
  assert.equal(observed.privateReceiptSink, privateReceiptSink);
  assert.equal(observed.dnsStageReceiptBytes, dnsStageReceiptBytes);
  assert.deepEqual(observed.protectedExecution, trusted.protectedExecution);
});

test("requests a fresh GitHub OIDC token only from the pinned Actions origin and audience", async () => {
  let observed;
  const jwt = `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`;
  const getToken = createGitHubOidcTokenProvider({
    requestToken: "request-token-that-is-not-printed",
    requestUrl:
      "https://pipelines.actions.githubusercontent.com/_apis/distributedtask/hubs/build/plans/plan/jobs/job/idtoken?api-version=2.0",
    fetcher: async (url, options) => {
      observed = { url: String(url), options };
      return new Response(JSON.stringify({ count: 1, value: jwt }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  assert.equal(await getToken(), jwt);
  const url = new URL(observed.url);
  assert.equal(url.hostname, "pipelines.actions.githubusercontent.com");
  assert.equal(url.searchParams.get("audience"), "deployment-control-executor-v1");
  assert.equal(observed.options.redirect, "error");
  assert.equal(observed.options.headers.authorization, "Bearer request-token-that-is-not-printed");
});

test("rejects an attacker-controlled OIDC origin and a malformed success envelope", async () => {
  assert.throws(
    () =>
      createGitHubOidcTokenProvider({
        requestToken: "request-token-that-is-not-printed",
        requestUrl: "https://example.net/idtoken",
      }),
    /oidc-request-boundary/,
  );
  assert.throws(
    () =>
      createGitHubOidcTokenProvider({
        requestToken: "request-token-that-is-not-printed",
        requestUrl:
          "https://attacker.actions.githubusercontent.com/_apis/distributedtask/hubs/build/plans/plan/jobs/job/idtoken?api-version=2.0",
      }),
    /oidc-request-boundary/,
  );
  const getToken = createGitHubOidcTokenProvider({
    requestToken: "request-token-that-is-not-printed",
    requestUrl:
      "https://pipelines.actions.githubusercontent.com/_apis/distributedtask/hubs/build/plans/plan/jobs/job/idtoken?api-version=2.0",
    fetcher: async () => new Response(JSON.stringify({ value: "x.y.z" })),
  });
  await assert.rejects(() => getToken(), /oidc-token-response/);
});

test("CLI failure reporting is code-only and never interpolates provider or secret errors", async () => {
  const source = await readFile(
    new URL("../scripts/run-production-provider-bootstrap.mjs", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /console\.(?:error|log)\([^\n]*error\.message/);
  assert.doesNotMatch(source, /console\.(?:error|log)\([^\n]*(?:TOKEN|PASSPHRASE|PRIVATE_KEY)/);
  assert.match(source, /Production provider Bootstrap stopped: \$\{safeFailureCode\(error\)\}/);
  assert.match(
    source,
    /resendRuntimeClientFactory:\s*\(token\)\s*=>\s*\n\s*createResendHttpAdapter\(\{ fetchImpl: fetcher, token \}\)/,
  );
});
