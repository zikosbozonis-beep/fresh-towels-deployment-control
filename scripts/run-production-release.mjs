#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateReleaseRequest,
} from "./control-contract.mjs";
import {
  createCiphertextCustodyBrokerClient,
  createGpgCiphertextCustodySinks,
} from "./ciphertext-custody-client.mjs";
import { materializeProductionCapsule } from "./production-capsule.mjs";
import {
  executeProductionReleaseAdapter,
  validateMaterializedRuntimeSecrets,
  validateProductionInfrastructureReceipt,
} from "./production-release-adapter.mjs";
import { createProductionWranglerAdapter } from "./production-wrangler-adapter.mjs";
import { executeProductionCandidateE2e } from "./production-candidate-e2e.mjs";
import { createProductionCandidateProviderAdapter } from "./production-candidate-provider-adapter.mjs";
import { createProductionReleaseCandidateReceipt } from "./production-release-candidate-receipt.mjs";
import { createCloudflareHttpAdapter, createResendHttpAdapter } from "./provider-adapter.mjs";
import { validateOperationPayload } from "./protected-transport.mjs";
import {
  createGitHubOidcTokenProvider,
  loadExactControllerIdentity,
  validateProtectedBootstrapEnvironment,
} from "./run-production-provider-bootstrap.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const expectedControllerRepositoryId = "1353294568";
const expectedSourceRepositoryId = "1350923567";
const expectedApplicationRepositoryId = expectedSourceRepositoryId;
const requiredBindings = Object.freeze([
  "DASHBOARD_AUTHORIZED_EMAILS",
  "LEAD_RATE_LIMIT_SECRET",
  "RESEND_API_KEY",
  "RESEND_WEBHOOK_SECRET",
]);

function required(environment, name, pattern, maximum = 4096) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\r\n\0]/.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    throw new Error("protected production release environment is incomplete");
  }
  return value;
}

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

function arguments_(args) {
  if (args.length !== 4 || args[0] !== "--capsule" || args[2] !== "--output") {
    throw new Error("production release arguments are invalid");
  }
  return { capsulePath: resolve(args[1]), outputPath: resolve(args[3]) };
}

async function verifyPrerequisite({ environment, getOidcToken, infrastructure, requestBase64, root }) {
  const jwtPath = resolve(root, "prerequisite-oidc.jwt");
  const token = await getOidcToken();
  await writeFile(jwtPath, token, { flag: "wx", mode: 0o400 });
  const result = spawnSync(
    process.execPath,
    [
      resolve("scripts/dispatch-controller.mjs"),
      resolve("controller-identity.json"),
      jwtPath,
      "verify-prerequisite",
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        PATH: environment.PATH ?? process.env.PATH,
        PREREQUISITE_RECEIPT_SHA256: infrastructure.receiptSha256,
        PREREQUISITE_REQUEST_ID: infrastructure.receipt.protectedExecution.brokerRequestId,
        PREREQUISITE_RUN_ID: infrastructure.receipt.protectedExecution.runId,
        RELEASE_REQUEST_BASE64: requestBase64,
      },
      maxBuffer: 512 * 1024,
      timeout: 60_000,
      windowsHide: true,
    },
  );
  await writeFile(jwtPath, Buffer.alloc(0), { flag: "w", mode: 0o400 }).catch(() => undefined);
  await rm(jwtPath, { force: true });
  if (result.status !== 0 || result.error) {
    throw new Error("exact production bootstrap prerequisite was not consumed");
  }
}

export function createProductionCandidateExecution({
  cloudflareClient,
  custody,
  fetcher,
  infrastructure,
  productionWranglerAdapter,
  recoveryContext,
  request,
  resendAdminClient,
  runner,
} = {}) {
  if (
    !cloudflareClient?.request ||
    !resendAdminClient?.request ||
    !custody?.productionReleaseReceiptSink?.store ||
    !productionWranglerAdapter?.inspectWorkerVersion ||
    !request ||
    !runner
  ) {
    throw new Error("production candidate execution dependencies are unavailable");
  }
  return async function executeCandidateVerification(input) {
    exactObject(
      input,
      [
        "deployment",
        "infrastructure",
        "materialized",
        "now",
        "primary",
        "productionReleaseStateSha256",
        "protectedExecutionRunId",
        "provider",
        "recovery",
        "recoveryProof",
        "triggerState",
        "workerVersion",
        "workerVersionExpected",
      ],
      "production candidate execution input",
    );
    if (
      input.infrastructure !== infrastructure ||
      input.protectedExecutionRunId !== runner.runId ||
      !digestPattern.test(input.productionReleaseStateSha256 ?? "") ||
      typeof input.now !== "function"
    ) {
      throw new Error("production candidate execution identity changed");
    }
    const receipt = infrastructure.receipt;
    const testRunId = randomUUID();
    const candidateExpected = Object.freeze({
      accessTeamDomain: receipt.cloudflare.access.teamDomain,
      applicationCommitSha: request.source.commitSha,
      artifactSha256: input.materialized.release.uploadArtifactSha256,
      controllerCommitSha: request.controller.commitSha,
      databaseId: receipt.cloudflare.d1.primary.databaseId,
      notificationRecipient: "info@freshtowels.gr",
      notificationSender: receipt.resend.senderAddress,
      workerName: receipt.cloudflare.workerName,
      workerVersionId: input.workerVersion.versionId,
      zoneId: receipt.cloudflare.zoneId,
    });
    const candidateRelease = Object.freeze({
      applicationCommitSha: request.source.commitSha,
      artifactSha256: input.materialized.release.uploadArtifactSha256,
      controllerCommitSha: request.controller.commitSha,
      databaseId: candidateExpected.databaseId,
      environment: "production-candidate-e2e",
      executionClaimSha256: digest({
        brokerRequestId: request.requestId,
        productionReleaseStateSha256: input.productionReleaseStateSha256,
        protectedExecutionRunId: runner.runId,
      }),
      executionRequestId: request.requestId,
      infrastructureReceiptSha256:
        input.materialized.release.productionInfrastructureReceiptSha256,
      productionReleaseStateSha256: input.productionReleaseStateSha256,
      workerName: candidateExpected.workerName,
      workerVersionId: candidateExpected.workerVersionId,
      zoneId: candidateExpected.zoneId,
    });
    const releaseBindingSha256 = digest(candidateRelease);
    const adapters = createProductionCandidateProviderAdapter({
      accountId: receipt.cloudflare.accountId,
      candidateExpected,
      cloudflareClient,
      databaseId: candidateExpected.databaseId,
      fetchImpl: fetcher,
      productionWranglerAdapter,
      releaseBindingSha256,
      resendAdminClient,
      testRunId,
      workerExpected: input.workerVersionExpected,
      zoneId: candidateExpected.zoneId,
    });
    const candidate = await executeProductionCandidateE2e({
      adapters,
      expected: candidateExpected,
      poll: {
        intervalMilliseconds: 2_000,
        now: input.now,
        sleep: (milliseconds) =>
          new Promise((resolve) => setTimeout(resolve, milliseconds)),
        timeoutMilliseconds: 15 * 60 * 1000,
      },
      release: candidateRelease,
      testRunId,
    });
    const completedAt = input.now().toISOString();
    const package_ = createProductionReleaseCandidateReceipt({
      candidate,
      completedAt,
      databases: {
        primary: input.primary,
        recovery: input.recovery,
        recoveryProof: input.recoveryProof,
      },
      environment: "production",
      provider: input.provider,
      receiptType: "fresh-towels-production-release-candidate",
      release: {
        applicationCommitSha: request.source.commitSha,
        applicationRepositoryId: expectedApplicationRepositoryId,
        brokerRequestId: request.requestId,
        buildArtifactSha256: input.materialized.release.buildArtifactSha256,
        controllerCommitSha: request.controller.commitSha,
        controllerRepositoryId: expectedControllerRepositoryId,
        productionInfrastructureReceiptSha256:
          input.materialized.release.productionInfrastructureReceiptSha256,
        productionReleaseCompletedAt: completedAt,
        productionReleaseStateSha256: input.productionReleaseStateSha256,
        protectedExecutionRunId: runner.runId,
        releaseId: input.materialized.release.releaseId,
        uploadArtifactSha256: input.materialized.release.uploadArtifactSha256,
      },
      schema: "deployment-control/production-release-candidate-receipt/v1",
      worker: {
        deploymentStateSha256: input.deployment.stateSha256,
        name: input.workerVersion.workerName,
        triggerStateSha256: input.triggerState.stateSha256,
        versionId: input.workerVersion.versionId,
        versionStateSha256: input.workerVersion.stateSha256,
      },
    });
    let stored;
    try {
      stored = await custody.productionReleaseReceiptSink.store({
        context: recoveryContext,
        receiptBytes: package_.bytes,
        receiptSha256: package_.receiptSha256,
      });
    } finally {
      package_.bytes.fill(0);
    }
    exactObject(
      stored,
      [
        "bindingVersionSha256",
        "ciphertextSha256",
        "custodySha256",
        "decryptionProofSha256",
        "receiptSha256",
        "stored",
      ],
      "production candidate receipt custody",
    );
    if (
      stored.stored !== true ||
      stored.receiptSha256 !== package_.receiptSha256 ||
      [
        stored.bindingVersionSha256,
        stored.ciphertextSha256,
        stored.custodySha256,
        stored.decryptionProofSha256,
      ].some((value) => !digestPattern.test(value ?? ""))
    ) {
      throw new Error("production candidate receipt custody is unverified");
    }
    const custodyProof = {
      bindingVersionSha256: stored.bindingVersionSha256,
      ciphertextSha256: stored.ciphertextSha256,
      custodySha256: stored.custodySha256,
      decryptionProofSha256: stored.decryptionProofSha256,
      privateReceiptSha256: package_.receiptSha256,
    };
    return Object.freeze({
      candidateEvidenceSha256: candidate.receiptSha256,
      candidateRoutesPreCutoverStateSha256:
        candidate.routes.preCutoverStateSha256,
      completedAt,
      custodyBindingVersionSha256: stored.bindingVersionSha256,
      custodyCiphertextSha256: stored.ciphertextSha256,
      custodyDecryptionProofSha256: stored.decryptionProofSha256,
      custodyProofSha256: digest(custodyProof),
      custodySha256: stored.custodySha256,
      leadArchivedStateSha256: candidate.lifecycle.finalStateSha256,
      privateReceiptSha256: package_.receiptSha256,
      productionReleaseStateSha256: input.productionReleaseStateSha256,
      resendDeliveryStateSha256: candidate.resend.deliveryStateSha256,
    });
  };
}

export async function runProductionReleaseCli({
  args = process.argv.slice(2),
  environment = process.env,
  fetcher = globalThis.fetch,
  now = () => new Date(),
} = {}) {
  const clock = typeof now === "function" ? now : () => new Date(now);
  const invocationTime = clock();
  if (!(invocationTime instanceof Date) || !Number.isFinite(invocationTime.valueOf())) {
    throw new Error("production release clock is invalid");
  }
  const paths = arguments_(args);
  const runner = validateProtectedBootstrapEnvironment(environment);
  const requestBase64 = required(environment, "RELEASE_REQUEST_BASE64", /^[A-Za-z0-9_-]+$/, 32_768);
  const requestBytes = decodeCanonicalBase64Url(requestBase64, "production release request");
  const request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(requestBytes));
  const validatedRequest = validateReleaseRequest(request, {
    expectedControllerRepositoryId,
    expectedControllerSha: runner.controllerSha,
    expectedOperation: "production-release",
    expectedSourceRepositoryId,
    now: invocationTime,
  });
  if (validatedRequest.canonical !== requestBytes.toString("utf8")) {
    throw new Error("production release request is not canonical");
  }
  const capsuleBytes = await readFile(paths.capsulePath);
  if (
    capsuleBytes.length !== request.artifact.plaintextBytes ||
    sha256(capsuleBytes) !== request.artifact.plaintextSha256
  ) {
    throw new Error("production capsule differs from the exact request");
  }
  const capsule = validateOperationPayload(capsuleBytes, request, { now });
  const root = await mkdtemp(resolve(environment.RUNNER_TEMP ?? process.cwd(), "production-release-"));
  const materializedRoot = resolve(root, "payload");
  let receiptMaterial;
  const runtimeSecrets = {};
  try {
    const materialized = await materializeProductionCapsule({
      capsule,
      rawPayload: capsuleBytes,
      outputRoot: materializedRoot,
    });
    const controllerIdentity = await loadExactControllerIdentity();
    const getOidcToken = createGitHubOidcTokenProvider({
      fetcher,
      requestToken: required(environment, "ACTIONS_ID_TOKEN_REQUEST_TOKEN", undefined, 4096),
      requestUrl: required(environment, "ACTIONS_ID_TOKEN_REQUEST_URL", undefined, 4096),
    });
    const brokerClient = createCiphertextCustodyBrokerClient({
      dispatcherOrigin: controllerIdentity.dispatcherOrigin,
      fetcher,
      getOidcToken,
      releaseRequestBase64: requestBase64,
    });
    const custody = await createGpgCiphertextCustodySinks({
      brokerClient,
      decryptionEnvironment: environment,
    });
    receiptMaterial = await custody.materializeBinding({
      binding: "PRODUCTION_INFRASTRUCTURE_RECEIPT",
    });
    const infrastructure = validateProductionInfrastructureReceipt({
      bytes: receiptMaterial.bytes,
      expectedSha256: materialized.release.productionInfrastructureReceiptSha256,
      materialized,
      now,
    });
    for (const binding of requiredBindings) {
      runtimeSecrets[binding] = await custody.materializeBinding({ binding });
    }
    validateMaterializedRuntimeSecrets({ materializedSecrets: runtimeSecrets, receipt: infrastructure });
    await verifyPrerequisite({
      environment,
      getOidcToken,
      infrastructure,
      requestBase64,
      root,
    });

    const cloudflareToken = required(environment, "CLOUDFLARE_PRODUCTION_TOKEN", /^\S{20,2048}$/);
    const resendAdminToken = required(environment, "RESEND_PRODUCTION_ADMIN_TOKEN", /^\S{20,2048}$/);
    const cloudflareClient = createCloudflareHttpAdapter({ fetchImpl: fetcher, token: cloudflareToken });
    const resendAdminClient = createResendHttpAdapter({ fetchImpl: fetcher, token: resendAdminToken });
    const recoveryContext = Object.freeze({
      applicationCommitSha: request.source.commitSha,
      brokerRequestId: request.requestId,
      capsuleRequestSha256: request.artifact.plaintextSha256,
      controllerCommitSha: request.controller.commitSha,
    });
    const recoverySnapshotSink = Object.freeze({
      async store(input) {
        return custody.recoveryBackupSink.store({ ...input, context: recoveryContext });
      },
    });
    const wranglerAdapter = createProductionWranglerAdapter({
      cloudflareClient,
      cloudflareToken,
      environment,
      infrastructure: infrastructure.receipt,
      recoverySnapshotSink,
      resendAdminClient,
    });
    const adapter = Object.freeze({
      ...wranglerAdapter,
      executeCandidateVerification: createProductionCandidateExecution({
        cloudflareClient,
        custody,
        fetcher,
        infrastructure,
        productionWranglerAdapter: wranglerAdapter,
        recoveryContext,
        request,
        resendAdminClient,
        runner,
      }),
    });
    const evidence = await executeProductionReleaseAdapter({
      adapter,
      infrastructure,
      materialized,
      runtimeSecrets,
      protectedExecutionRunId: runner.runId,
      now: clock,
    });
    if (!digestPattern.test(evidence.receiptSha256 ?? "")) {
      throw new Error("production release evidence is invalid");
    }
    await writeFile(paths.outputPath, `${canonicalJson(evidence)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    const githubOutput = required(environment, "GITHUB_OUTPUT", undefined, 4096);
    await appendFile(githubOutput, `receipt_sha256=${evidence.receiptSha256}\n`, "utf8");
    process.stdout.write("Production release completed with protected pre-cutover routes; hash-only evidence written.\n");
    return evidence;
  } finally {
    if (Buffer.isBuffer(receiptMaterial?.bytes)) receiptMaterial.bytes.fill(0);
    for (const value of Object.values(runtimeSecrets)) {
      if (Buffer.isBuffer(value?.bytes)) value.bytes.fill(0);
    }
    await rm(root, { force: true, recursive: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runProductionReleaseCli().catch(() => {
    console.error("Production release stopped: protected-provider-adapter-failure");
    process.exitCode = 1;
  });
}
