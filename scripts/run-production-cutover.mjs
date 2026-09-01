#!/usr/bin/env node

import { appendFile, readFile, writeFile } from "node:fs/promises";
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
import {
  executeProductionCutoverAdapter,
  productionCutoverConstants,
} from "./production-cutover-adapter.mjs";
import { createProductionCutoverProviderAdapter } from "./production-cutover-provider-adapter.mjs";
import { validateProductionReleaseCandidateReceipt } from "./production-release-candidate-receipt.mjs";
import {
  inspectProductionCutoverProviderState,
  inspectProductionCutoverWorkerState,
} from "./production-wrangler-adapter.mjs";
import { createCloudflareHttpAdapter, createResendHttpAdapter } from "./provider-adapter.mjs";
import { validateOperationPayload } from "./protected-transport.mjs";
import {
  createGitHubOidcTokenProvider,
  loadExactControllerIdentity,
  validateProtectedBootstrapEnvironment,
} from "./run-production-provider-bootstrap.mjs";

const decimalPattern = /^[1-9][0-9]{0,19}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const emailPattern = /^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const expectedApplicationRepository = "zikosbozonis-beep/fresh-towels-website";
const expectedApplicationRepositoryId = "1350923567";
const expectedControllerRepository =
  "zikosbozonis-beep/fresh-towels-deployment-control";
const expectedControllerRepositoryId = "1353294568";

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
}

function withState(value) {
  return Object.freeze({ ...value, stateSha256: digest(value) });
}

function required(environment, name, pattern, maximum = 4096) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\r\n\0]/.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    throw new Error("protected production cutover environment is incomplete");
  }
  return value;
}

function arguments_(args) {
  if (args.length !== 4 || args[0] !== "--capsule" || args[2] !== "--output") {
    throw new Error("production cutover arguments are invalid");
  }
  return Object.freeze({ capsulePath: resolve(args[1]), outputPath: resolve(args[3]) });
}

function parsePrivateReceipt(material) {
  if (
    !Buffer.isBuffer(material?.bytes) ||
    material.bytes.byteLength < 1 ||
    material.bytes.byteLength > 256 * 1024 ||
    !digestPattern.test(material?.plaintextSha256 ?? "") ||
    sha256(material.bytes) !== material.plaintextSha256
  ) {
    throw new Error("private production release receipt material changed");
  }
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(material.bytes));
  } catch {
    throw new Error("private production release receipt is not UTF-8 JSON");
  }
  if (!material.bytes.equals(Buffer.from(canonicalJson(value) + "\n", "utf8"))) {
    throw new Error("private production release receipt is not canonical");
  }
  return validateProductionReleaseCandidateReceipt(value);
}

function providerProjection(receipt) {
  const cloudflare = receipt.provider.cloudflare;
  const database = receipt.databases.primary;
  const access = cloudflare.access;
  const resendSource = receipt.provider.resend;
  const account = withState({ accountId: cloudflare.accountId });
  const zone = withState({
    zoneId: cloudflare.zoneId,
    name: cloudflare.zoneName,
    status: cloudflare.zoneStatus,
  });
  const dns = withState({
    recordCount: cloudflare.dnsInventoryCount,
    inventorySha256: cloudflare.dnsInventorySha256,
  });
  const d1 = withState({
    databaseIdSha256: sha256(Buffer.from(database.databaseId, "utf8")),
    databaseName: database.databaseName,
    jurisdiction: database.jurisdiction,
    schemaVersion: database.schemaVersion,
    schemaSha256: database.schemaSha256,
  });
  const accessState = withState({
    applicationId: access.applicationId,
    applicationDomain: access.applicationDomain,
    status: "active",
    adminIdentitySha256: access.adminIdentitySha256,
    policyDecision: access.policyDecision,
    extraPolicyCount: access.extraPolicyCount,
  });
  const resend = withState({
    domain: resendSource.domain,
    status: resendSource.domainStatus,
    sendingEnabled: resendSource.sendingCapability === "enabled",
    senderAddress: resendSource.senderAddress,
    webhookEndpointSha256: resendSource.webhookEndpointSha256,
    webhookStatus: resendSource.webhookStatus,
  });
  return withState({
    cloudflare: { account, zone, dns, d1, access: accessState },
    resend,
  });
}

export function deriveProductionCutoverInput({
  accessAudit,
  capsule,
  privateReceipt,
  releaseRequest,
}) {
  const release = privateReceipt.release;
  const prerequisite = capsule.cutover.prerequisite;
  if (
    release.applicationRepositoryId !== expectedApplicationRepositoryId ||
    release.controllerRepositoryId !== expectedControllerRepositoryId ||
    release.applicationCommitSha !== capsule.application.commitSha ||
    release.controllerCommitSha !== capsule.controller.commitSha ||
    release.applicationCommitSha !== releaseRequest.source.commitSha ||
    release.controllerCommitSha !== releaseRequest.controller.commitSha ||
    release.brokerRequestId !== prerequisite.requestId ||
    release.protectedExecutionRunId !== prerequisite.runId ||
    release.productionReleaseCompletedAt !== prerequisite.completedAt ||
    privateReceipt.completedAt !== prerequisite.completedAt ||
    capsule.application.repository !== expectedApplicationRepository ||
    capsule.controller.repository !== expectedControllerRepository ||
    !digestPattern.test(accessAudit?.eventSha256 ?? "")
  ) {
    throw new Error("private production release prerequisite differs from cutover");
  }
  const provider = providerProjection(privateReceipt);
  const worker = privateReceipt.worker;
  const candidate = privateReceipt.candidate;
  return Object.freeze({
    schemaVersion: 1,
    operation: "production-cutover",
    environment: "production",
    issuedAt: capsule.createdAt,
    validUntil: capsule.validUntil,
    cutoverRequestId: releaseRequest.requestId,
    release: {
      releaseId: release.releaseId,
      applicationRepository: expectedApplicationRepository,
      applicationRepositoryId: expectedApplicationRepositoryId,
      applicationCommitSha: release.applicationCommitSha,
      controllerRepository: expectedControllerRepository,
      controllerCommitSha: release.controllerCommitSha,
      buildArtifactSha256: release.buildArtifactSha256,
      uploadArtifactSha256: release.uploadArtifactSha256,
      productionInfrastructureReceiptSha256:
        release.productionInfrastructureReceiptSha256,
    },
    productionReleasePrerequisite: structuredClone(prerequisite),
    worker: {
      name: worker.name,
      versionId: worker.versionId,
      versionStateSha256: worker.versionStateSha256,
      deploymentStateSha256: worker.deploymentStateSha256,
    },
    provider: {
      accountId: privateReceipt.provider.cloudflare.accountId,
      zoneId: privateReceipt.provider.cloudflare.zoneId,
      zoneName: privateReceipt.provider.cloudflare.zoneName,
      fullDnsInventorySha256:
        privateReceipt.provider.cloudflare.dnsInventorySha256,
      primaryDatabaseIdSha256: provider.cloudflare.d1.databaseIdSha256,
      primaryDatabaseName: provider.cloudflare.d1.databaseName,
      primaryDatabaseJurisdiction: provider.cloudflare.d1.jurisdiction,
      primaryDatabaseSchemaVersion: provider.cloudflare.d1.schemaVersion,
      primaryDatabaseSchemaSha256: provider.cloudflare.d1.schemaSha256,
      primaryDatabaseStateSha256: provider.cloudflare.d1.stateSha256,
      accessApplicationId: provider.cloudflare.access.applicationId,
      accessApplicationDomain: provider.cloudflare.access.applicationDomain,
      accessAdminIdentitySha256: provider.cloudflare.access.adminIdentitySha256,
      accessStateSha256: provider.cloudflare.access.stateSha256,
      resendDomain: provider.resend.domain,
      resendStateSha256: provider.resend.stateSha256,
      providerStateSha256: provider.stateSha256,
    },
    candidate: {
      completedAt: candidate.completedAt,
      routesStateSha256: candidate.routes.preCutoverStateSha256,
      syntheticMarkerSha256: candidate.leadFlow.syntheticMarkerSha256,
      e2eEvidenceSha256: candidate.receiptSha256,
      d1EvidenceSha256: candidate.leadFlow.d1StateSha256,
      outboxEvidenceSha256: candidate.leadFlow.outboxStateSha256,
      resendDeliveryEvidenceSha256: candidate.resend.deliveryStateSha256,
      accessAuditEvidenceSha256: accessAudit.eventSha256,
      productionReleaseStateSha256: release.productionReleaseStateSha256,
      productionReleaseCandidateReceiptSha256: privateReceipt.receiptSha256,
    },
  });
}

export async function runProductionCutoverCli({
  args = process.argv.slice(2),
  environment = process.env,
  fetcher = globalThis.fetch,
  now = new Date(),
  dependencies = {},
} = {}) {
  const paths = arguments_(args);
  const runner = (dependencies.validateEnvironment ?? validateProtectedBootstrapEnvironment)(
    environment,
  );
  const requestBase64 = required(
    environment,
    "RELEASE_REQUEST_BASE64",
    /^[A-Za-z0-9_-]+$/,
    32_768,
  );
  const requestBytes = decodeCanonicalBase64Url(
    requestBase64,
    "production cutover request",
  );
  const request = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(requestBytes),
  );
  const validatedRequest = validateReleaseRequest(request, {
    expectedControllerRepositoryId,
    expectedControllerSha: runner.controllerSha,
    expectedOperation: "production-cutover",
    expectedSourceRepositoryId: expectedApplicationRepositoryId,
    now,
  });
  if (validatedRequest.canonical !== requestBytes.toString("utf8")) {
    throw new Error("production cutover request is not canonical");
  }
  const capsuleBytes = await readFile(paths.capsulePath);
  if (
    capsuleBytes.byteLength !== request.artifact.plaintextBytes ||
    sha256(capsuleBytes) !== request.artifact.plaintextSha256
  ) {
    throw new Error("production cutover capsule differs from the exact request");
  }
  const capsule = validateOperationPayload(capsuleBytes, request, { now });
  if (
    required(environment, "EXPECTED_BROKER_REQUEST_ID", uuidPattern) !==
      request.requestId ||
    required(environment, "EXPECTED_CAPSULE_REQUEST_SHA256", digestPattern) !==
      capsule.cutover.cutoverId ||
    required(environment, "PROTECTED_EXECUTION_RUN_ID", decimalPattern) !==
      runner.runId
  ) {
    throw new Error("production cutover protected execution identity changed");
  }
  let receiptMaterial;
  try {
    const controllerIdentity = await (
      dependencies.loadControllerIdentity ?? loadExactControllerIdentity
    )();
    const getOidcToken = (dependencies.createOidcTokenProvider ??
      createGitHubOidcTokenProvider)({
      fetcher,
      requestToken: required(
        environment,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        undefined,
        4096,
      ),
      requestUrl: required(
        environment,
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        undefined,
        4096,
      ),
    });
    const brokerClient = (dependencies.createBrokerClient ??
      createCiphertextCustodyBrokerClient)({
      dispatcherOrigin: controllerIdentity.dispatcherOrigin,
      fetcher,
      getOidcToken,
      releaseRequestBase64: requestBase64,
    });
    const custody = await (
      dependencies.createCustody ?? createGpgCiphertextCustodySinks
    )({ brokerClient, decryptionEnvironment: environment });
    receiptMaterial = await custody.materializeProductionReleaseReceipt();
    const privateReceipt = parsePrivateReceipt(receiptMaterial);
    const cloudflareToken = required(
      environment,
      "CLOUDFLARE_PRODUCTION_TOKEN",
      /^\S{20,2048}$/,
    );
    const resendAdminToken = required(
      environment,
      "RESEND_PRODUCTION_ADMIN_TOKEN",
      /^\S{20,2048}$/,
    );
    const adminIdentity = required(
      environment,
      "PRODUCTION_ACCESS_ADMIN_EMAIL",
      emailPattern,
    );
    if (
      sha256(Buffer.from(adminIdentity, "utf8")) !==
      privateReceipt.provider.cloudflare.access.adminIdentitySha256
    ) {
      throw new Error("protected Access administrator identity changed");
    }
    const cloudflareClient = (dependencies.createCloudflareClient ??
      ((options) => createCloudflareHttpAdapter(options)))({
      fetchImpl: fetcher,
      token: cloudflareToken,
    });
    const resendAdminClient = (dependencies.createResendClient ??
      ((options) => createResendHttpAdapter(options)))({
      fetchImpl: fetcher,
      token: resendAdminToken,
    });
    const projectedProvider = providerProjection(privateReceipt);
    const inspectProviderState = async () => {
      await (dependencies.inspectProviderState ?? inspectProductionCutoverProviderState)({
        approvedState: privateReceipt.provider,
        cloudflareClient,
        infrastructure: {
          cloudflare: privateReceipt.provider.cloudflare,
          resend: privateReceipt.provider.resend,
        },
        resendAdminClient,
      });
      return structuredClone(projectedProvider);
    };
    const inspectWorkerState = async () =>
      (dependencies.inspectWorkerState ?? inspectProductionCutoverWorkerState)({
        accountId: privateReceipt.provider.cloudflare.accountId,
        approvedWorker: privateReceipt.worker,
        cloudflareClient,
      });
    const inspectCandidateE2e = async ({ receiptSha256 }) => {
      if (receiptSha256 !== privateReceipt.candidate.receiptSha256) {
        throw new Error("candidate receipt identity changed");
      }
      return structuredClone(privateReceipt.candidate);
    };
    const adapter = (dependencies.createCutoverAdapter ??
      createProductionCutoverProviderAdapter)({
      accountId: privateReceipt.provider.cloudflare.accountId,
      adminIdentity,
      cloudflareClient,
      fetchImpl: fetcher,
      inspectCandidateE2e,
      inspectProviderState,
      inspectWorkerState,
      now: () => now,
      zoneId: privateReceipt.provider.cloudflare.zoneId,
    });
    const accessAudit = await adapter.inspectAccessAudit({
      after: privateReceipt.candidate.completedAt,
      adminIdentitySha256:
        privateReceipt.provider.cloudflare.access.adminIdentitySha256,
      applicationDomain:
        privateReceipt.provider.cloudflare.access.applicationDomain,
      applicationId: privateReceipt.provider.cloudflare.access.applicationId,
    });
    const cutoverInput = deriveProductionCutoverInput({
      accessAudit,
      capsule,
      privateReceipt,
      releaseRequest: request,
    });
    const evidence = await (dependencies.executeCutover ??
      executeProductionCutoverAdapter)({
      adapter,
      cutoverInput,
      protectedExecutionRunId: runner.runId,
      now: () => now,
    });
    if (!digestPattern.test(evidence?.receiptSha256 ?? "")) {
      throw new Error("production cutover evidence is invalid");
    }
    await writeFile(paths.outputPath, canonicalJson(evidence) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    await appendFile(
      required(environment, "GITHUB_OUTPUT", undefined, 4096),
      `receipt_sha256=${evidence.receiptSha256}\n`,
      "utf8",
    );
    process.stdout.write("Production cutover completed; hash-only evidence written.\n");
    return evidence;
  } finally {
    if (Buffer.isBuffer(receiptMaterial?.bytes)) receiptMaterial.bytes.fill(0);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runProductionCutoverCli().catch(() => {
    console.error("Production cutover stopped: protected-provider-adapter-failure");
    process.exitCode = 1;
  });
}

export const productionCutoverRunnerConstants = Object.freeze({
  expectedApplicationRepositoryId,
  expectedControllerRepositoryId,
  expectedZoneName: productionCutoverConstants.expectedZoneName,
});
