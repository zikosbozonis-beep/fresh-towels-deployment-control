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
  executeProductionDnsStage,
  validateProductionDnsStageCapsule,
} from "./production-dns-stage.mjs";
import {
  createCiphertextCustodyBrokerClient,
  createGpgCiphertextCustodySinks,
} from "./ciphertext-custody-client.mjs";
import {
  createGitHubOidcTokenProvider,
  loadExactControllerIdentity,
} from "./run-production-provider-bootstrap.mjs";
import {
  createCloudflareHttpAdapter,
  createResendHttpAdapter,
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "./provider-adapter.mjs";
import { ProductionBootstrapAmbiguousError } from "./production-provider-bootstrap.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const uuidV4Pattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const expectedControllerRepository = "zikosbozonis-beep/fresh-towels-deployment-control";
const expectedControllerRepositoryId = "1353294568";
const expectedSourceRepositoryId = "1350923567";
const expectedWorkflowRef =
  `${expectedControllerRepository}/.github/workflows/execute-release.yml@refs/heads/main`;

const evidenceKeys = [
  "applicationCommitSha",
  "applicationRunAttempt",
  "applicationRunId",
  "capsuleRequestSha256",
  "capsuleSha256",
  "cloudflareZoneStateSha256",
  "completedAt",
  "controllerCommitSha",
  "dnsInventorySha256",
  "encryptedCustodyProofSha256",
  "operation",
  "protectedExecutionRunId",
  "providerStateSha256",
  "privateReceiptSha256",
  "receiptSha256",
  "requestId",
  "resendVerificationRecordsSha256",
  "result",
  "schema",
];

export class ProductionDnsStageRunnerError extends Error {
  constructor(code) {
    super("Production DNS stage stopped: " + code);
    this.name = "ProductionDnsStageRunnerError";
    this.code = code;
  }
}

function fail(code) {
  throw new ProductionDnsStageRunnerError(code);
}

function exactObject(value, keys, code) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(code);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(code);
  }
}

function required(environment, name, pattern, secret = false) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > (secret ? 2048 : 32768) ||
    /[\r\n\0]/.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    fail(secret ? "protected-credential-unavailable" : "protected-execution-environment");
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value) + "\n", "utf8");
}

function canonicalInstant(value) {
  const timestamp = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

export function deriveTrustedProductionDnsStageInput({
  capsuleBytes,
  encodedRequest,
  expectedBrokerRequestId,
  expectedCapsuleRequestSha256,
  expectedControllerSha,
  githubRunId,
  protectedExecutionRunId,
  now = new Date(),
}) {
  let requestBytes;
  try {
    requestBytes = decodeCanonicalBase64Url(encodedRequest, "RELEASE_REQUEST_BASE64");
  } catch {
    fail("release-request-binding");
  }
  if (requestBytes.byteLength < 2 || requestBytes.byteLength > 24_576) {
    fail("release-request-boundary");
  }
  let request;
  let capsule;
  try {
    request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(requestBytes));
    capsule = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(capsuleBytes));
  } catch {
    fail("release-request-json");
  }
  let verifiedRequest;
  try {
    verifiedRequest = validateReleaseRequest(request, {
      expectedControllerRepositoryId,
      expectedControllerSha,
      expectedSourceRepositoryId,
      expectedOperation: "production-dns-stage",
      now,
    });
  } catch {
    fail("release-request-binding");
  }
  if (verifiedRequest.canonical !== new TextDecoder("utf-8", { fatal: true }).decode(requestBytes)) {
    fail("release-request-canonicalization");
  }
  const exactCapsuleBytes = Buffer.from(capsuleBytes);
  if (
    request.artifact.plaintextBytes !== exactCapsuleBytes.byteLength ||
    request.artifact.plaintextSha256 !== sha256(exactCapsuleBytes)
  ) {
    fail("dns-stage-capsule-artifact-binding");
  }
  if (
    !uuidV4Pattern.test(expectedBrokerRequestId ?? "") ||
    expectedBrokerRequestId !== request.requestId ||
    !digestPattern.test(expectedCapsuleRequestSha256 ?? "") ||
    capsule?.dnsStage?.requestId !== expectedCapsuleRequestSha256 ||
    !decimalPattern.test(protectedExecutionRunId ?? "") ||
    protectedExecutionRunId !== githubRunId
  ) {
    fail("protected-execution-provenance");
  }
  try {
    validateProductionDnsStageCapsule({
      capsule,
      capsuleBytes: exactCapsuleBytes,
      expectedCapsuleSha256: request.artifact.plaintextSha256,
      now,
    });
  } catch {
    fail("dns-stage-capsule-binding");
  }
  if (
    capsule.application.repositoryId !== request.source.repositoryId ||
    capsule.application.commitSha !== request.source.commitSha ||
    capsule.application.runId !== request.source.workflowRunId ||
    capsule.application.runAttempt !== request.source.workflowRunAttempt ||
    capsule.controller.commitSha !== request.controller.commitSha
  ) {
    fail("dns-stage-release-request-substitution");
  }
  return Object.freeze({
    capsule,
    capsuleBytes: exactCapsuleBytes,
    expectedCapsuleSha256: request.artifact.plaintextSha256,
    protectedExecution: Object.freeze({
      brokerRequestId: expectedBrokerRequestId,
      capsuleRequestSha256: expectedCapsuleRequestSha256,
      runId: protectedExecutionRunId,
    }),
    releaseRequest: verifiedRequest.request,
  });
}

export function validateHashOnlyProductionDnsStageEvidence(evidence, trusted) {
  exactObject(evidence, evidenceKeys, "dns-stage-evidence-shape");
  if (
    evidence.schema !== "deployment-control/production-dns-stage-evidence/v1" ||
    evidence.operation !== "production-dns-stage" ||
    evidence.result !== "verified" ||
    evidence.requestId !== trusted.releaseRequest.requestId ||
    evidence.capsuleRequestSha256 !== trusted.protectedExecution.capsuleRequestSha256 ||
    evidence.applicationCommitSha !== trusted.releaseRequest.source.commitSha ||
    evidence.controllerCommitSha !== trusted.releaseRequest.controller.commitSha ||
    evidence.applicationRunId !== trusted.releaseRequest.source.workflowRunId ||
    evidence.applicationRunAttempt !== trusted.releaseRequest.source.workflowRunAttempt ||
    evidence.protectedExecutionRunId !== trusted.protectedExecution.runId ||
    evidence.capsuleSha256 !== trusted.expectedCapsuleSha256 ||
    !canonicalInstant(evidence.completedAt)
  ) {
    fail("dns-stage-evidence-binding");
  }
  for (const key of [
    "capsuleRequestSha256",
    "capsuleSha256",
    "cloudflareZoneStateSha256",
    "dnsInventorySha256",
    "encryptedCustodyProofSha256",
    "privateReceiptSha256",
    "resendVerificationRecordsSha256",
    "providerStateSha256",
    "receiptSha256",
  ]) {
    if (!digestPattern.test(evidence[key] ?? "")) fail("dns-stage-evidence-digest");
  }
  const { receiptSha256, ...body } = evidence;
  if (sha256(canonicalBytes(body)) !== receiptSha256) fail("dns-stage-evidence-integrity");
  return true;
}

export function validateProtectedDnsStageEnvironment(environment) {
  const controllerSha = required(environment, "GITHUB_SHA", commitPattern);
  const runId = required(environment, "GITHUB_RUN_ID", decimalPattern);
  if (
    required(environment, "GITHUB_ACTIONS", /^(?:true)$/) !== "true" ||
    required(environment, "GITHUB_EVENT_NAME", /^(?:workflow_dispatch)$/) !== "workflow_dispatch" ||
    required(environment, "GITHUB_REF", /^(?:refs\/heads\/main)$/) !== "refs/heads/main" ||
    required(environment, "GITHUB_REF_PROTECTED", /^(?:true)$/) !== "true" ||
    required(environment, "GITHUB_REPOSITORY") !== expectedControllerRepository ||
    required(environment, "GITHUB_REPOSITORY_ID", decimalPattern) !== expectedControllerRepositoryId ||
    required(environment, "GITHUB_WORKFLOW_REF") !== expectedWorkflowRef ||
    required(environment, "GITHUB_WORKFLOW_SHA", commitPattern) !== controllerSha
  ) {
    fail("protected-execution-environment");
  }
  return Object.freeze({ controllerSha, runId });
}

export async function persistProductionDnsStageEvidence({ evidence, githubOutput, outputPath, trusted }) {
  validateHashOnlyProductionDnsStageEvidence(evidence, trusted);
  const resolved = resolve(outputPath);
  if (githubOutput && resolve(githubOutput) === resolved) fail("dns-stage-evidence-output-alias");
  await writeFile(resolved, canonicalJson(evidence) + "\n", {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  if (githubOutput) {
    await appendFile(resolve(githubOutput), "receipt_sha256=" + evidence.receiptSha256 + "\n", "utf8");
  }
}

export async function runProductionDnsStageCli({
  args = process.argv.slice(2),
  environment = process.env,
  fetcher = globalThis.fetch,
  now = new Date(),
} = {}) {
  if (args.length !== 4 || args[0] !== "--capsule" || args[2] !== "--output") {
    fail("dns-stage-cli-arguments");
  }
  const runner = validateProtectedDnsStageEnvironment(environment);
  const trusted = deriveTrustedProductionDnsStageInput({
    capsuleBytes: await readFile(resolve(args[1])),
    encodedRequest: required(environment, "RELEASE_REQUEST_BASE64", /^[A-Za-z0-9_-]{100,32768}$/),
    expectedBrokerRequestId: required(environment, "EXPECTED_BROKER_REQUEST_ID", uuidV4Pattern),
    expectedCapsuleRequestSha256: required(environment, "EXPECTED_CAPSULE_REQUEST_SHA256", digestPattern),
    expectedControllerSha: runner.controllerSha,
    githubRunId: runner.runId,
    protectedExecutionRunId: required(environment, "PROTECTED_EXECUTION_RUN_ID", decimalPattern),
    now,
  });
  const identity = await loadExactControllerIdentity();
  const getOidcToken = createGitHubOidcTokenProvider({
    fetcher,
    requestToken: required(environment, "ACTIONS_ID_TOKEN_REQUEST_TOKEN", undefined, true),
    requestUrl: required(environment, "ACTIONS_ID_TOKEN_REQUEST_URL"),
  });
  const brokerClient = createCiphertextCustodyBrokerClient({
    dispatcherOrigin: identity.dispatcherOrigin,
    fetcher,
    getOidcToken,
    releaseRequestBase64: required(
      environment,
      "RELEASE_REQUEST_BASE64",
      /^[A-Za-z0-9_-]{100,32768}$/,
    ),
  });
  const custody = await createGpgCiphertextCustodySinks({
    brokerClient,
    decryptionEnvironment: environment,
  });
  const evidence = await executeProductionDnsStage({
    capsule: trusted.capsule,
    capsuleBytes: trusted.capsuleBytes,
    expectedCapsuleSha256: trusted.expectedCapsuleSha256,
    cloudflareClient: createCloudflareHttpAdapter({
      fetchImpl: fetcher,
      token: required(environment, "CLOUDFLARE_PRODUCTION_TOKEN", /^\S{20,2048}$/, true),
    }),
    resendClient: createResendHttpAdapter({
      fetchImpl: fetcher,
      token: required(environment, "RESEND_PRODUCTION_ADMIN_TOKEN", /^\S{20,2048}$/, true),
    }),
    privateReceiptSink: custody.dnsStageReceiptSink,
    protectedExecution: trusted.protectedExecution,
    expectedBrokerRequestId: trusted.releaseRequest.requestId,
  });
  await persistProductionDnsStageEvidence({
    evidence,
    githubOutput: required(environment, "GITHUB_OUTPUT"),
    outputPath: resolve(args[3]),
    trusted,
  });
  process.stdout.write("Production DNS stage completed; hash-only evidence written.\n");
  return evidence;
}

function safeFailureCode(error) {
  if (error instanceof ProductionDnsStageRunnerError) return error.code;
  if (error instanceof ProviderRejectedError) return "provider-rejected";
  if (error instanceof ProviderTransportAmbiguousError) return "provider-transport-ambiguous";
  if (error instanceof ProductionBootstrapAmbiguousError) return "provider-state-ambiguous";
  return "unexpected-failure";
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runProductionDnsStageCli().catch((error) => {
    console.error("Production DNS stage stopped: " + safeFailureCode(error));
    process.exitCode = 1;
  });
}
