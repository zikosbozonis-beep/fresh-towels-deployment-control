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
  executeProductionProviderBootstrap,
  ProductionBootstrapAmbiguousError,
  validateProductionBootstrapCapsule,
} from "./production-provider-bootstrap.mjs";
import {
  createCloudflareHttpAdapter,
  createResendHttpAdapter,
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "./provider-adapter.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const uuidV4Pattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const emailPattern = /^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/;
const expectedControllerRepository = "zikosbozonis-beep/fresh-towels-deployment-control";
const expectedControllerRepositoryId = "1353294568";
const expectedSourceRepositoryId = "1350923567";
const expectedWorkflowRef =
  `${expectedControllerRepository}/.github/workflows/execute-release.yml@refs/heads/main`;
const expectedControllerIdentityPath = "controller-identity.json";
const oidcAudience = "deployment-control-executor-v1";
const oidcRequestHost = "pipelines.actions.githubusercontent.com";
const maximumRequestBytes = 24_576;

const evidenceKeys = [
  "applicationCommitSha",
  "applicationRunAttempt",
  "applicationRunId",
  "capsuleRequestSha256",
  "capsuleSha256",
  "completedAt",
  "controllerCommitSha",
  "encryptedCustodyProofSha256",
  "operation",
  "privateReceiptSha256",
  "protectedExecutionRunId",
  "providerStateSha256",
  "wordpressFallbackSha256",
  "receiptSha256",
  "requestId",
  "result",
  "schema",
];

export class ProductionBootstrapRunnerError extends Error {
  constructor(code) {
    super(`Production provider bootstrap stopped: ${code}`);
    this.name = "ProductionBootstrapRunnerError";
    this.code = code;
  }
}

function fail(code) {
  throw new ProductionBootstrapRunnerError(code);
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

function requiredEnvironment(
  environment,
  name,
  pattern,
  { maxLength = 1024, secret = false } = {},
) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    /[\r\n\0]/.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    fail(secret ? "protected-credential-unavailable" : "protected-execution-environment");
  }
  return value;
}

function canonicalInstant(value) {
  const timestamp = Date.parse(value);
  return (
    typeof value === "string" &&
    Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value
  );
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function requestBytes(encodedRequest) {
  let bytes;
  try {
    bytes = decodeCanonicalBase64Url(encodedRequest, "RELEASE_REQUEST_BASE64");
  } catch {
    fail("release-request-binding");
  }
  if (bytes.length < 2 || bytes.length > maximumRequestBytes) fail("release-request-boundary");
  return bytes;
}

function utf8Json(bytes, code) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail(code);
  }
}

export function deriveTrustedProductionBootstrapInput({
  adminIdentity,
  capsuleBytes,
  encodedRequest,
  expectedBrokerRequestId,
  expectedCapsuleRequestSha256,
  expectedControllerSha,
  githubRunId,
  protectedExecutionRunId,
  now = new Date(),
}) {
  if (!(capsuleBytes instanceof Uint8Array)) fail("trusted-bootstrap-capsule-missing");
  const exactCapsuleBytes = Buffer.from(capsuleBytes);
  const encodedBytes = requestBytes(encodedRequest);
  const requestText = new TextDecoder("utf-8", { fatal: true }).decode(encodedBytes);
  const request = utf8Json(encodedBytes, "release-request-json");
  let verifiedRequest;
  try {
    verifiedRequest = validateReleaseRequest(request, {
      expectedControllerRepositoryId,
      expectedControllerSha,
      expectedSourceRepositoryId,
      expectedOperation: "production-bootstrap",
      now,
    });
  } catch {
    fail("release-request-binding");
  }
  if (verifiedRequest.canonical !== requestText) fail("release-request-canonicalization");
  if (
    request.artifact.plaintextBytes !== exactCapsuleBytes.byteLength ||
    request.artifact.plaintextSha256 !== sha256(exactCapsuleBytes)
  ) {
    fail("bootstrap-capsule-artifact-binding");
  }
  const capsule = utf8Json(exactCapsuleBytes, "bootstrap-capsule-json");
  if (!exactCapsuleBytes.equals(canonicalBytes(capsule))) {
    fail("bootstrap-capsule-canonicalization");
  }
  if (
    !uuidV4Pattern.test(expectedBrokerRequestId ?? "") ||
    expectedBrokerRequestId !== request.requestId ||
    !digestPattern.test(expectedCapsuleRequestSha256 ?? "") ||
    capsule?.bootstrap?.requestId !== expectedCapsuleRequestSha256 ||
    !decimalPattern.test(protectedExecutionRunId ?? "") ||
    protectedExecutionRunId !== githubRunId ||
    !emailPattern.test(adminIdentity ?? "") ||
    adminIdentity !== adminIdentity.toLowerCase()
  ) {
    fail("protected-execution-provenance");
  }
  try {
    validateProductionBootstrapCapsule({
      capsule,
      capsuleBytes: exactCapsuleBytes,
      expectedCapsuleSha256: request.artifact.plaintextSha256,
      adminIdentity,
      now,
    });
  } catch {
    fail("bootstrap-capsule-binding");
  }
  const application = capsule.application;
  const controller = capsule.controller;
  if (
    application.repositoryId !== request.source.repositoryId ||
    application.commitSha !== request.source.commitSha ||
    application.runId !== request.source.workflowRunId ||
    application.runAttempt !== request.source.workflowRunAttempt ||
    controller.commitSha !== request.controller.commitSha
  ) {
    fail("bootstrap-release-request-substitution");
  }
  return Object.freeze({
    adminIdentity,
    capsule,
    capsuleBytes: exactCapsuleBytes,
    expectedCapsuleSha256: request.artifact.plaintextSha256,
    protectedExecution: Object.freeze({
      brokerRequestId: expectedBrokerRequestId,
      capsuleRequestSha256: expectedCapsuleRequestSha256,
      runId: protectedExecutionRunId,
    }),
    releaseRequest: verifiedRequest.request,
    releaseRequestBase64: encodedRequest,
    releaseRequestDigest: verifiedRequest.digest,
  });
}

export function validateHashOnlyProductionBootstrapEvidence(evidence, trusted) {
  exactObject(evidence, evidenceKeys, "bootstrap-evidence-shape");
  const completedAt = Date.parse(evidence.completedAt);
  const capsuleCreatedAt = Date.parse(trusted.capsule.createdAt);
  const capsuleValidUntil = Date.parse(trusted.capsule.validUntil);
  if (
    evidence.schema !== "deployment-control/production-provider-bootstrap-evidence/v1" ||
    evidence.operation !== "production-bootstrap" ||
    evidence.result !== "verified" ||
    evidence.requestId !== trusted.releaseRequest.requestId ||
    evidence.capsuleRequestSha256 !== trusted.protectedExecution.capsuleRequestSha256 ||
    evidence.applicationCommitSha !== trusted.releaseRequest.source.commitSha ||
    evidence.controllerCommitSha !== trusted.releaseRequest.controller.commitSha ||
    evidence.applicationRunId !== trusted.releaseRequest.source.workflowRunId ||
    evidence.applicationRunAttempt !== trusted.releaseRequest.source.workflowRunAttempt ||
    evidence.protectedExecutionRunId !== trusted.protectedExecution.runId ||
    evidence.capsuleSha256 !== trusted.expectedCapsuleSha256 ||
    !canonicalInstant(evidence.completedAt) ||
    completedAt < capsuleCreatedAt ||
    completedAt >= capsuleValidUntil
  ) {
    fail("bootstrap-evidence-binding");
  }
  for (const key of [
    "capsuleRequestSha256",
    "capsuleSha256",
    "privateReceiptSha256",
    "encryptedCustodyProofSha256",
    "providerStateSha256",
    "wordpressFallbackSha256",
    "receiptSha256",
  ]) {
    if (!digestPattern.test(evidence[key] ?? "")) fail("bootstrap-evidence-digest");
  }
  const { receiptSha256, ...body } = evidence;
  if (sha256(canonicalBytes(body)) !== receiptSha256) fail("bootstrap-evidence-integrity");
  return true;
}

export async function persistProductionBootstrapEvidence({
  evidence,
  githubOutput,
  outputPath,
  trusted,
}) {
  validateHashOnlyProductionBootstrapEvidence(evidence, trusted);
  const resolvedOutput = resolve(outputPath);
  if (githubOutput && resolve(githubOutput) === resolvedOutput) {
    fail("bootstrap-evidence-output-alias");
  }
  await writeFile(resolvedOutput, `${canonicalJson(evidence)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  if (githubOutput) {
    await appendFile(resolve(githubOutput), `receipt_sha256=${evidence.receiptSha256}\n`, "utf8");
  }
  return evidence.receiptSha256;
}

export function createGitHubOidcTokenProvider({
  audience = oidcAudience,
  fetcher = globalThis.fetch,
  requestToken,
  requestUrl,
  timeoutMilliseconds = 15_000,
}) {
  let url;
  try {
    url = new URL(requestUrl);
  } catch {
    fail("oidc-request-boundary");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    url.hostname !== oidcRequestHost ||
    !url.pathname.startsWith("/_apis/distributedtask/hubs/") ||
    !url.pathname.endsWith("/idtoken") ||
    url.searchParams.get("api-version") !== "2.0" ||
    [...url.searchParams.keys()].some((key) => key !== "api-version" && key !== "audience") ||
    url.hash ||
    typeof requestToken !== "string" ||
    requestToken.length < 20 ||
    requestToken.length > 4096 ||
    /[\r\n\0]/.test(requestToken) ||
    typeof fetcher !== "function" ||
    audience !== oidcAudience ||
    !Number.isSafeInteger(timeoutMilliseconds) ||
    timeoutMilliseconds < 1000 ||
    timeoutMilliseconds > 60_000
  ) {
    fail("oidc-request-boundary");
  }
  url.searchParams.set("audience", audience);
  return async function getOidcToken() {
    let response;
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), timeoutMilliseconds);
    try {
      response = await fetcher(url, {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${requestToken}`,
          "user-agent": "deployment-control-protected-bootstrap",
        },
        redirect: "error",
        signal: abort.signal,
      });
    } catch {
      clearTimeout(timer);
      fail("oidc-token-transport");
    }
    let text;
    try {
      text = await response.text();
    } catch {
      fail("oidc-token-response");
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok || Buffer.byteLength(text) > 32_768) fail("oidc-token-response");
    const payload = utf8Json(Buffer.from(text, "utf8"), "oidc-token-response");
    exactObject(payload, ["count", "value"], "oidc-token-response");
    if (
      payload.count !== 1 ||
      typeof payload.value !== "string" ||
      payload.value.length < 100 ||
      payload.value.length > 16_384 ||
      payload.value.split(".").length !== 3 ||
      /[\r\n\0]/.test(payload.value)
    ) {
      fail("oidc-token-response");
    }
    return payload.value;
  };
}

export async function loadExactControllerIdentity(path = expectedControllerIdentityPath) {
  const bytes = await readFile(resolve(path));
  const identity = utf8Json(bytes, "controller-identity-json");
  exactObject(
    identity,
    ["configured", "dispatcherOrigin", "repository", "repositoryId"],
    "controller-identity-shape",
  );
  let origin;
  try {
    origin = new URL(identity.dispatcherOrigin);
  } catch {
    fail("controller-identity-origin");
  }
  if (
    identity.configured !== true ||
    identity.repository !== expectedControllerRepository ||
    identity.repositoryId !== expectedControllerRepositoryId ||
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    origin.hostname.endsWith(".invalid")
  ) {
    fail("controller-identity-binding");
  }
  return Object.freeze(structuredClone(identity));
}

export async function runTrustedProductionProviderBootstrap({
  cloudflareClient,
  dnsStageReceiptBytes,
  executeBootstrap = executeProductionProviderBootstrap,
  privateReceiptSink,
  resendClient,
  resendRuntimeClientFactory,
  secretSink,
  trusted,
}) {
  if (
    typeof executeBootstrap !== "function" ||
    !(dnsStageReceiptBytes instanceof Uint8Array) ||
    !cloudflareClient?.request ||
    !resendClient?.request ||
    typeof resendRuntimeClientFactory !== "function" ||
    !secretSink?.inspect ||
    !secretSink?.store ||
    !privateReceiptSink?.store
  ) {
    fail("bootstrap-runtime-dependencies");
  }
  const evidence = await executeBootstrap({
    adminIdentity: trusted.adminIdentity,
    capsule: trusted.capsule,
    capsuleBytes: trusted.capsuleBytes,
    cloudflareClient,
    dnsStageReceiptBytes,
    expectedBrokerRequestId: trusted.protectedExecution.brokerRequestId,
    expectedCapsuleSha256: trusted.expectedCapsuleSha256,
    privateReceiptSink,
    protectedExecution: trusted.protectedExecution,
    resendClient,
    resendRuntimeClientFactory,
    secretSink,
  });
  validateHashOnlyProductionBootstrapEvidence(evidence, trusted);
  return evidence;
}

export function validateProtectedBootstrapEnvironment(environment) {
  const controllerSha = requiredEnvironment(environment, "GITHUB_SHA", commitPattern);
  const runId = requiredEnvironment(environment, "GITHUB_RUN_ID", decimalPattern);
  const runAttempt = requiredEnvironment(
    environment,
    "GITHUB_RUN_ATTEMPT",
    /^(?:[1-9]|[1-9][0-9]|100)$/,
  );
  if (
    requiredEnvironment(environment, "GITHUB_ACTIONS", /^(?:true)$/) !== "true" ||
    requiredEnvironment(environment, "GITHUB_EVENT_NAME", /^(?:workflow_dispatch)$/) !==
      "workflow_dispatch" ||
    requiredEnvironment(environment, "GITHUB_REF", /^(?:refs\/heads\/main)$/) !==
      "refs/heads/main" ||
    requiredEnvironment(environment, "GITHUB_REF_PROTECTED", /^(?:true)$/) !== "true" ||
    requiredEnvironment(
      environment,
      "GITHUB_REPOSITORY",
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
    ) !== expectedControllerRepository ||
    requiredEnvironment(environment, "GITHUB_REPOSITORY_ID", decimalPattern) !==
      expectedControllerRepositoryId ||
    requiredEnvironment(environment, "GITHUB_WORKFLOW_REF") !== expectedWorkflowRef ||
    requiredEnvironment(environment, "GITHUB_WORKFLOW_SHA", commitPattern) !== controllerSha
  ) {
    fail("protected-execution-environment");
  }
  return Object.freeze({ controllerSha, runAttempt: Number(runAttempt), runId });
}

function cliArguments(args) {
  if (args.length !== 4 || args[0] !== "--capsule" || args[2] !== "--output") {
    fail("bootstrap-cli-arguments");
  }
  return Object.freeze({ capsulePath: resolve(args[1]), outputPath: resolve(args[3]) });
}

export async function runProductionProviderBootstrapCli({
  args = process.argv.slice(2),
  environment = process.env,
  fetcher = globalThis.fetch,
  now = new Date(),
} = {}) {
  const paths = cliArguments(args);
  const runner = validateProtectedBootstrapEnvironment(environment);
  const encodedRequest = requiredEnvironment(
    environment,
    "RELEASE_REQUEST_BASE64",
    /^[A-Za-z0-9_-]{100,32768}$/,
    { maxLength: 32_768 },
  );
  const trusted = deriveTrustedProductionBootstrapInput({
    adminIdentity: requiredEnvironment(environment, "PRODUCTION_ACCESS_ADMIN_EMAIL", emailPattern),
    capsuleBytes: await readFile(paths.capsulePath),
    encodedRequest,
    expectedBrokerRequestId: requiredEnvironment(
      environment,
      "EXPECTED_BROKER_REQUEST_ID",
      uuidV4Pattern,
    ),
    expectedCapsuleRequestSha256: requiredEnvironment(
      environment,
      "EXPECTED_CAPSULE_REQUEST_SHA256",
      digestPattern,
    ),
    expectedControllerSha: runner.controllerSha,
    githubRunId: runner.runId,
    protectedExecutionRunId: requiredEnvironment(
      environment,
      "PROTECTED_EXECUTION_RUN_ID",
      decimalPattern,
    ),
    now,
  });
  const controllerIdentity = await loadExactControllerIdentity();
  const getOidcToken = createGitHubOidcTokenProvider({
    fetcher,
    requestToken: requiredEnvironment(
      environment,
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
      undefined,
      { maxLength: 4096, secret: true },
    ),
    requestUrl: requiredEnvironment(environment, "ACTIONS_ID_TOKEN_REQUEST_URL"),
  });
  const brokerClient = createCiphertextCustodyBrokerClient({
    dispatcherOrigin: controllerIdentity.dispatcherOrigin,
    fetcher,
    getOidcToken,
    releaseRequestBase64: encodedRequest,
  });
  const custody = await createGpgCiphertextCustodySinks({
    brokerClient,
    decryptionEnvironment: environment,
  });
  const dnsStageReceipt = await custody.materializeBinding({
    binding: "PRODUCTION_DNS_STAGE_RECEIPT",
  });
  const cloudflareClient = createCloudflareHttpAdapter({
    fetchImpl: fetcher,
    token: requiredEnvironment(
      environment,
      "CLOUDFLARE_PRODUCTION_TOKEN",
      /^\S{20,2048}$/,
      { maxLength: 2048, secret: true },
    ),
  });
  const resendClient = createResendHttpAdapter({
    fetchImpl: fetcher,
    token: requiredEnvironment(
      environment,
      "RESEND_PRODUCTION_ADMIN_TOKEN",
      /^\S{20,2048}$/,
      { maxLength: 2048, secret: true },
    ),
  });
  let evidence;
  try {
    evidence = await runTrustedProductionProviderBootstrap({
      cloudflareClient,
      dnsStageReceiptBytes: dnsStageReceipt.bytes,
      privateReceiptSink: custody.privateReceiptSink,
      resendClient,
      resendRuntimeClientFactory: (token) =>
        createResendHttpAdapter({ fetchImpl: fetcher, token }),
      secretSink: custody.secretSink,
      trusted,
    });
  } finally {
    dnsStageReceipt.bytes.fill(0);
  }
  await persistProductionBootstrapEvidence({
    evidence,
    githubOutput: requiredEnvironment(environment, "GITHUB_OUTPUT"),
    outputPath: paths.outputPath,
    trusted,
  });
  process.stdout.write("Production provider Bootstrap completed; hash-only evidence written.\n");
  return evidence;
}

function safeFailureCode(error) {
  if (error instanceof ProductionBootstrapRunnerError) return error.code;
  if (error instanceof ProviderRejectedError) return "provider-rejected";
  if (error instanceof ProviderTransportAmbiguousError) return "provider-transport-ambiguous";
  if (error instanceof ProductionBootstrapAmbiguousError) return "provider-state-ambiguous";
  return "unexpected-failure";
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runProductionProviderBootstrapCli().catch((error) => {
    console.error(`Production provider Bootstrap stopped: ${safeFailureCode(error)}`);
    process.exitCode = 1;
  });
}
