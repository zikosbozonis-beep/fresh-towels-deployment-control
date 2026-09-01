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
  createCloudflareHttpAdapter,
  createResendHttpAdapter,
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "./provider-adapter.mjs";
import { validateProviderCanaryCapsule } from "./protected-transport.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const workerIdPattern = /^[a-f0-9]{32}$/;
const requestIdPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const accountIdPattern = /^[a-f0-9]{32}$/;
const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const canaryNamePattern = /^ft-provider-canary-[a-f0-9]{12}-[a-f0-9]{7}$/;
const safeProviderIdPattern = /^[A-Za-z0-9._:-]{1,128}$/;
const releaseKeys = [
  "requestId",
  "releaseId",
  "applicationCommitSha",
  "controllerCommitSha",
  "artifactSha256",
  "plaintextSha256",
  "uploadArtifactSha256",
  "evidenceSha256",
];

export class ProviderCanaryError extends Error {
  constructor(code) {
    super(`Provider canary stopped: ${code}`);
    this.name = "ProviderCanaryError";
    this.code = code;
  }
}

export function classifyProviderCanaryFailure(error, provider) {
  if (error instanceof ProviderCanaryError) return error;
  if (!["cloudflare", "resend"].includes(provider)) {
    return new ProviderCanaryError("provider-response-invalid");
  }
  if (error instanceof ProviderRejectedError) {
    if (
      error.status === 401 ||
      (provider === "resend" && error.providerErrorCode === "invalid_api_key")
    ) {
      return new ProviderCanaryError(`${provider}-auth-failed`);
    }
    if (
      error.status === 403 ||
      (provider === "resend" && error.providerErrorCode === "restricted_api_key")
    ) {
      return new ProviderCanaryError(`${provider}-scope-failed`);
    }
    if (error.status === 404) {
      return new ProviderCanaryError(`${provider}-resource-mismatch`);
    }
    return new ProviderCanaryError(`${provider}-response-invalid`);
  }
  if (error instanceof ProviderTransportAmbiguousError) {
    if (
      error.code === "network-or-timeout" ||
      error.code === "response-read" ||
      /^http-(?:408|425|429|5[0-9]{2})$/.test(error.code ?? "")
    ) {
      return new ProviderCanaryError(`${provider}-network-failure`);
    }
    return new ProviderCanaryError(`${provider}-response-invalid`);
  }
  return new ProviderCanaryError(`${provider}-response-invalid`);
}

function fail(code) {
  throw new ProviderCanaryError(code);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactPlainObject(value, keys, code) {
  if (!isPlainObject(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(code);
  }
}

function canonicalDigest(value) {
  return sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function canonicalInstant(now) {
  const value = now().toISOString();
  if (new Date(value).toISOString() !== value) fail("non-canonical-time");
  return value;
}

function validateRelease(release, expected) {
  exactPlainObject(release, releaseKeys, "release-binding-shape");
  if (
    !requestIdPattern.test(release.requestId) ||
    !digestPattern.test(release.releaseId) ||
    !commitPattern.test(release.applicationCommitSha) ||
    !commitPattern.test(release.controllerCommitSha) ||
    releaseKeys.slice(4).some((key) => !digestPattern.test(release[key]))
  ) {
    fail("release-binding-format");
  }
  if (!expected || !isPlainObject(expected)) fail("trusted-release-binding-missing");
  for (const key of releaseKeys) {
    if (expected[key] !== release[key]) fail("release-binding-substitution");
  }
  return Object.freeze(structuredClone(release));
}

export function deriveTrustedProviderCanaryInput({
  capsuleBytes,
  encodedRequest,
  expectedControllerRepositoryId,
  expectedControllerSha,
  expectedSourceRepositoryId,
  now = new Date(),
}) {
  if (!(capsuleBytes instanceof Uint8Array)) fail("trusted-capsule-missing");
  let request;
  let capsule;
  try {
    const requestBytes = decodeCanonicalBase64Url(encodedRequest, "release request");
    request = JSON.parse(requestBytes.toString("utf8"));
    validateReleaseRequest(request, {
      expectedControllerRepositoryId,
      expectedControllerSha,
      expectedSourceRepositoryId,
      expectedOperation: "provider-canary",
      now,
    });
    if (
      request.artifact.plaintextBytes !== capsuleBytes.byteLength ||
      request.artifact.plaintextSha256 !== sha256(capsuleBytes)
    ) {
      fail("trusted-provider-canary-payload-digest");
    }
    capsule = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(capsuleBytes));
    validateProviderCanaryCapsule(capsule, capsuleBytes, request);
  } catch {
    fail("trusted-provider-canary-binding");
  }
  const release = Object.freeze({
    requestId: request.requestId,
    releaseId: capsule.providerCanary.canaryId,
    applicationCommitSha: request.source.commitSha,
    controllerCommitSha: request.controller.commitSha,
    artifactSha256: request.artifact.ciphertextSha256,
    plaintextSha256: request.artifact.plaintextSha256,
    uploadArtifactSha256: canonicalDigest(capsule.providerCanary),
    evidenceSha256: request.evidence.manifestSha256,
  });
  validateRelease(release, release);
  return Object.freeze({
    expectedCloudflareAccountId: capsule.providerCanary.targets.cloudflare.accountId,
    expectedResendDomain: capsule.providerCanary.targets.resend.domain,
    release,
  });
}

export function deriveProviderCanaryResourceName(release) {
  const name = `ft-provider-canary-${release.releaseId.slice(0, 12)}-${release.controllerCommitSha.slice(0, 7)}`;
  if (!canaryNamePattern.test(name)) fail("unsafe-disposable-resource-name");
  return name;
}

export function assertDisposableProviderCanaryName(name) {
  if (!canaryNamePattern.test(name) || /(?:^|-)prod(?:uction)?(?:-|$)/.test(name)) {
    fail("unsafe-disposable-resource-name");
  }
  return true;
}

function request(method, path, options = {}) {
  const bodyBytes = options.bodyBytes;
  return {
    method,
    path,
    body: options.body,
    bodyBytes,
    bodySha256: bodyBytes === undefined ? options.bodySha256 : sha256(bodyBytes),
    contentType: options.contentType,
    idempotencyKey: options.idempotencyKey ?? null,
    query: options.query,
  };
}

function requestEvidence(result) {
  return canonicalDigest({
    providerRequestIdSha256:
      result.providerRequestId === null
        ? canonicalDigest("none")
        : canonicalDigest(result.providerRequestId),
    responseSha256: result.responseSha256,
    status: result.status,
  });
}

function validateProviderResult(result, provider) {
  if (
    !isPlainObject(result) ||
    result.provider !== provider ||
    !Number.isSafeInteger(result.status) ||
    result.status < 200 ||
    result.status > 299 ||
    !digestPattern.test(result.responseSha256) ||
    (result.providerRequestId !== null && !safeProviderIdPattern.test(result.providerRequestId))
  ) {
    fail("provider-result-envelope");
  }
  return result;
}

async function providerRequest(client, provider, input) {
  try {
    return validateProviderResult(await client.request(input), provider);
  } catch (error) {
    if (error instanceof ProviderRejectedError || error instanceof ProviderTransportAmbiguousError) {
      throw error;
    }
    fail(`${provider}-response-invalid`);
  }
}

async function verifyCloudflareAccount(client, accountId) {
  const response = await providerRequest(
    client,
    "cloudflare",
    request("GET", `/accounts/${accountId}`),
  );
  if (!isPlainObject(response.result) || response.result.id !== accountId) {
    fail("cloudflare-account-substitution");
  }
  return canonicalDigest({
    accountId,
    requestEvidenceSha256: requestEvidence(response),
  });
}

function validateD1Record(value, { name, requireEu = true } = {}) {
  if (
    !isPlainObject(value) ||
    !uuidPattern.test(value.uuid ?? "") ||
    value.name !== name ||
    (requireEu && value.jurisdiction !== "eu")
  ) {
    fail("d1-resource-substitution");
  }
  return Object.freeze({ jurisdiction: value.jurisdiction, name: value.name, uuid: value.uuid });
}

async function listD1ByName(client, accountId, name) {
  const response = await providerRequest(
    client,
    "cloudflare",
    request("GET", `/accounts/${accountId}/d1/database`, {
      query: { name, page: "1", per_page: "10000" },
    }),
  );
  if (response.pagination?.complete !== true || !Array.isArray(response.result)) {
    fail("d1-list-incomplete");
  }
  const matches = response.result.filter((item) => isPlainObject(item) && item.name === name);
  if (matches.length > 1) fail("d1-resource-ambiguous");
  return Object.freeze({
    record: matches.length === 0 ? null : validateD1Record(matches[0], { name }),
    requestEvidenceSha256: requestEvidence(response),
  });
}

async function getD1ById(client, accountId, record) {
  try {
    const response = await providerRequest(
      client,
      "cloudflare",
      request("GET", `/accounts/${accountId}/d1/database/${record.uuid}`),
    );
    return Object.freeze({
      record: validateD1Record(response.result, { name: record.name }),
      requestEvidenceSha256: requestEvidence(response),
    });
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) {
      return Object.freeze({ record: null, requestEvidenceSha256: canonicalDigest("404") });
    }
    throw error;
  }
}

async function createD1(client, accountId, name, idempotencyKey) {
  const body = { jurisdiction: "eu", name };
  const input = request("POST", `/accounts/${accountId}/d1/database`, {
    body,
    bodySha256: canonicalDigest(body),
    idempotencyKey,
  });
  let createResponse = null;
  let createAmbiguous = false;
  try {
    createResponse = await providerRequest(client, "cloudflare", input);
  } catch (error) {
    if (!(error instanceof ProviderTransportAmbiguousError)) throw error;
    createAmbiguous = true;
  }
  let created = null;
  if (createResponse !== null) {
    try {
      created = validateD1Record(createResponse.result, { name });
    } catch (error) {
      if (!(error instanceof ProviderCanaryError)) throw error;
      createAmbiguous = true;
    }
  }
  let observed = created === null
    ? await listD1ByName(client, accountId, name)
    : await getD1ById(client, accountId, created);
  if (created !== null && observed.record === null) {
    const named = await listD1ByName(client, accountId, name);
    if (named.record !== null) fail("d1-create-substitution");
    observed = named;
  }
  if (observed.record === null) fail(createAmbiguous ? "d1-create-ambiguous" : "d1-create-not-visible");
  if (created !== null && created.uuid !== observed.record.uuid) fail("d1-create-substitution");
  return Object.freeze({
    record: observed.record,
    stateSha256: canonicalDigest({
      desired: { jurisdiction: "eu", name },
      observed: observed.record,
      createRequestEvidenceSha256:
        createResponse === null ? canonicalDigest("ambiguous") : requestEvidence(createResponse),
      reconcileRequestEvidenceSha256: observed.requestEvidenceSha256,
    }),
  });
}

async function verifyD1Query(client, accountId, record, idempotencyKey) {
  const body = { params: [], sql: "SELECT 1 AS provider_canary_value" };
  const response = await providerRequest(
    client,
    "cloudflare",
    request("POST", `/accounts/${accountId}/d1/database/${record.uuid}/query`, {
      body,
      bodySha256: canonicalDigest(body),
      idempotencyKey,
    }),
  );
  if (
    !Array.isArray(response.result) ||
    response.result.length !== 1 ||
    !isPlainObject(response.result[0]) ||
    response.result[0].success !== true ||
    !Array.isArray(response.result[0].results) ||
    response.result[0].results.length !== 1 ||
    !isPlainObject(response.result[0].results[0]) ||
    response.result[0].results[0].provider_canary_value !== 1
  ) {
    fail("d1-query-verification");
  }
  return canonicalDigest({
    databaseIdentitySha256: canonicalDigest(record),
    querySha256: canonicalDigest(body),
    requestEvidenceSha256: requestEvidence(response),
    verifiedValue: 1,
  });
}

async function deleteD1AndReconcile(client, accountId, record) {
  let deletion = null;
  let deletionError = null;
  try {
    deletion = await providerRequest(
      client,
      "cloudflare",
      request("DELETE", `/accounts/${accountId}/d1/database/${record.uuid}`),
    );
  } catch (error) {
    deletionError = error;
  }
  let observed;
  try {
    observed = await getD1ById(client, accountId, record);
  } catch {
    fail("d1-cleanup-reconciliation-unavailable");
  }
  if (observed.record !== null) fail("d1-cleanup-not-proven");
  if (
    deletionError !== null &&
    !(deletionError instanceof ProviderTransportAmbiguousError) &&
    !(deletionError instanceof ProviderRejectedError)
  ) {
    fail("d1-cleanup-client-contract");
  }
  return canonicalDigest({
    deletedIdentitySha256: canonicalDigest(record),
    deleteRequestEvidenceSha256:
      deletion === null ? canonicalDigest("reconciled-after-error") : requestEvidence(deletion),
    reconcileRequestEvidenceSha256: observed.requestEvidenceSha256,
    state: "absent",
  });
}

function workerMultipart(release, name) {
  const moduleBytes = Buffer.from(
    'export default { fetch() { return new Response("provider-canary"); } };\n',
    "utf8",
  );
  const moduleSha256 = sha256(moduleBytes);
  const boundary = `fresh-towels-${release.releaseId.slice(0, 24)}`;
  const metadata = {
    annotations: {
      "workers/message": `provider-canary:${release.applicationCommitSha}:${moduleSha256}`,
      "workers/tag": release.releaseId.slice(0, 32),
    },
    compatibility_date: "2026-08-31",
    main_module: "index.js",
  };
  const chunks = [
    `--${boundary}\r\nContent-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n${canonicalJson(metadata)}\r\n`,
    `--${boundary}\r\nContent-Disposition: form-data; name="index.js"; filename="index.js"\r\nContent-Type: application/javascript+module\r\n\r\n`,
    moduleBytes,
    `\r\n--${boundary}--\r\n`,
  ];
  const bytes = Buffer.concat(chunks.map((chunk) => (Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))));
  return Object.freeze({
    bytes,
    contentType: `multipart/form-data; boundary=${boundary}`,
    desiredStateSha256: canonicalDigest({ metadata, moduleSha256, name }),
    metadata,
    moduleSha256,
  });
}

function validateWorkerContainer(value, { expectedId = null, expectedName }) {
  if (
    !isPlainObject(value) ||
    !workerIdPattern.test(value.id ?? "") ||
    value.name !== expectedName ||
    (expectedId !== null && value.id !== expectedId) ||
    value.deployed_on !== null ||
    !isPlainObject(value.subdomain) ||
    value.subdomain.enabled !== false ||
    value.subdomain.previews_enabled !== false ||
    !Array.isArray(value.tags) ||
    value.tags.length !== 1 ||
    value.tags[0] !== "fresh-towels-provider-canary"
  ) {
    fail("worker-container-substitution");
  }
  return Object.freeze({ id: value.id, name: value.name });
}

async function getWorkerContainer(client, accountId, identifier, expectedName) {
  let response;
  try {
    response = await providerRequest(
      client,
      "cloudflare",
      request("GET", `/accounts/${accountId}/workers/workers/${identifier}`),
    );
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) {
      return Object.freeze({ record: null, requestEvidenceSha256: canonicalDigest("404") });
    }
    throw error;
  }
  const record = validateWorkerContainer(response.result, {
    expectedId: workerIdPattern.test(identifier) ? identifier : null,
    expectedName,
  });
  return Object.freeze({
    record,
    requestEvidenceSha256: requestEvidence(response),
    stateSha256: canonicalDigest({
      deployed: false,
      id: record.id,
      name: record.name,
      previewsEnabled: false,
      subdomainEnabled: false,
      tags: ["fresh-towels-provider-canary"],
    }),
  });
}

async function getWorkerIdentityForCleanup(client, accountId, expectedName) {
  let response;
  try {
    response = await providerRequest(
      client,
      "cloudflare",
      request("GET", `/accounts/${accountId}/workers/workers/${expectedName}`),
    );
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) return null;
    throw error;
  }
  if (
    !isPlainObject(response.result) ||
    !workerIdPattern.test(response.result.id ?? "") ||
    response.result.name !== expectedName ||
    !Array.isArray(response.result.tags) ||
    response.result.tags.length !== 1 ||
    response.result.tags[0] !== "fresh-towels-provider-canary"
  ) {
    fail("worker-cleanup-identity-untrusted");
  }
  return Object.freeze({ id: response.result.id, name: response.result.name });
}

async function createWorkerContainer(client, accountId, name, idempotencyKey) {
  const body = {
    name,
    subdomain: { enabled: false, previews_enabled: false },
    tags: ["fresh-towels-provider-canary"],
  };
  let response = null;
  let responseRecord = null;
  try {
    response = await providerRequest(
      client,
      "cloudflare",
      request("POST", `/accounts/${accountId}/workers/workers`, {
        body,
        bodySha256: canonicalDigest(body),
        idempotencyKey,
      }),
    );
    try {
      responseRecord = validateWorkerContainer(response.result, { expectedName: name });
    } catch (error) {
      if (!(error instanceof ProviderCanaryError)) throw error;
    }
  } catch (error) {
    if (!(error instanceof ProviderTransportAmbiguousError)) throw error;
  }
  const observed = await getWorkerContainer(client, accountId, name, name);
  if (observed.record === null) fail("worker-container-create-ambiguous");
  if (response !== null && responseRecord === null) fail("worker-container-create-substitution");
  if (responseRecord !== null && responseRecord.id !== observed.record.id) {
    fail("worker-container-create-substitution");
  }
  return Object.freeze({
    record: observed.record,
    stateSha256: canonicalDigest({
      createRequestEvidenceSha256:
        response === null ? canonicalDigest("ambiguous") : requestEvidence(response),
      observedStateSha256: observed.stateSha256,
      reconcileRequestEvidenceSha256: observed.requestEvidenceSha256,
    }),
  });
}

async function getWorkerSettings(client, accountId, name, upload) {
  const response = await providerRequest(
    client,
    "cloudflare",
    request("GET", `/accounts/${accountId}/workers/scripts/${name}/settings`),
  );
  const value = response.result;
  const expectedAnnotations = upload.metadata.annotations;
  if (
    !isPlainObject(value) ||
    !isPlainObject(value.annotations) ||
    value.annotations["workers/message"] !== expectedAnnotations["workers/message"] ||
    value.annotations["workers/tag"] !== expectedAnnotations["workers/tag"] ||
    Object.keys(value.annotations).some(
      (key) => !["workers/message", "workers/tag", "workers/triggered_by"].includes(key),
    ) ||
    value.compatibility_date !== upload.metadata.compatibility_date ||
    (value.compatibility_flags !== undefined &&
      (!Array.isArray(value.compatibility_flags) || value.compatibility_flags.length !== 0)) ||
    (value.bindings !== undefined &&
      (!Array.isArray(value.bindings) || value.bindings.length !== 0))
  ) {
    fail("worker-settings-substitution");
  }
  return Object.freeze({
    stateSha256: canonicalDigest({
      annotations: expectedAnnotations,
      bindings: [],
      compatibilityDate: value.compatibility_date,
    }),
    requestEvidenceSha256: requestEvidence(response),
  });
}

async function listWorkerVersions(client, accountId, name) {
  let response;
  try {
    response = await providerRequest(
      client,
      "cloudflare",
      request("GET", `/accounts/${accountId}/workers/scripts/${name}/versions`, {
        query: { page: "1", per_page: "100" },
      }),
    );
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) {
      return Object.freeze({ exists: false, items: [], requestEvidenceSha256: canonicalDigest("404") });
    }
    throw error;
  }
  if (
    response.pagination?.complete !== true ||
    !isPlainObject(response.result) ||
    !Array.isArray(response.result.items)
  ) {
    fail("worker-version-list-envelope");
  }
  const items = response.result.items.map((item) => {
    if (!isPlainObject(item) || !uuidPattern.test(item.id ?? "")) fail("worker-version-substitution");
    return Object.freeze({ id: item.id });
  });
  return Object.freeze({
    exists: true,
    items,
    requestEvidenceSha256: requestEvidence(response),
  });
}

function validateWorkerVersionState(
  value,
  { expectedProviderEtag = null, expectedVersionId, upload },
) {
  const expectedAnnotations = upload.metadata.annotations;
  if (
    !isPlainObject(value) ||
    value.id !== expectedVersionId ||
    !isPlainObject(value.annotations) ||
    value.annotations["workers/message"] !== expectedAnnotations["workers/message"] ||
    value.annotations["workers/tag"] !== expectedAnnotations["workers/tag"] ||
    Object.keys(value.annotations).some(
      (key) => !["workers/message", "workers/tag", "workers/triggered_by"].includes(key),
    ) ||
    !isPlainObject(value.resources) ||
    !isPlainObject(value.resources.script) ||
    !digestPattern.test(value.resources.script.etag ?? "") ||
    (expectedProviderEtag !== null && value.resources.script.etag !== expectedProviderEtag) ||
    !isPlainObject(value.resources.script_runtime) ||
    value.resources.script_runtime.compatibility_date !== upload.metadata.compatibility_date ||
    (value.resources.script_runtime.compatibility_flags !== undefined &&
      (!Array.isArray(value.resources.script_runtime.compatibility_flags) ||
        value.resources.script_runtime.compatibility_flags.length !== 0)) ||
    !Array.isArray(value.resources.bindings) ||
    value.resources.bindings.length !== 0
  ) {
    fail("worker-version-detail-substitution");
  }
  return Object.freeze({
    providerEtag: value.resources.script.etag,
    stateSha256: canonicalDigest({
      annotations: expectedAnnotations,
      bindings: [],
      compatibilityDate: value.resources.script_runtime.compatibility_date,
      moduleSha256: upload.moduleSha256,
      providerEtag: value.resources.script.etag,
      versionId: expectedVersionId,
    }),
  });
}

async function getWorkerVersion(
  client,
  accountId,
  name,
  versionId,
  upload,
  expectedProviderEtag,
) {
  const response = await providerRequest(
    client,
    "cloudflare",
    request("GET", `/accounts/${accountId}/workers/scripts/${name}/versions/${versionId}`),
  );
  const state = validateWorkerVersionState(response.result, {
    expectedProviderEtag,
    expectedVersionId: versionId,
    upload,
  });
  return Object.freeze({
    providerEtag: state.providerEtag,
    stateSha256: state.stateSha256,
    requestEvidenceSha256: requestEvidence(response),
  });
}

async function createWorkerVersion(
  client,
  accountId,
  container,
  release,
  idempotencyKey,
) {
  const name = container.name;
  const upload = workerMultipart(release, name);
  let response = null;
  let versionId = null;
  let createdVersionState = null;
  try {
    response = await providerRequest(
      client,
      "cloudflare",
      request("POST", `/accounts/${accountId}/workers/scripts/${name}/versions`, {
        bodyBytes: upload.bytes,
        contentType: upload.contentType,
        idempotencyKey,
      }),
    );
    if (!isPlainObject(response.result) || !uuidPattern.test(response.result.id ?? "")) {
      response = null;
    } else {
      versionId = response.result.id;
      createdVersionState = validateWorkerVersionState(response.result, {
        expectedVersionId: versionId,
        upload,
      });
    }
  } catch (error) {
    if (!(error instanceof ProviderTransportAmbiguousError)) throw error;
  }
  const observed = await listWorkerVersions(client, accountId, name);
  if (!observed.exists || observed.items.length !== 1) fail("worker-create-ambiguous");
  if (versionId !== null && observed.items[0].id !== versionId) fail("worker-create-substitution");
  versionId = observed.items[0].id;
  const detail = await getWorkerVersion(
    client,
    accountId,
    name,
    versionId,
    upload,
    createdVersionState?.providerEtag ?? null,
  );
  const settings = await getWorkerSettings(client, accountId, name, upload);
  const containerAfterUpload = await getWorkerContainer(
    client,
    accountId,
    container.id,
    name,
  );
  if (containerAfterUpload.record === null) fail("worker-container-disappeared");
  return Object.freeze({
    desiredStateSha256: upload.desiredStateSha256,
    versionId,
    stateSha256: canonicalDigest({
      createRequestEvidenceSha256:
        response === null ? canonicalDigest("ambiguous") : requestEvidence(response),
      desiredStateSha256: upload.desiredStateSha256,
      detailRequestEvidenceSha256: detail.requestEvidenceSha256,
      observedStateSha256: detail.stateSha256,
      settingsRequestEvidenceSha256: settings.requestEvidenceSha256,
      settingsStateSha256: settings.stateSha256,
      containerRequestEvidenceSha256: containerAfterUpload.requestEvidenceSha256,
      containerStateSha256: containerAfterUpload.stateSha256,
      reconcileRequestEvidenceSha256: observed.requestEvidenceSha256,
      versionIdentitySha256: canonicalDigest(versionId),
    }),
  });
}

async function deleteWorkerAndReconcile(client, accountId, record) {
  let deletion = null;
  let deletionError = null;
  try {
    deletion = await providerRequest(
      client,
      "cloudflare",
      request("DELETE", `/accounts/${accountId}/workers/workers/${record.id}`),
    );
  } catch (error) {
    deletionError = error;
  }
  let observedById;
  let observedByName;
  try {
    observedById = await getWorkerContainer(client, accountId, record.id, record.name);
    observedByName = await getWorkerContainer(client, accountId, record.name, record.name);
  } catch {
    fail("worker-cleanup-reconciliation-unavailable");
  }
  if (observedById.record !== null || observedByName.record !== null) {
    fail("worker-cleanup-not-proven");
  }
  if (
    deletionError !== null &&
    !(deletionError instanceof ProviderTransportAmbiguousError) &&
    !(deletionError instanceof ProviderRejectedError)
  ) {
    fail("worker-cleanup-client-contract");
  }
  return canonicalDigest({
    deleteRequestEvidenceSha256:
      deletion === null ? canonicalDigest("reconciled-after-error") : requestEvidence(deletion),
    reconcileByIdRequestEvidenceSha256: observedById.requestEvidenceSha256,
    reconcileByNameRequestEvidenceSha256: observedByName.requestEvidenceSha256,
    resourceIdentitySha256: canonicalDigest(record),
    state: "absent",
  });
}

async function verifyResendDomain(client, expectedDomain) {
  const response = await providerRequest(client, "resend", request("GET", "/domains"));
  const envelope = response.result;
  if (
    !isPlainObject(envelope) ||
    envelope.object !== "list" ||
    !Array.isArray(envelope.data) ||
    envelope.has_more !== false
  ) {
    fail("resend-domain-list-incomplete");
  }
  const matches = envelope.data.filter(
    (item) => isPlainObject(item) && item.name === expectedDomain,
  );
  if (matches.length !== 1) fail("resend-domain-substitution");
  const domain = matches[0];
  const allowedDomainStatuses = new Set([
    "not_started",
    "pending",
    "verified",
    "failed",
    "temporary_failure",
  ]);
  if (
    !uuidPattern.test(domain.id ?? "") ||
    !allowedDomainStatuses.has(domain.status) ||
    typeof domain.region !== "string" ||
    !/^[a-z0-9-]{3,32}$/.test(domain.region) ||
    !isPlainObject(domain.capabilities) ||
    !["enabled", "disabled"].includes(domain.capabilities.sending) ||
    !["enabled", "disabled"].includes(domain.capabilities.receiving)
  ) {
    fail("resend-domain-state-envelope");
  }
  return canonicalDigest({
    domainIdentitySha256: canonicalDigest({ id: domain.id, name: domain.name }),
    capabilities: {
      receiving: domain.capabilities.receiving,
      sending: domain.capabilities.sending,
    },
    region: domain.region,
    requestEvidenceSha256: requestEvidence(response),
    status: domain.status,
  });
}

function receiptBody({
  release,
  completedAt,
  cloudflareAccountStateSha256,
  d1DesiredStateSha256,
  d1VerifiedStateSha256,
  d1DeletedStateSha256,
  workerDesiredStateSha256,
  workerVerifiedStateSha256,
  workerDeletedStateSha256,
  resendDomainStateSha256,
}) {
  return {
    schema: "deployment-control/provider-canary-receipt/v1",
    requestId: release.requestId,
    releaseId: release.releaseId,
    applicationCommitSha: release.applicationCommitSha,
    controllerCommitSha: release.controllerCommitSha,
    artifactSha256: release.artifactSha256,
    plaintextSha256: release.plaintextSha256,
    uploadArtifactSha256: release.uploadArtifactSha256,
    evidenceSha256: release.evidenceSha256,
    cloudflareAccountStateSha256,
    d1DesiredStateSha256,
    d1VerifiedStateSha256,
    d1DeletedStateSha256,
    workerDesiredStateSha256,
    workerVerifiedStateSha256,
    workerDeletedStateSha256,
    resendDomainStateSha256,
    completedAt,
  };
}

export function validateProviderCanaryReceipt(receipt, expectedRelease) {
  const keys = [
    ...Object.keys(
      receiptBody({
        release: Object.fromEntries(releaseKeys.map((key) => [key, ""])),
        completedAt: "",
        cloudflareAccountStateSha256: "",
        d1DesiredStateSha256: "",
        d1VerifiedStateSha256: "",
        d1DeletedStateSha256: "",
        workerDesiredStateSha256: "",
        workerVerifiedStateSha256: "",
        workerDeletedStateSha256: "",
        resendDomainStateSha256: "",
      }),
    ),
    "receiptSha256",
  ];
  exactPlainObject(receipt, keys, "provider-canary-receipt-shape");
  const { receiptSha256, ...body } = receipt;
  if (receipt.schema !== "deployment-control/provider-canary-receipt/v1") {
    fail("provider-canary-receipt-schema");
  }
  validateRelease(
    Object.fromEntries(releaseKeys.map((key) => [key, receipt[key]])),
    expectedRelease,
  );
  for (const key of Object.keys(receipt).filter((key) => key.endsWith("Sha256"))) {
    if (!digestPattern.test(receipt[key])) fail("provider-canary-receipt-digest");
  }
  const timestamp = Date.parse(receipt.completedAt);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== receipt.completedAt) {
    fail("provider-canary-receipt-time");
  }
  if (canonicalDigest(body) !== receiptSha256) fail("provider-canary-receipt-binding");
  return true;
}

export async function persistProviderCanaryReceipt({
  outputPath,
  receipt,
  expectedRelease,
  githubOutput,
}) {
  validateProviderCanaryReceipt(receipt, expectedRelease);
  await writeFile(outputPath, `${canonicalJson(receipt)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  if (githubOutput) {
    await appendFile(githubOutput, `receipt_sha256=${receipt.receiptSha256}\n`, "utf8");
  }
}

export async function runProviderCanary({
  release,
  expectedRelease,
  expectedCloudflareAccountId,
  expectedResendDomain,
  cloudflareClient,
  resendClient,
  now = () => new Date(),
}) {
  const verifiedRelease = validateRelease(release, expectedRelease);
  if (
    !accountIdPattern.test(expectedCloudflareAccountId ?? "") ||
    !domainPattern.test(expectedResendDomain ?? "") ||
    expectedResendDomain !== expectedResendDomain.toLowerCase() ||
    !cloudflareClient ||
    typeof cloudflareClient.request !== "function" ||
    !resendClient ||
    typeof resendClient.request !== "function"
  ) {
    fail("provider-canary-configuration");
  }
  const resourceName = deriveProviderCanaryResourceName(verifiedRelease);
  assertDisposableProviderCanaryName(resourceName);
  const idempotencyRoot = canonicalDigest({
    operation: "provider-canary",
    release: verifiedRelease,
    resourceName,
  });
  let cloudflareAccountStateSha256;
  try {
    cloudflareAccountStateSha256 = await verifyCloudflareAccount(
      cloudflareClient,
      expectedCloudflareAccountId,
    );
    const initialD1 = await listD1ByName(
      cloudflareClient,
      expectedCloudflareAccountId,
      resourceName,
    );
    if (initialD1.record !== null) fail("d1-previous-execution-ambiguous");
    const initialWorker = await getWorkerContainer(
      cloudflareClient,
      expectedCloudflareAccountId,
      resourceName,
      resourceName,
    );
    if (initialWorker.record !== null) fail("worker-previous-execution-ambiguous");
  } catch (error) {
    throw classifyProviderCanaryFailure(error, "cloudflare");
  }

  let d1Record = null;
  let d1CreateAttempted = false;
  let workerRecord = null;
  let workerCreateAttempted = false;
  let primaryError = null;
  let primaryProvider = "cloudflare";
  let d1DesiredStateSha256 = canonicalDigest({ jurisdiction: "eu", name: resourceName });
  let d1VerifiedStateSha256 = canonicalDigest("not-verified");
  let d1DeletedStateSha256 = canonicalDigest("not-deleted");
  const workerUpload = workerMultipart(verifiedRelease, resourceName);
  let workerVerifiedStateSha256 = canonicalDigest("not-verified");
  let workerDeletedStateSha256 = canonicalDigest("not-deleted");
  let resendDomainStateSha256 = canonicalDigest("not-verified");
  try {
    d1CreateAttempted = true;
    const d1 = await createD1(
      cloudflareClient,
      expectedCloudflareAccountId,
      resourceName,
      canonicalDigest({ idempotencyRoot, step: "d1-create" }),
    );
    d1Record = d1.record;
    d1VerifiedStateSha256 = canonicalDigest({
      createStateSha256: d1.stateSha256,
      queryStateSha256: await verifyD1Query(
        cloudflareClient,
        expectedCloudflareAccountId,
        d1Record,
        canonicalDigest({ idempotencyRoot, step: "d1-query" }),
      ),
    });
    workerCreateAttempted = true;
    const workerContainer = await createWorkerContainer(
      cloudflareClient,
      expectedCloudflareAccountId,
      resourceName,
      canonicalDigest({ idempotencyRoot, step: "worker-container-create" }),
    );
    workerRecord = workerContainer.record;
    const worker = await createWorkerVersion(
      cloudflareClient,
      expectedCloudflareAccountId,
      workerRecord,
      verifiedRelease,
      canonicalDigest({ idempotencyRoot, step: "worker-version-create" }),
    );
    workerVerifiedStateSha256 = canonicalDigest({
      containerStateSha256: workerContainer.stateSha256,
      versionStateSha256: worker.stateSha256,
    });
    primaryProvider = "resend";
    resendDomainStateSha256 = await verifyResendDomain(resendClient, expectedResendDomain);
  } catch (error) {
    primaryError = error;
  } finally {
    let cleanupError = null;
    if (workerCreateAttempted) {
      try {
        if (workerRecord === null) {
          workerRecord = await getWorkerIdentityForCleanup(
            cloudflareClient,
            expectedCloudflareAccountId,
            resourceName,
          );
        }
        if (workerRecord !== null) {
          workerDeletedStateSha256 = await deleteWorkerAndReconcile(
            cloudflareClient,
            expectedCloudflareAccountId,
            workerRecord,
          );
        }
      } catch (error) {
        cleanupError = error;
      }
    }
    if (d1CreateAttempted && d1Record === null) {
      try {
        const observed = await listD1ByName(
          cloudflareClient,
          expectedCloudflareAccountId,
          resourceName,
        );
        d1Record = observed.record;
      } catch (error) {
        cleanupError ??= error;
      }
    }
    if (d1Record !== null) {
      try {
        d1DeletedStateSha256 = await deleteD1AndReconcile(
          cloudflareClient,
          expectedCloudflareAccountId,
          d1Record,
        );
      } catch (error) {
        cleanupError ??= error;
      }
    }
    if (
      cleanupError instanceof ProviderCanaryError &&
      cleanupError.code === "worker-cleanup-identity-untrusted"
    ) {
      throw cleanupError;
    }
    if (cleanupError !== null) fail("disposable-cleanup-not-proven");
  }
  if (primaryError !== null) {
    throw classifyProviderCanaryFailure(primaryError, primaryProvider);
  }
  const body = receiptBody({
    release: verifiedRelease,
    completedAt: canonicalInstant(now),
    cloudflareAccountStateSha256,
    d1DesiredStateSha256,
    d1VerifiedStateSha256,
    d1DeletedStateSha256,
    workerDesiredStateSha256: workerUpload.desiredStateSha256,
    workerVerifiedStateSha256,
    workerDeletedStateSha256,
    resendDomainStateSha256,
  });
  const receipt = Object.freeze({ ...body, receiptSha256: canonicalDigest(body) });
  validateProviderCanaryReceipt(receipt, verifiedRelease);
  return receipt;
}

function requiredEnvironment(name, pattern) {
  const value = process.env[name];
  if (typeof value !== "string" || (pattern && !pattern.test(value))) {
    fail("missing-protected-provider-configuration");
  }
  return value;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--capsule" || args[2] !== "--output") {
    fail("provider-canary-cli-arguments");
  }
  const capsulePath = resolve(args[1]);
  const outputPath = resolve(args[3]);
  const trusted = deriveTrustedProviderCanaryInput({
    capsuleBytes: await readFile(capsulePath),
    encodedRequest: requiredEnvironment("RELEASE_REQUEST_BASE64", /^[A-Za-z0-9_-]{100,32768}$/),
    expectedControllerRepositoryId: requiredEnvironment(
      "EXPECTED_CONTROLLER_REPOSITORY_ID",
      /^[1-9][0-9]{0,19}$/,
    ),
    expectedControllerSha: requiredEnvironment("GITHUB_SHA", commitPattern),
    expectedSourceRepositoryId: requiredEnvironment(
      "EXPECTED_SOURCE_REPOSITORY_ID",
      /^[1-9][0-9]{0,19}$/,
    ),
  });
  const cloudflareClient = createCloudflareHttpAdapter({
    token: requiredEnvironment("CLOUDFLARE_PROVIDER_CANARY_TOKEN", /^\S{20,2048}$/),
  });
  const resendClient = createResendHttpAdapter({
    token: requiredEnvironment("RESEND_PROVIDER_CANARY_TOKEN", /^\S{20,2048}$/),
  });
  const receipt = await runProviderCanary({
    release: trusted.release,
    expectedRelease: trusted.release,
    expectedCloudflareAccountId: trusted.expectedCloudflareAccountId,
    expectedResendDomain: trusted.expectedResendDomain,
    cloudflareClient,
    resendClient,
  });
  await persistProviderCanaryReceipt({
    outputPath,
    receipt,
    expectedRelease: trusted.release,
    githubOutput: process.env.GITHUB_OUTPUT,
  });
  process.stdout.write("Provider canary completed; hash-only receipt written.\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    const code = error instanceof ProviderCanaryError ? error.code : "unexpected-failure";
    console.error(`Provider canary stopped: ${code}`);
    process.exitCode = 1;
  });
}
