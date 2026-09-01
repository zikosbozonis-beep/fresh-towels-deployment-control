#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  appendFile,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateReleaseRequest,
} from "./control-contract.mjs";
import { validateProductionCapsuleContents } from "./production-capsule.mjs";
import { validateProductionCutoverCapsule } from "./production-cutover-capsule.mjs";
import { validateProductionDnsStageCapsule } from "./production-dns-stage.mjs";
import { validateProductionBootstrapCapsule } from "./production-provider-bootstrap.mjs";

const maximumEnvelopeBytes = 128 * 1024 * 1024;
const shaPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const privateApplicationRepository = "zikosbozonis-beep/fresh-towels-website";
const privateApplicationWorkflow = ".github/workflows/release-handoff.yml";
const controllerRepository = "zikosbozonis-beep/fresh-towels-deployment-control";
const controllerWorkflow = ".github/workflows/package-release.yml";

function exactKeys(value, keys, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains missing or unexpected fields`);
  }
}

function canonicalInstant(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${label} is not canonical UTC`);
  }
  return timestamp;
}

function validateCapsuleWindow(capsule, request) {
  const createdAt = canonicalInstant(capsule.createdAt, "capsule createdAt");
  const validUntil = canonicalInstant(capsule.validUntil, "capsule validUntil");
  const issuedAt = canonicalInstant(request.issuedAt, "request issuedAt");
  if (
    validUntil - createdAt !== 2 * 60 * 60 * 1000 ||
    createdAt > issuedAt + 60_000 ||
    createdAt < issuedAt - 30 * 60 * 1000 ||
    validUntil <= Date.parse(request.expiresAt)
  ) {
    throw new Error("capsule validity window differs from the request");
  }
}

function validateCommonCapsuleIdentity(capsule, request) {
  exactKeys(
    capsule.application,
    [
      "repository",
      "repositoryId",
      "ref",
      "commitSha",
      "workflowRef",
      "workflowSha",
      "runId",
      "runAttempt",
    ],
    "capsule application",
  );
  exactKeys(capsule.controller, ["repository", "commitSha", "workflowRef"], "capsule controller");
  const expectedApplication = {
    repository: privateApplicationRepository,
    repositoryId: request.source.repositoryId,
    ref: "refs/heads/main",
    commitSha: request.source.commitSha,
    workflowRef: `${privateApplicationRepository}/${privateApplicationWorkflow}@refs/heads/main`,
    workflowSha: request.source.commitSha,
    runId: request.source.workflowRunId,
    runAttempt: request.source.workflowRunAttempt,
  };
  for (const [name, expected] of Object.entries(expectedApplication)) {
    if (capsule.application[name] !== expected) {
      throw new Error(`capsule application ${name} differs from the signed request`);
    }
  }
  const expectedController = {
    repository: controllerRepository,
    commitSha: request.controller.commitSha,
    workflowRef: `${controllerRepository}/${controllerWorkflow}@${request.controller.commitSha}`,
  };
  for (const [name, expected] of Object.entries(expectedController)) {
    if (capsule.controller[name] !== expected) {
      throw new Error(`capsule controller ${name} differs from the signed request`);
    }
  }
  validateCapsuleWindow(capsule, request);
}

function canaryId(capsule) {
  return sha256(
    Buffer.from(
      [
        capsule.application.commitSha,
        capsule.controller.commitSha,
        capsule.application.runId,
        capsule.application.runAttempt,
        capsule.createdAt,
      ].join("\0"),
      "utf8",
    ),
  );
}

function validateCanaryCapsule(capsule, bytes, request) {
  exactKeys(
    capsule,
    [
      "application",
      "canary",
      "capsuleType",
      "controller",
      "createdAt",
      "operation",
      "schemaVersion",
      "validUntil",
    ],
    "canary capsule",
  );
  exactKeys(
    capsule.canary,
    ["canaryId", "intent", "productionCredentialsPresent", "providerMutationAuthorized"],
    "canary declaration",
  );
  if (
    capsule.schemaVersion !== 1 ||
    capsule.capsuleType !== "fresh-towels-protected-executor-canary" ||
    capsule.operation !== "canary" ||
    capsule.canary.intent !== "verify-protected-boundary-without-provider-mutation" ||
    capsule.canary.productionCredentialsPresent !== false ||
    capsule.canary.providerMutationAuthorized !== false ||
    typeof capsule.canary.canaryId !== "string" ||
    !digestPattern.test(capsule.canary.canaryId) ||
    capsule.canary.canaryId !== canaryId(capsule)
  ) {
    throw new Error("canary capsule declaration is invalid");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (`${canonicalJson(capsule)}\n` !== text || bytes.byteLength > 4096) {
    throw new Error("canary capsule is not canonical or exceeds its boundary");
  }
  validateCommonCapsuleIdentity(capsule, request);
}

function providerCanaryId(capsule) {
  return sha256(
    Buffer.from(
      canonicalJson({
        applicationCommitSha: capsule.application.commitSha,
        controllerCommitSha: capsule.controller.commitSha,
        createdAt: capsule.createdAt,
        runAttempt: String(capsule.application.runAttempt),
        runId: capsule.application.runId,
        safeguards: capsule.providerCanary.safeguards,
        targets: capsule.providerCanary.targets,
      }),
      "utf8",
    ),
  );
}

export function validateProviderCanaryCapsule(capsule, bytes, request) {
  exactKeys(
    capsule,
    [
      "application",
      "capsuleType",
      "controller",
      "createdAt",
      "operation",
      "providerCanary",
      "schemaVersion",
      "validUntil",
    ],
    "provider canary capsule",
  );
  exactKeys(
    capsule.providerCanary,
    ["canaryId", "intent", "safeguards", "targets"],
    "provider canary declaration",
  );
  exactKeys(
    capsule.providerCanary.safeguards,
    [
      "cleanupRequired",
      "productionAccessMutationAuthorized",
      "productionD1MutationAuthorized",
      "productionDnsMutationAuthorized",
      "productionEmailAuthorized",
      "productionTrafficMutationAuthorized",
    ],
    "provider canary safeguards",
  );
  exactKeys(
    capsule.providerCanary.targets,
    ["cloudflare", "resend"],
    "provider canary targets",
  );
  exactKeys(
    capsule.providerCanary.targets.cloudflare,
    ["accountId", "jurisdiction"],
    "provider canary Cloudflare target",
  );
  exactKeys(
    capsule.providerCanary.targets.resend,
    ["domain", "mutationAuthorized"],
    "provider canary Resend target",
  );
  const safeguards = capsule.providerCanary.safeguards;
  const cloudflare = capsule.providerCanary.targets.cloudflare;
  const resend = capsule.providerCanary.targets.resend;
  if (
    capsule.schemaVersion !== 1 ||
    capsule.capsuleType !== "fresh-towels-provider-canary-capsule" ||
    capsule.operation !== "provider-canary" ||
    capsule.providerCanary.intent !==
      "verify-real-provider-adapter-on-disposable-non-production-resources" ||
    capsule.providerCanary.canaryId !== providerCanaryId(capsule) ||
    !digestPattern.test(capsule.providerCanary.canaryId ?? "") ||
    safeguards.cleanupRequired !== true ||
    Object.entries(safeguards)
      .filter(([name]) => name !== "cleanupRequired")
      .some(([, value]) => value !== false) ||
    !/^[a-f0-9]{32}$/.test(cloudflare.accountId ?? "") ||
    /^0+$/.test(cloudflare.accountId) ||
    cloudflare.jurisdiction !== "eu" ||
    resend.domain !== "notify.freshtowels.gr" ||
    resend.mutationAuthorized !== false
  ) {
    throw new Error("provider canary declaration is invalid");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (`${canonicalJson(capsule)}\n` !== text || bytes.byteLength > 8192) {
    throw new Error("provider canary capsule is not canonical or exceeds its boundary");
  }
  validateCommonCapsuleIdentity(capsule, request);
  return capsule;
}

function validateProductionCapsule(capsule, request, bytes) {
  exactKeys(
    capsule,
    [
      "application",
      "capsuleType",
      "controller",
      "createdAt",
      "operation",
      "payload",
      "releaseId",
      "releaseIntegrity",
      "releasePrerequisite",
      "schemaVersion",
      "validUntil",
    ],
    "production capsule",
  );
  if (
    capsule.schemaVersion !== 2 ||
    capsule.capsuleType !== "fresh-towels-private-release-capsule" ||
    capsule.operation !== "production-release" ||
    typeof capsule.releaseId !== "string" ||
    !digestPattern.test(capsule.releaseId)
  ) {
    throw new Error("production capsule declaration is invalid");
  }
  exactKeys(
    capsule.releaseIntegrity,
    [
      "buildArtifactSha256",
      "databaseSchemaSha256",
      "releaseApprovalManifestSha256",
      "configurationTemplateSha256",
      "uploadArtifactSha256",
      "capsuleTreeSha256",
      "productionInfrastructureReceiptSha256",
    ],
    "production capsule integrity",
  );
  if (
    Object.values(capsule.releaseIntegrity).some(
      (value) => typeof value !== "string" || !digestPattern.test(value),
    )
  ) {
    throw new Error("production capsule integrity is invalid");
  }
  exactKeys(
    capsule.payload,
    ["encoding", "rawBytes", "fileCount", "entries"],
    "production capsule payload",
  );
  if (
    capsule.payload.encoding !== "base64-per-file" ||
    !Number.isSafeInteger(capsule.payload.rawBytes) ||
    capsule.payload.rawBytes < 1 ||
    capsule.payload.rawBytes > 32 * 1024 * 1024 ||
    !Number.isSafeInteger(capsule.payload.fileCount) ||
    capsule.payload.fileCount < 1 ||
    capsule.payload.fileCount > 4096 ||
    !Array.isArray(capsule.payload.entries) ||
    capsule.payload.entries.length !== capsule.payload.fileCount
  ) {
    throw new Error("production capsule payload boundary is invalid");
  }
  validateCommonCapsuleIdentity(capsule, request);
  validateProductionCapsuleContents(capsule, bytes);
}

export function validateOperationPayload(payload, request, options = {}) {
  let capsule;
  try {
    capsule = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    throw new Error("release capsule is not valid UTF-8 JSON");
  }
  if (request.operation === "canary") {
    validateCanaryCapsule(capsule, payload, request);
  } else if (request.operation === "provider-canary") {
    validateProviderCanaryCapsule(capsule, payload, request);
  } else if (request.operation === "production-dns-stage") {
    validateCommonCapsuleIdentity(capsule, request);
    validateProductionDnsStageCapsule({
      capsule,
      capsuleBytes: Buffer.from(payload),
      expectedCapsuleSha256: request.artifact.plaintextSha256,
      now: options.now ?? new Date(),
    });
  } else if (request.operation === "production-bootstrap") {
    validateCommonCapsuleIdentity(capsule, request);
    validateProductionBootstrapCapsule({
      capsule,
      capsuleBytes: Buffer.from(payload),
      expectedCapsuleSha256: request.artifact.plaintextSha256,
      adminIdentity: options.adminIdentity,
      now: options.now ?? new Date(),
    });
  } else if (request.operation === "production-release") {
    validateProductionCapsule(capsule, request, payload);
  } else if (request.operation === "production-cutover") {
    validateCommonCapsuleIdentity(capsule, request);
    validateProductionCutoverCapsule(capsule, payload);
  } else {
    throw new Error("release operation is unsupported");
  }
  return capsule;
}

export function protectedOperationOutputs(capsule, request) {
  if (request.operation === "production-dns-stage") {
    const prerequisite = capsule?.dnsStage?.providerCanary;
    if (
      capsule?.operation !== "production-dns-stage" ||
      !digestPattern.test(capsule?.dnsStage?.requestId ?? "") ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
        prerequisite?.requestId ?? "",
      ) ||
      !digestPattern.test(prerequisite?.receiptSha256 ?? "") ||
      !decimalPattern.test(prerequisite?.runId ?? "")
    ) {
      throw new Error("production DNS-stage prerequisite outputs are invalid");
    }
    return Object.freeze({
      capsule_request_sha256: capsule.dnsStage.requestId,
      prerequisite_receipt_sha256: prerequisite.receiptSha256,
      prerequisite_request_id: prerequisite.requestId,
      prerequisite_run_id: prerequisite.runId,
    });
  }
  if (request.operation === "production-bootstrap") {
    const dnsStage = capsule?.bootstrap?.dnsStage;
    if (
      capsule?.operation !== "production-bootstrap" ||
      !digestPattern.test(capsule?.bootstrap?.requestId ?? "") ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
        dnsStage?.requestId ?? "",
      ) ||
      !digestPattern.test(dnsStage?.receiptSha256 ?? "") ||
      !decimalPattern.test(dnsStage?.runId ?? "")
    ) {
      throw new Error("production bootstrap prerequisite outputs are invalid");
    }
    return Object.freeze({
      capsule_request_sha256: capsule.bootstrap.requestId,
      prerequisite_receipt_sha256: dnsStage.receiptSha256,
      prerequisite_request_id: dnsStage.requestId,
      prerequisite_run_id: dnsStage.runId,
    });
  }
  if (request.operation === "production-release") {
    const prerequisite = capsule?.releasePrerequisite;
    if (
      capsule?.operation !== "production-release" ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
        prerequisite?.requestId ?? "",
      ) ||
      !digestPattern.test(prerequisite?.receiptSha256 ?? "") ||
      !decimalPattern.test(prerequisite?.runId ?? "")
    ) {
      throw new Error("production release prerequisite outputs are invalid");
    }
    return Object.freeze({
      prerequisite_receipt_sha256: prerequisite.receiptSha256,
      prerequisite_request_id: prerequisite.requestId,
      prerequisite_run_id: prerequisite.runId,
    });
  }
  if (request.operation === "production-cutover") {
    const prerequisite = capsule?.cutover?.prerequisite;
    if (
      capsule?.operation !== "production-cutover" ||
      !digestPattern.test(capsule?.cutover?.cutoverId ?? "") ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
        prerequisite?.requestId ?? "",
      ) ||
      !digestPattern.test(prerequisite?.receiptSha256 ?? "") ||
      !decimalPattern.test(prerequisite?.runId ?? "")
    ) {
      throw new Error("production cutover prerequisite outputs are invalid");
    }
    return Object.freeze({
      capsule_request_sha256: capsule.cutover.cutoverId,
      prerequisite_receipt_sha256: prerequisite.receiptSha256,
      prerequisite_request_id: prerequisite.requestId,
      prerequisite_run_id: prerequisite.runId,
    });
  }
  return Object.freeze({});
}

async function appendProtectedOperationOutputs(path, outputs) {
  if (!path || Object.keys(outputs).length === 0) return;
  const lines = Object.entries(outputs).map(([name, value]) => `${name}=${value}`);
  await appendFile(resolve(path), `${lines.join("\n")}\n`, "utf8");
}

function required(environment, name, pattern) {
  const value = environment[name]?.trim();
  if (!value || (pattern && !pattern.test(value))) {
    throw new Error(`${name} is unavailable or invalid`);
  }
  return value;
}

export function validateTransportBindings(environment) {
  const rawDeployKey = required(environment, "PRIVATE_TRANSPORT_DEPLOY_KEY");
  const normalizedDeployKey = rawDeployKey.replaceAll("\r\n", "\n");
  const keyLabel = "OPENSSH";
  const begin = `-----BEGIN ${keyLabel} PRIVATE KEY-----`;
  const end = `-----END ${keyLabel} PRIVATE KEY-----`;
  const lines = normalizedDeployKey.split("\n");
  if (
    normalizedDeployKey.includes("\r") ||
    normalizedDeployKey.includes("\0") ||
    lines.length < 4 ||
    lines[0] !== begin ||
    lines.at(-1) !== end ||
    lines.slice(1, -1).some((line) => !/^[A-Za-z0-9+/]{4,}={0,2}$/.test(line))
  ) {
    throw new Error("Deploy key material is invalid");
  }
  const deployKey = `${normalizedDeployKey}\n`;
  const expectedKeySha256 = required(
    environment,
    "PRIVATE_TRANSPORT_DEPLOY_KEY_SHA256",
    digestPattern,
  );
  if (sha256(Buffer.from(deployKey)) !== expectedKeySha256) {
    throw new Error("Deploy key secret binding differs");
  }

  const gitUrl = required(
    environment,
    "PRIVATE_TRANSPORT_GIT_URL",
    /^git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/,
  );
  const expectedGitUrlSha256 = required(
    environment,
    "PRIVATE_TRANSPORT_GIT_URL_SHA256",
    digestPattern,
  );
  if (sha256(Buffer.from(gitUrl)) !== expectedGitUrlSha256) {
    throw new Error("Transport repository binding differs");
  }
  return { deployKey, gitUrl };
}

export function validateDecryptionBindings(environment) {
  const rawPrivateKey = required(environment, "RELEASE_DECRYPTION_PRIVATE_KEY");
  const normalizedPrivateKey = rawPrivateKey.replaceAll("\r\n", "\n");
  const keyLabel = "PGP";
  const begin = `-----BEGIN ${keyLabel} PRIVATE KEY BLOCK-----`;
  const end = `-----END ${keyLabel} PRIVATE KEY BLOCK-----`;
  if (
    normalizedPrivateKey.includes("\r") ||
    normalizedPrivateKey.includes("\0") ||
    !normalizedPrivateKey.startsWith(begin) ||
    !normalizedPrivateKey.endsWith(end)
  ) {
    throw new Error("Release decryption key material is invalid");
  }
  const privateKey = `${normalizedPrivateKey}\n`;
  const expectedPrivateKeySha256 = required(
    environment,
    "RELEASE_DECRYPTION_PRIVATE_KEY_SHA256",
    digestPattern,
  );
  if (sha256(Buffer.from(privateKey)) !== expectedPrivateKeySha256) {
    throw new Error("Release decryption key binding differs");
  }

  const passphrase = environment.RELEASE_DECRYPTION_PASSPHRASE;
  if (
    typeof passphrase !== "string" ||
    passphrase.length < 16 ||
    passphrase.length > 1024 ||
    /[\r\n\0]/.test(passphrase)
  ) {
    throw new Error("release decryption passphrase is unavailable or invalid");
  }
  const expectedPassphraseSha256 = required(
    environment,
    "RELEASE_DECRYPTION_PASSPHRASE_SHA256",
    digestPattern,
  );
  if (sha256(Buffer.from(passphrase)) !== expectedPassphraseSha256) {
    throw new Error("Release decryption passphrase binding differs");
  }
  return { passphrase, privateKey };
}

export function validateImportedSecretKey(
  listing,
  expectedPrimaryFingerprint,
  expectedEncryptionSubkeyFingerprint,
) {
  if (
    typeof listing !== "string" ||
    !/^[A-F0-9]{40}$/.test(expectedPrimaryFingerprint) ||
    !/^[A-F0-9]{40}$/.test(expectedEncryptionSubkeyFingerprint)
  ) {
    throw new Error("Pinned release decryption fingerprint is invalid");
  }
  const keys = [];
  let awaitingFingerprint;
  for (const line of listing.split("\n")) {
    const fields = line.split(":");
    if (fields[0] === "sec" || fields[0] === "ssb") {
      awaitingFingerprint = {
        capabilities: (fields[11] ?? "").toLowerCase(),
        fingerprint: "",
        record: fields[0],
      };
    } else if (fields[0] === "fpr" && awaitingFingerprint) {
      awaitingFingerprint.fingerprint = fields[9] ?? "";
      keys.push(awaitingFingerprint);
      awaitingFingerprint = undefined;
    }
  }
  const primaryKeys = keys.filter((key) => key.record === "sec");
  if (primaryKeys.length !== 1 || primaryKeys[0].fingerprint !== expectedPrimaryFingerprint) {
    throw new Error("Imported release decryption key fingerprint differs");
  }
  const encryptionSubkeys = keys.filter(
    (key) => key.record === "ssb" && key.capabilities.includes("e"),
  );
  if (
    encryptionSubkeys.length !== 1 ||
    encryptionSubkeys[0].fingerprint !== expectedEncryptionSubkeyFingerprint
  ) {
    throw new Error("Imported release secret encryption subkey differs");
  }
  return true;
}

function runGit(repository, arguments_, options = {}) {
  const result = spawnSync("git", ["-C", repository, ...arguments_], {
    encoding: options.encoding ?? "utf8",
    env: options.environment,
    maxBuffer: maximumEnvelopeBytes + 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`Git plumbing rejected ${arguments_[0]}`);
  }
  return result.stdout;
}

export function parseTree(raw) {
  return raw
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const match = /^(\d{6}) (\w+) ([a-f0-9]{40})\t([^\0]+)$/.exec(entry);
      if (!match) throw new Error("Transport tree entry is malformed");
      return { mode: match[1], type: match[2], sha: match[3], name: match[4] };
    });
}

export function validateTransportTree(entries, request) {
  const expected = new Map([
    ["manifest.json", request.artifact.manifestBlobSha1],
    ["release.gpg", request.artifact.ciphertextBlobSha1],
  ]);
  if (!Array.isArray(entries) || entries.length !== 2) {
    throw new Error("Transport tree must contain exactly two entries");
  }
  for (const entry of entries) {
    if (
      entry.mode !== "100644" ||
      entry.type !== "blob" ||
      !expected.has(entry.name) ||
      expected.get(entry.name) !== entry.sha
    ) {
      throw new Error("Transport tree contains an unexpected entry");
    }
    expected.delete(entry.name);
  }
  if (expected.size !== 0) throw new Error("Transport tree is incomplete");
  return true;
}

function octal(bytes, offset, length, label) {
  const text = new TextDecoder()
    .decode(bytes.subarray(offset, offset + length))
    .replaceAll("\0", "")
    .trim();
  if (!/^[0-7]+$/.test(text)) throw new Error(`Tar ${label} is invalid`);
  return Number.parseInt(text, 8);
}

function tarString(bytes, offset, length) {
  const field = bytes.subarray(offset, offset + length);
  const end = field.indexOf(0);
  return new TextDecoder().decode(end < 0 ? field : field.subarray(0, end));
}

export function parseFixedEnvelope(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 2048 || bytes.length > maximumEnvelopeBytes) {
    throw new Error("Envelope size is invalid");
  }
  const files = new Map();
  let offset = 0;
  let zeroBlocks = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += 512;
      if (zeroBlocks === 2) break;
      continue;
    }
    if (zeroBlocks > 0) throw new Error("Tar data follows a zero block");
    const storedChecksum = octal(header, 148, 8, "checksum");
    let computedChecksum = 0;
    for (let index = 0; index < 512; index += 1) {
      computedChecksum += index >= 148 && index < 156 ? 32 : header[index];
    }
    if (storedChecksum !== computedChecksum) throw new Error("Tar checksum changed");
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const linkName = tarString(header, 157, 100);
    const type = header[156];
    const mode = octal(header, 100, 8, "mode");
    const size = octal(header, 124, 12, "size");
    if (
      prefix ||
      linkName ||
      (type !== 0 && type !== 48) ||
      (mode & 0o111) !== 0 ||
      !["manifest.json", "payload.bin"].includes(name) ||
      files.has(name) ||
      size < 1 ||
      size > maximumEnvelopeBytes
    ) {
      throw new Error("Tar entry is outside the fixed allowlist");
    }
    offset += 512;
    if (offset + size > bytes.length) throw new Error("Tar entry is truncated");
    files.set(name, bytes.slice(offset, offset + size));
    offset += Math.ceil(size / 512) * 512;
  }
  if (zeroBlocks !== 2 || files.size !== 2) {
    throw new Error("Tar envelope is incomplete");
  }
  if (bytes.subarray(offset).some((byte) => byte !== 0)) {
    throw new Error("Tar envelope has trailing data");
  }
  return files;
}

export function validateManifest(manifestBytes, request) {
  const text = new TextDecoder().decode(manifestBytes);
  const manifest = JSON.parse(text);
  if (`${canonicalJson(manifest)}\n` !== text) {
    throw new Error("Transport manifest is not canonical");
  }
  const expected = {
    controller: request.controller,
    evidence: { oidcTokenSha256: request.evidence.oidcTokenSha256 },
    nonce: request.nonce,
    payload: {
      bytes: request.artifact.plaintextBytes,
      sha256: request.artifact.plaintextSha256,
    },
    requestId: request.requestId,
    schema: "deployment-control/private-transport-manifest/v1",
    source: request.source,
  };
  if (canonicalJson(manifest) !== canonicalJson(expected)) {
    throw new Error("Transport manifest differs from approved request");
  }
  if (sha256(manifestBytes) !== request.evidence.manifestSha256) {
    throw new Error("Transport manifest digest changed");
  }
  return manifest;
}

async function fetchTransport(request, environment, root) {
  const bindings = validateTransportBindings(environment);
  const repository = join(root, "transport.git");
  await mkdir(repository, { mode: 0o700 });
  const deployKey = join(root, "deploy-key");
  const sshWrapper = join(root, "ssh-wrapper");
  await writeFile(deployKey, bindings.deployKey, {
    flag: "wx",
    mode: 0o600,
  });
  const knownHosts = fileURLToPath(new URL("../keys/github-known-hosts", import.meta.url));
  const wrapper = `#!/bin/sh\nexec /usr/bin/ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${JSON.stringify(knownHosts)} -i ${JSON.stringify(deployKey)} "$@"\n`;
  await writeFile(sshWrapper, wrapper, { flag: "wx", mode: 0o700 });
  const gitEnvironment = {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_SSH: sshWrapper,
    HOME: root,
    PATH: process.env.PATH,
  };
  runGit(repository, ["init", "--bare"], { environment: gitEnvironment });
  runGit(
    repository,
    [
      "fetch",
      "--depth=1",
      "--no-tags",
      bindings.gitUrl,
      `refs/tags/${request.artifact.transportTag}:refs/tags/release`,
    ],
    { environment: gitEnvironment },
  );
  await chmod(deployKey, 0o600);
  await writeFile(deployKey, "", { mode: 0o600 });
  const commit = runGit(repository, ["rev-parse", "refs/tags/release"]).trim();
  if (commit !== request.artifact.transportCommitSha) {
    throw new Error("Transport tag resolves to a different commit");
  }
  if (runGit(repository, ["cat-file", "-t", "refs/tags/release"]).trim() !== "commit") {
    throw new Error("Transport tag must directly reference one commit");
  }
  const ancestry = runGit(repository, ["rev-list", "--parents", "-n", "1", commit])
    .trim()
    .split(/\s+/);
  if (ancestry.length !== 1 || ancestry[0] !== commit) {
    throw new Error("Transport commit must be parentless");
  }
  const tree = parseTree(runGit(repository, ["ls-tree", "-z", commit]));
  validateTransportTree(tree, request);
  const manifestBytes = runGit(repository, ["cat-file", "blob", `${commit}:manifest.json`], {
    encoding: "buffer",
  });
  const ciphertextBytes = runGit(repository, ["cat-file", "blob", `${commit}:release.gpg`], {
    encoding: "buffer",
  });
  if (
    manifestBytes.subarray(0, 42).toString("utf8").includes("git-lfs.github.com") ||
    ciphertextBytes.subarray(0, 42).toString("utf8").includes("git-lfs.github.com")
  ) {
    throw new Error("Git LFS pointers are forbidden");
  }
  if (sha256(ciphertextBytes) !== request.artifact.ciphertextSha256) {
    throw new Error("Ciphertext digest changed");
  }
  validateManifest(manifestBytes, request);
  const ciphertextPath = join(root, "release.gpg");
  await writeFile(ciphertextPath, ciphertextBytes, { flag: "wx", mode: 0o400 });
  return { ciphertextPath, manifestBytes };
}

export async function decryptBoundCiphertext(
  ciphertextPath,
  environment,
  root,
  expectedPrimaryFingerprint,
  expectedEncryptionSubkeyFingerprint,
) {
  const bindings = validateDecryptionBindings(environment);
  const gpgHome = join(root, "gpg");
  await mkdir(gpgHome, { mode: 0o700 });
  const privateKey = join(root, "decryption-key.asc");
  const envelopePath = join(root, "envelope.tar");
  await writeFile(privateKey, bindings.privateKey, {
    flag: "wx",
    mode: 0o600,
  });
  const cleanEnvironment = {
    GNUPGHOME: gpgHome,
    HOME: root,
    PATH: process.env.PATH,
  };
  const importResult = spawnSync(
    "gpg",
    ["--batch", "--no-tty", "--homedir", gpgHome, "--import", privateKey],
    { encoding: "utf8", env: cleanEnvironment, windowsHide: true },
  );
  await chmod(privateKey, 0o600);
  await writeFile(privateKey, "", { mode: 0o600 });
  if (importResult.status !== 0) throw new Error("Offline GPG key import failed");
  const fingerprintResult = spawnSync(
    "gpg",
    [
      "--batch",
      "--no-tty",
      "--homedir",
      gpgHome,
      "--with-colons",
      "--list-secret-keys",
      "--fingerprint",
      "--fingerprint",
    ],
    { encoding: "utf8", env: cleanEnvironment, windowsHide: true },
  );
  if (fingerprintResult.status !== 0) {
    throw new Error("Offline GPG secret-key inspection failed");
  }
  validateImportedSecretKey(
    fingerprintResult.stdout,
    expectedPrimaryFingerprint,
    expectedEncryptionSubkeyFingerprint,
  );
  const decryptResult = spawnSync(
    "gpg",
    [
      "--batch",
      "--no-tty",
      "--homedir",
      gpgHome,
      "--no-auto-key-retrieve",
      "--auto-key-locate",
      "clear",
      "--pinentry-mode",
      "loopback",
      "--passphrase-fd",
      "0",
      "--output",
      envelopePath,
      "--decrypt",
      ciphertextPath,
    ],
    {
      encoding: "utf8",
      env: cleanEnvironment,
      input: `${bindings.passphrase}\n`,
      windowsHide: true,
    },
  );
  if (decryptResult.status !== 0) throw new Error("Offline GPG decryption failed");
  return envelopePath;
}

async function decrypt(ciphertextPath, environment, root) {
  const [expectedPrimaryFingerprint, expectedEncryptionSubkeyFingerprint] = await Promise.all([
    readFile(
      fileURLToPath(new URL("../keys/release-encryption-fingerprint.txt", import.meta.url)),
      "utf8",
    ).then((value) => value.trim()),
    readFile(
      fileURLToPath(
        new URL("../keys/release-encryption-subkey-fingerprint.txt", import.meta.url),
      ),
      "utf8",
    ).then((value) => value.trim()),
  ]);
  return decryptBoundCiphertext(
    ciphertextPath,
    environment,
    root,
    expectedPrimaryFingerprint,
    expectedEncryptionSubkeyFingerprint,
  );
}

export async function verifyProtectedTransport(environment = process.env) {
  const encoded = required(environment, "RELEASE_REQUEST_BASE64", /^[A-Za-z0-9_-]{100,32768}$/);
  const request = JSON.parse(
    decodeCanonicalBase64Url(encoded, "RELEASE_REQUEST_BASE64").toString("utf8"),
  );
  validateReleaseRequest(request, {
    expectedControllerRepositoryId: required(
      environment,
      "EXPECTED_CONTROLLER_REPOSITORY_ID",
      decimalPattern,
    ),
    expectedControllerSha: required(environment, "GITHUB_SHA", shaPattern),
    expectedSourceRepositoryId: required(
      environment,
      "EXPECTED_SOURCE_REPOSITORY_ID",
      decimalPattern,
    ),
  });
  const root = await mkdtemp(join(tmpdir(), "deployment-control-transport-"));
  try {
    const encryptionPublicKey = await readFile(
      fileURLToPath(new URL("../keys/release-encryption-public.asc", import.meta.url)),
    );
    if (sha256(encryptionPublicKey) !== request.artifact.encryptionKeySha256) {
      throw new Error("Pinned encryption public key digest differs");
    }
    const transport = await fetchTransport(request, environment, root);
    const envelopePath = await decrypt(transport.ciphertextPath, environment, root);
    const files = parseFixedEnvelope(await readFile(envelopePath));
    const manifest = files.get("manifest.json");
    if (!manifest || !Buffer.from(manifest).equals(transport.manifestBytes)) {
      throw new Error("Encrypted and transport manifests differ");
    }
    validateManifest(manifest, request);
    const payload = files.get("payload.bin");
    if (!payload) throw new Error("Envelope payload is incomplete");
    if (
      payload.length !== request.artifact.plaintextBytes ||
      sha256(payload) !== request.artifact.plaintextSha256
    ) {
      throw new Error("Plaintext capsule digest changed");
    }
    const capsule = validateOperationPayload(payload, request, {
      adminIdentity:
        request.operation === "production-bootstrap"
          ? required(
              environment,
              "PRODUCTION_ACCESS_ADMIN_EMAIL",
              /^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/,
            )
          : undefined,
    });
    const outputDirectory = resolve(required(environment, "VERIFIED_PAYLOAD_OUTPUT_DIRECTORY"));
    await mkdir(outputDirectory, { recursive: false, mode: 0o700 });
    const output = join(outputDirectory, "release-capsule.bin");
    await writeFile(output, payload, { flag: "wx", mode: 0o400 });
    await appendProtectedOperationOutputs(
      environment.GITHUB_OUTPUT,
      protectedOperationOutputs(capsule, request),
    );
    return Object.freeze({ output, request });
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

if (process.argv[1]?.endsWith("protected-transport.mjs")) {
  verifyProtectedTransport().then(
    () => process.stdout.write("Protected transport verified.\n"),
    (error) => {
      console.error(`Protected transport rejected: ${error.message}`);
      process.exitCode = 1;
    },
  );
}
