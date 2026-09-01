import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import { sha256 } from "./control-contract.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const accountIdPattern = /^[a-f0-9]{32}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const safeSegmentPattern = /^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,127}$/;
const migrationPattern = /^migrations\/(\d{4})_([a-z0-9_]+)\.sql$/;
const capsulePrefix = ".wrangler/production-upload/";
const maximumFileCount = 4096;
const maximumRawBytes = 32 * 1024 * 1024;
const maximumEntryBytes = 16 * 1024 * 1024;
const expectedWranglerVersion = "4.127.1";

const runtimeConfirmationNames = Object.freeze([
  "PRODUCTION_RELEASE_READY",
  "PRODUCTION_DATABASE_READY",
  "PRODUCTION_D1_BACKUP_READY",
  "PRODUCTION_DASHBOARD_AUTH_READY",
  "PRODUCTION_ACCESS_POLICY_VERIFIED",
  "PRODUCTION_EMAIL_DOMAIN_VERIFIED",
  "PRODUCTION_RESEND_WEBHOOK_REGISTERED",
  "PRODUCTION_PRIVACY_LEGAL_APPROVED",
  "PRODUCTION_LAUNCH_MEDIA_APPROVED",
  "PRODUCTION_REDIRECT_CANDIDATE_VERIFIED",
  "PRODUCTION_WORKERS_DEV_DISABLED",
  "PRODUCTION_CUTOVER_APPROVED",
]);

function exactPlainObject(value, keys, label) {
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

function treeSha256(entries) {
  const hash = createHash("sha256");
  for (const entry of entries) {
    hash.update(entry.path, "utf8");
    hash.update("\0");
    hash.update(String(entry.bytes), "utf8");
    hash.update("\0");
    hash.update(entry.sha256, "ascii");
    hash.update("\0");
  }
  return hash.digest("hex");
}

function canonicalBase64(content, label) {
  if (
    typeof content !== "string" ||
    content.length === 0 ||
    content.length > Math.ceil(maximumEntryBytes / 3) * 4 ||
    content.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(content)
  ) {
    throw new Error(`${label} is not canonical base64`);
  }
  const bytes = Buffer.from(content, "base64");
  if (bytes.toString("base64") !== content) {
    throw new Error(`${label} has a non-canonical base64 spelling`);
  }
  return bytes;
}

function assertSafePath(path) {
  if (
    typeof path !== "string" ||
    path.length > 512 ||
    !path.startsWith(capsulePrefix) ||
    path.includes("\\") ||
    path.includes("\0") ||
    /[\r\n:%]/.test(path)
  ) {
    throw new Error("Capsule entry path is outside the immutable upload root");
  }
  const uploadPath = path.slice(capsulePrefix.length);
  const segments = uploadPath.split("/");
  if (
    !uploadPath ||
    segments.some(
      (segment) =>
        !segment || segment === "." || segment === ".." || !safeSegmentPattern.test(segment),
    )
  ) {
    throw new Error(`Capsule entry path is non-canonical: ${path}`);
  }
  if (
    ![
      "worker/index.js",
      "schema-version.json",
      "wrangler.template.jsonc",
      "upload-manifest.json",
    ].includes(uploadPath) &&
    !uploadPath.startsWith("assets/") &&
    !migrationPattern.test(uploadPath)
  ) {
    throw new Error(`Capsule entry path is not allowlisted: ${path}`);
  }
  return uploadPath;
}

function decodeEntries(payload) {
  exactPlainObject(payload, ["encoding", "rawBytes", "fileCount", "entries"], "capsule payload");
  if (
    payload.encoding !== "base64-per-file" ||
    !Number.isSafeInteger(payload.rawBytes) ||
    payload.rawBytes < 1 ||
    payload.rawBytes > maximumRawBytes ||
    !Number.isSafeInteger(payload.fileCount) ||
    payload.fileCount < 1 ||
    payload.fileCount > maximumFileCount ||
    !Array.isArray(payload.entries) ||
    payload.entries.length !== payload.fileCount
  ) {
    throw new Error("Production capsule payload boundary is invalid");
  }

  const decoded = [];
  const seen = new Set();
  let rawBytes = 0;
  let previousPath = "";
  for (const entry of payload.entries) {
    exactPlainObject(entry, ["path", "bytes", "sha256", "encoding", "content"], "capsule entry");
    const uploadPath = assertSafePath(entry.path);
    if (seen.has(entry.path) || (previousPath && previousPath.localeCompare(entry.path, "en") >= 0)) {
      throw new Error("Capsule entry paths must be unique and strictly sorted");
    }
    seen.add(entry.path);
    previousPath = entry.path;
    if (
      entry.encoding !== "base64" ||
      !Number.isSafeInteger(entry.bytes) ||
      entry.bytes < 1 ||
      entry.bytes > maximumEntryBytes ||
      typeof entry.sha256 !== "string" ||
      !digestPattern.test(entry.sha256)
    ) {
      throw new Error(`Capsule entry metadata is invalid: ${entry.path}`);
    }
    const bytes = canonicalBase64(entry.content, `Capsule entry ${entry.path}`);
    if (bytes.byteLength !== entry.bytes || sha256(bytes) !== entry.sha256) {
      throw new Error(`Capsule entry bytes or digest changed: ${entry.path}`);
    }
    rawBytes += bytes.byteLength;
    if (rawBytes > maximumRawBytes) throw new Error("Capsule entries exceed the raw byte boundary");
    decoded.push(Object.freeze({
      path: entry.path,
      uploadPath,
      bytes: entry.bytes,
      sha256: entry.sha256,
      content: bytes,
    }));
  }
  if (rawBytes !== payload.rawBytes) throw new Error("Capsule raw byte total changed");
  return Object.freeze(decoded);
}

function parseExactJson(bytes, label, indentation) {
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid UTF-8 JSON`);
  }
  if (`${JSON.stringify(value, null, indentation)}\n` !== text) {
    throw new Error(`${label} is not in the exact generated JSON representation`);
  }
  return value;
}

const deploymentPlaceholders = Object.freeze({
  accountId: "__FRESH_TOWELS_CLOUDFLARE_ACCOUNT_ID__",
  databaseId: "__FRESH_TOWELS_PRODUCTION_D1_ID__",
  accessAudience: "__FRESH_TOWELS_ACCESS_AUD__",
  accessTeamDomain: "__FRESH_TOWELS_ACCESS_TEAM_DOMAIN__",
  previewSuffix: "__FRESH_TOWELS_WORKERS_DEV_PREVIEW_SUFFIX__",
});

function validateRuntimeVariables(variables) {
  const keys = [
    "NEXT_PUBLIC_SITE_ENV",
    "PRODUCTION_CANONICAL_URL",
    "PRODUCTION_VERSION_PREVIEW_URL_SUFFIX",
    "LEAD_NOTIFICATION_MODE",
    "LEAD_NOTIFICATION_TO",
    "RESEND_FROM",
    "LEAD_CONSENT_VERSION",
    "LEAD_ANTISPAM_MODE",
    "CLOUDFLARE_ACCESS_AUD",
    "CLOUDFLARE_ACCESS_TEAM_DOMAIN",
    "PRODUCTION_INFRASTRUCTURE_RECEIPT_SHA256",
    ...runtimeConfirmationNames,
  ];
  exactPlainObject(variables, keys, "Wrangler runtime variables");
  if (
    variables.NEXT_PUBLIC_SITE_ENV !== "production" ||
    variables.PRODUCTION_CANONICAL_URL !== "https://freshtowels.gr" ||
    variables.LEAD_NOTIFICATION_MODE !== "resend" ||
    variables.LEAD_ANTISPAM_MODE !== "honeypot_rate_limit" ||
    variables.LEAD_NOTIFICATION_TO !== "info@freshtowels.gr" ||
    variables.RESEND_FROM !== "Fresh Towels <notifications@notify.freshtowels.gr>" ||
    variables.CLOUDFLARE_ACCESS_AUD !== deploymentPlaceholders.accessAudience ||
    !digestPattern.test(variables.PRODUCTION_INFRASTRUCTURE_RECEIPT_SHA256) ||
    variables.CLOUDFLARE_ACCESS_TEAM_DOMAIN !== deploymentPlaceholders.accessTeamDomain ||
    variables.PRODUCTION_VERSION_PREVIEW_URL_SUFFIX !== deploymentPlaceholders.previewSuffix ||
    typeof variables.LEAD_CONSENT_VERSION !== "string" ||
    variables.LEAD_CONSENT_VERSION.length < 8 ||
    /(?:draft|local|test)/i.test(variables.LEAD_CONSENT_VERSION) ||
    runtimeConfirmationNames.some((name) => variables[name] !== "confirmed")
  ) {
    throw new Error("Wrangler runtime variables violate production semantics");
  }
}

function validateWranglerTemplate(entry) {
  const configuration = parseExactJson(entry.content, "Wrangler upload template", 2);
  exactPlainObject(
    configuration,
    [
      "name",
      "account_id",
      "main",
      "compatibility_date",
      "compatibility_flags",
      "vars",
      "workers_dev",
      "preview_urls",
      "assets",
      "d1_databases",
      "triggers",
      "observability",
    ],
    "Wrangler upload template",
  );
  if (
    configuration.name !== "fresh-towels-production" ||
    configuration.account_id !== deploymentPlaceholders.accountId ||
    configuration.main !== "./worker/index.js" ||
    configuration.compatibility_date !== "2026-08-28" ||
    JSON.stringify(configuration.compatibility_flags) !== JSON.stringify(["nodejs_compat"]) ||
    configuration.workers_dev !== false ||
    configuration.preview_urls !== false
  ) {
    throw new Error("Wrangler upload configuration identity or runtime mode changed");
  }
  exactPlainObject(configuration.assets, ["directory", "run_worker_first"], "Wrangler Assets binding");
  const expectedWorkerFirst = [
    "/internal/leads",
    "/internal/leads/*",
    "/api/internal/*",
    "/api/leads",
    "/api/webhooks/resend",
  ];
  if (
    configuration.assets.directory !== "./assets" ||
    JSON.stringify(configuration.assets.run_worker_first) !== JSON.stringify(expectedWorkerFirst)
  ) {
    throw new Error("Wrangler Assets routing semantics changed");
  }
  if (!Array.isArray(configuration.d1_databases) || configuration.d1_databases.length !== 1) {
    throw new Error("Wrangler configuration must contain one production D1 binding");
  }
  const database = configuration.d1_databases[0];
  exactPlainObject(
    database,
    ["binding", "database_name", "database_id", "migrations_dir", "migrations_table"],
    "Wrangler D1 binding",
  );
  if (
    database.binding !== "LEADS_DB" ||
    database.database_name !== "fresh-towels-leads-prod" ||
    database.database_id !== deploymentPlaceholders.databaseId ||
    database.migrations_dir !== "./migrations" ||
    database.migrations_table !== "d1_migrations"
  ) {
    throw new Error("Wrangler production D1 binding semantics changed");
  }
  exactPlainObject(configuration.triggers, ["crons"], "Wrangler triggers");
  if (JSON.stringify(configuration.triggers.crons) !== JSON.stringify(["*/5 * * * *"])) {
    throw new Error("Wrangler retention/outbox trigger semantics changed");
  }
  exactPlainObject(configuration.observability, ["enabled", "logs"], "Wrangler observability");
  exactPlainObject(
    configuration.observability.logs,
    ["enabled", "invocation_logs", "persist"],
    "Wrangler observability logs",
  );
  if (
    configuration.observability.enabled !== true ||
    Object.values(configuration.observability.logs).some((value) => value !== true)
  ) {
    throw new Error("Wrangler production observability semantics changed");
  }
  validateRuntimeVariables(configuration.vars);
  return Object.freeze({
    templateSha256: entry.sha256,
    workerName: configuration.name,
    databaseName: database.database_name,
    productionInfrastructureReceiptSha256:
      configuration.vars.PRODUCTION_INFRASTRUCTURE_RECEIPT_SHA256,
    template: configuration,
  });
}

function validateSchemaAndMigrations(entries) {
  const schemaEntry = entries.find((entry) => entry.uploadPath === "schema-version.json");
  const schema = parseExactJson(schemaEntry.content, "Database schema version", 2);
  exactPlainObject(schema, ["currentLeadSchemaVersion"], "Database schema version");
  const version = schema.currentLeadSchemaVersion;
  if (!Number.isSafeInteger(version) || version < 1 || version > 9999) {
    throw new Error("Database schema version is invalid");
  }
  const migrations = entries
    .map((entry) => ({ entry, match: migrationPattern.exec(entry.uploadPath) }))
    .filter(({ match }) => match)
    .map(({ entry, match }) => ({ entry, version: Number(match[1]) }));
  if (
    migrations.length !== version ||
    migrations.some(({ version: migrationVersion }, index) => migrationVersion !== index + 1)
  ) {
    throw new Error("Database migration chain is not contiguous with schema-version.json");
  }
  return Object.freeze({ currentLeadSchemaVersion: version, migrationCount: migrations.length });
}

function validateUploadManifest(entries, releaseIntegrity) {
  const byPath = new Map(entries.map((entry) => [entry.uploadPath, entry]));
  const manifestEntry = byPath.get("upload-manifest.json");
  const manifest = parseExactJson(manifestEntry.content, "Immutable upload manifest", 2);
  exactPlainObject(
    manifest,
    [
      "schemaVersion",
      "artifactType",
      "wranglerVersion",
      "sourceIntegrity",
      "workerModuleSha256",
      "staticAssetsTreeSha256",
      "databasePayloadTreeSha256",
      "configurationTemplateSha256",
      "uploadTreeSha256",
      "fileCount",
      "totalBytes",
      "deployContract",
    ],
    "Immutable upload manifest",
  );
  exactPlainObject(
    manifest.sourceIntegrity,
    [
      "buildArtifactSha256",
      "databaseSchemaSha256",
      "releaseApprovalManifestSha256",
      "productionInfrastructureReceiptSha256",
    ],
    "Upload manifest source integrity",
  );
  exactPlainObject(
    manifest.deployContract,
    ["command", "configurationMaterialization", "noBundleRequired", "secretsFileRequired"],
    "Upload deploy contract",
  );
  const payloadEntries = entries
    .filter((entry) => entry.uploadPath !== "upload-manifest.json")
    .map((entry) => ({ path: entry.uploadPath, bytes: entry.bytes, sha256: entry.sha256 }));
  const assets = payloadEntries.filter((entry) => entry.path.startsWith("assets/"));
  const database = payloadEntries.filter(
    (entry) => entry.path === "schema-version.json" || entry.path.startsWith("migrations/"),
  );
  const source = manifest.sourceIntegrity;
  if (
    manifest.schemaVersion !== 2 ||
    manifest.artifactType !== "fresh-towels-cloudflare-immutable-upload" ||
    manifest.wranglerVersion !== expectedWranglerVersion ||
    source.buildArtifactSha256 !== releaseIntegrity.buildArtifactSha256 ||
    source.databaseSchemaSha256 !== releaseIntegrity.databaseSchemaSha256 ||
    source.releaseApprovalManifestSha256 !== releaseIntegrity.releaseApprovalManifestSha256 ||
    source.productionInfrastructureReceiptSha256 !==
      releaseIntegrity.productionInfrastructureReceiptSha256 ||
    manifest.workerModuleSha256 !== byPath.get("worker/index.js")?.sha256 ||
    manifest.configurationTemplateSha256 !== byPath.get("wrangler.template.jsonc")?.sha256 ||
    manifest.configurationTemplateSha256 !== releaseIntegrity.configurationTemplateSha256 ||
    manifest.staticAssetsTreeSha256 !== treeSha256(assets) ||
    manifest.databasePayloadTreeSha256 !== treeSha256(database) ||
    manifest.uploadTreeSha256 !== treeSha256(payloadEntries) ||
    manifest.uploadTreeSha256 !== releaseIntegrity.uploadArtifactSha256 ||
    manifest.fileCount !== payloadEntries.length ||
    manifest.totalBytes !== payloadEntries.reduce((total, entry) => total + entry.bytes, 0) ||
    manifest.deployContract.command !== "wrangler versions upload" ||
    manifest.deployContract.configurationMaterialization !==
      "protected-infrastructure-receipt-v1" ||
    manifest.deployContract.noBundleRequired !== true ||
    manifest.deployContract.secretsFileRequired !== true ||
    assets.length === 0 ||
    database.length === 0
  ) {
    throw new Error("Immutable upload manifest or tree binding changed");
  }
  return Object.freeze({
    uploadTreeSha256: manifest.uploadTreeSha256,
    workerModuleSha256: manifest.workerModuleSha256,
    staticAssetsTreeSha256: manifest.staticAssetsTreeSha256,
    databasePayloadTreeSha256: manifest.databasePayloadTreeSha256,
    configurationTemplateSha256: manifest.configurationTemplateSha256,
    fileCount: manifest.fileCount,
    totalBytes: manifest.totalBytes,
    wranglerVersion: manifest.wranglerVersion,
  });
}

function recomputeReleaseId(capsule) {
  return sha256(
    Buffer.from(
      [
        capsule.application.commitSha,
        capsule.controller.commitSha,
        capsule.operation,
        capsule.releaseIntegrity.buildArtifactSha256,
        capsule.releaseIntegrity.uploadArtifactSha256,
        capsule.releaseIntegrity.productionInfrastructureReceiptSha256,
        capsule.releasePrerequisite.requestId,
        capsule.releasePrerequisite.receiptSha256,
        capsule.releasePrerequisite.runId,
        capsule.application.runId,
        capsule.application.runAttempt,
        capsule.createdAt,
      ].join("\0"),
      "utf8",
    ),
  );
}

export function validateProductionCapsuleContents(capsule, rawPayload) {
  exactPlainObject(
    capsule.releasePrerequisite,
    ["requestId", "receiptSha256", "runId"],
    "production Bootstrap prerequisite",
  );
  if (
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(
      capsule.releasePrerequisite.requestId,
    ) ||
    !digestPattern.test(capsule.releasePrerequisite.receiptSha256) ||
    !/^[1-9][0-9]{0,19}$/.test(capsule.releasePrerequisite.runId)
  ) {
    throw new Error("Production Bootstrap prerequisite is invalid");
  }
  exactPlainObject(
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
  if (Object.values(capsule.releaseIntegrity).some((value) => !digestPattern.test(value))) {
    throw new Error("Production capsule integrity digest is invalid");
  }
  if (rawPayload !== undefined) {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(rawPayload);
    if (`${JSON.stringify(capsule)}\n` !== text) {
      throw new Error("Production capsule is not in the exact generated JSON representation");
    }
  }
  if (capsule.releaseId !== recomputeReleaseId(capsule)) {
    throw new Error("Production capsule releaseId binding changed");
  }
  const entries = decodeEntries(capsule.payload);
  if (treeSha256(entries) !== capsule.releaseIntegrity.capsuleTreeSha256) {
    throw new Error("Production capsule tree digest changed");
  }
  const requiredPaths = [
    "worker/index.js",
    "schema-version.json",
    "wrangler.template.jsonc",
    "upload-manifest.json",
  ];
  for (const path of requiredPaths) {
    if (!entries.some((entry) => entry.uploadPath === path)) {
      throw new Error(`Production capsule is missing ${path}`);
    }
  }
  const manifest = validateUploadManifest(entries, capsule.releaseIntegrity);
  const configurationTemplate = validateWranglerTemplate(
    entries.find((entry) => entry.uploadPath === "wrangler.template.jsonc"),
  );
  const database = validateSchemaAndMigrations(entries);
  const worker = entries.find((entry) => entry.uploadPath === "worker/index.js");
  if (worker.content.includes(Buffer.from("sourceMappingURL="))) {
    throw new Error("Reviewed Worker module must not retain a source-map reference");
  }
  return Object.freeze({
    entries,
    release: Object.freeze({
      releaseId: capsule.releaseId,
      applicationCommitSha: capsule.application.commitSha,
      controllerCommitSha: capsule.controller.commitSha,
      buildArtifactSha256: capsule.releaseIntegrity.buildArtifactSha256,
      plaintextTreeSha256: capsule.releaseIntegrity.capsuleTreeSha256,
      uploadArtifactSha256: capsule.releaseIntegrity.uploadArtifactSha256,
      configurationTemplateSha256: capsule.releaseIntegrity.configurationTemplateSha256,
      productionInfrastructureReceiptSha256:
        capsule.releaseIntegrity.productionInfrastructureReceiptSha256,
    }),
    manifest,
    configurationTemplate,
    database,
  });
}

function isInside(root, child) {
  const path = relative(resolve(root), resolve(child));
  return path && path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

export async function materializeProductionCapsule({ capsule, rawPayload, outputRoot }) {
  if (typeof outputRoot !== "string" || !isAbsolute(outputRoot)) {
    throw new Error("Materialized capsule root must be one absolute path");
  }
  const existing = await lstat(outputRoot).catch(() => null);
  if (existing) throw new Error("Materialized capsule root must not already exist");
  const validated = validateProductionCapsuleContents(capsule, rawPayload);
  await mkdir(outputRoot, { recursive: false, mode: 0o700 });
  const canonicalRoot = await realpath(outputRoot);
  for (const entry of validated.entries) {
    const target = resolve(canonicalRoot, entry.uploadPath);
    if (!isInside(canonicalRoot, target)) throw new Error("Materialized entry escaped its root");
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, entry.content, { flag: "wx", mode: 0o600 });
    const status = await lstat(target);
    if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
      throw new Error("Materialized entry is not one private regular file");
    }
    const reread = await readFile(target);
    if (reread.byteLength !== entry.bytes || sha256(reread) !== entry.sha256) {
      throw new Error("Materialized entry failed post-write digest verification");
    }
  }
  return Object.freeze({
    root: canonicalRoot,
    release: validated.release,
    manifest: validated.manifest,
    configurationTemplate: validated.configurationTemplate,
    database: validated.database,
    files: Object.freeze(
      validated.entries.map(({ uploadPath, bytes, sha256: digest }) =>
        Object.freeze({ path: uploadPath, bytes, sha256: digest }),
      ),
    ),
  });
}

export const productionCapsuleLimits = Object.freeze({
  capsulePrefix,
  maximumEntryBytes,
  maximumFileCount,
  maximumRawBytes,
});

export const productionDeploymentPlaceholders = deploymentPlaceholders;
