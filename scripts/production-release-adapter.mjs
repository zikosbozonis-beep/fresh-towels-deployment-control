import { lstat, readFile, realpath, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { canonicalJson, sha256 } from "./control-contract.mjs";
import { productionDeploymentPlaceholders } from "./production-capsule.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const emailPattern = /^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/;
const expectedApplicationRepository = "zikosbozonis-beep/fresh-towels-website";
const expectedApplicationRepositoryId = "1350923567";
const expectedControllerRepository =
  "zikosbozonis-beep/fresh-towels-deployment-control";
const expectedWorkerName = "fresh-towels-production";
const expectedDomain = "freshtowels.gr";
const expectedSender = "notifications@notify.freshtowels.gr";
const requiredSecretBindings = Object.freeze([
  "DASHBOARD_AUTHORIZED_EMAILS",
  "LEAD_RATE_LIMIT_SECRET",
  "RESEND_API_KEY",
  "RESEND_WEBHOOK_SECRET",
]);

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
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(label + " contains missing or unexpected fields");
  }
}

function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value) + "\n", "utf8");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function exactInstant(value, label) {
  if (typeof value !== "string") throw new Error(label + " is invalid");
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(label + " is not canonical UTC");
  }
  return timestamp;
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !digestPattern.test(value)) {
    throw new Error(label + " is invalid");
  }
  return value;
}

function exactUuid(value, label) {
  if (typeof value !== "string" || !uuidPattern.test(value)) {
    throw new Error(label + " is invalid");
  }
  return value;
}

function exactBootstrapSecret(value, binding) {
  exactObject(
    value,
    ["binding", "bindingVersionSha256", "resourceIdentitySha256"],
    "bootstrap runtime secret " + binding,
  );
  if (
    value.binding !== binding ||
    !digestPattern.test(value.bindingVersionSha256) ||
    !digestPattern.test(value.resourceIdentitySha256)
  ) {
    throw new Error("bootstrap runtime secret identity changed");
  }
  return value;
}

export function validateProductionInfrastructureReceipt({
  bytes,
  expectedSha256,
  materialized,
  now = new Date(),
}) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.byteLength < 1 ||
    bytes.byteLength > 65_536 ||
    !digestPattern.test(expectedSha256 ?? "") ||
    sha256(bytes) !== expectedSha256 ||
    expectedSha256 !== materialized.release.productionInfrastructureReceiptSha256
  ) {
    throw new Error("production infrastructure receipt byte binding changed");
  }
  let receipt;
  try {
    receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("production infrastructure receipt is not UTF-8 JSON");
  }
  if (!bytes.equals(Buffer.from(JSON.stringify(receipt) + "\n", "utf8"))) {
    throw new Error("production infrastructure receipt is not in its exact representation");
  }
  exactObject(
    receipt,
    [
      "schemaVersion",
      "receiptType",
      "environment",
      "issuedAt",
      "validUntil",
      "application",
      "controller",
      "providerCanary",
      "protectedExecution",
      "verifiedState",
      "stableEvidence",
      "cloudflare",
      "resend",
      "runtimeSecrets",
    ],
    "production infrastructure receipt",
  );
  const issuedAt = exactInstant(receipt.issuedAt, "receipt issuedAt");
  const validUntil = exactInstant(receipt.validUntil, "receipt validUntil");
  if (
    receipt.schemaVersion !== 1 ||
    receipt.receiptType !== "fresh-towels-production-infrastructure-bootstrap" ||
    receipt.environment !== "production" ||
    validUntil - issuedAt !== 24 * 60 * 60 * 1000 ||
    now.valueOf() < issuedAt - 60_000 ||
    now.valueOf() >= validUntil
  ) {
    throw new Error("production infrastructure receipt is stale or invalid");
  }
  exactObject(receipt.application, ["repository", "repositoryId", "commitSha"], "receipt application");
  exactObject(receipt.controller, ["repository", "commitSha"], "receipt controller");
  if (
    receipt.application.repository !== expectedApplicationRepository ||
    receipt.application.repositoryId !== expectedApplicationRepositoryId ||
    receipt.application.commitSha !== materialized.release.applicationCommitSha ||
    receipt.controller.repository !== expectedControllerRepository ||
    receipt.controller.commitSha !== materialized.release.controllerCommitSha
  ) {
    throw new Error("production infrastructure receipt release identity changed");
  }
  exactObject(receipt.providerCanary, ["requestId", "receiptSha256", "runId"], "provider Canary prerequisite");
  if (
    !uuidPattern.test(receipt.providerCanary.requestId) ||
    !digestPattern.test(receipt.providerCanary.receiptSha256) ||
    !decimalPattern.test(receipt.providerCanary.runId)
  ) {
    throw new Error("provider Canary prerequisite is invalid");
  }
  exactObject(receipt.protectedExecution, ["brokerRequestId", "capsuleRequestSha256", "runId"], "bootstrap protected execution");
  if (
    !uuidPattern.test(receipt.protectedExecution.brokerRequestId) ||
    !digestPattern.test(receipt.protectedExecution.capsuleRequestSha256) ||
    !decimalPattern.test(receipt.protectedExecution.runId)
  ) {
    throw new Error("bootstrap protected execution is invalid");
  }
  exactObject(
    receipt.verifiedState,
    [
      "cloudflareTargetVerified",
      "cloudflareZoneActive",
      "d1TargetsVerified",
      "accessConfigurationVerified",
      "resendDomainVerified",
      "resendWebhookVerified",
    ],
    "bootstrap verified state",
  );
  const zoneReceiptConsistent =
    (receipt.verifiedState.cloudflareZoneActive === true &&
      receipt.cloudflare?.zoneStatus === "active") ||
    (receipt.verifiedState.cloudflareZoneActive === false &&
      receipt.cloudflare?.zoneStatus === "pending");
  if (
    !zoneReceiptConsistent ||
    Object.entries(receipt.verifiedState).some(
      ([key, value]) => key !== "cloudflareZoneActive" && value !== true,
    )
  ) {
    throw new Error("production provider bootstrap is not fully active");
  }
  exactObject(
    receipt.stableEvidence,
    [
      "redirectCandidateEvidenceSha256",
      "privacyOperationsEvidenceSha256",
      "legacyWordPressRecoveryEvidenceSha256",
    ],
    "stable release evidence",
  );
  if (Object.values(receipt.stableEvidence).some((value) => !digestPattern.test(value))) {
    throw new Error("stable release evidence is invalid");
  }
  exactObject(
    receipt.cloudflare,
    [
      "accountId",
      "zoneId",
      "zoneName",
      "zoneStatus",
      "nameServers",
      "zoneSettings",
      "dnsInventoryCount",
      "dnsInventorySha256",
      "workerName",
      "workersDevSubdomain",
      "d1",
      "access",
    ],
    "Cloudflare bootstrap receipt",
  );
  if (
    !/^[a-f0-9]{32}$/.test(receipt.cloudflare.accountId) ||
    !/^[a-f0-9]{32}$/.test(receipt.cloudflare.zoneId) ||
    receipt.cloudflare.zoneName !== expectedDomain ||
    !["active", "pending"].includes(receipt.cloudflare.zoneStatus) ||
    receipt.cloudflare.workerName !== expectedWorkerName ||
    typeof receipt.cloudflare.workersDevSubdomain !== "string" ||
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(receipt.cloudflare.workersDevSubdomain) ||
    !Array.isArray(receipt.cloudflare.nameServers) ||
    receipt.cloudflare.nameServers.length !== 2 ||
    new Set(receipt.cloudflare.nameServers).size !== 2 ||
    receipt.cloudflare.nameServers.some(
      (value) => !/^[a-z0-9-]+\.ns\.cloudflare\.com$/.test(value),
    ) ||
    canonicalJson(receipt.cloudflare.zoneSettings) !==
      canonicalJson({ always_use_https: "on", min_tls_version: "1.2", ssl: "strict" }) ||
    !Number.isSafeInteger(receipt.cloudflare.dnsInventoryCount) ||
    receipt.cloudflare.dnsInventoryCount < 0 ||
    receipt.cloudflare.dnsInventoryCount > 10_000 ||
    !digestPattern.test(receipt.cloudflare.dnsInventorySha256)
  ) {
    throw new Error("Cloudflare bootstrap receipt identity changed");
  }
  exactObject(receipt.cloudflare.d1, ["jurisdiction", "primary", "recovery"], "D1 receipt");
  for (const [kind, expectedName] of [
    ["primary", "fresh-towels-leads-prod"],
    ["recovery", "fresh-towels-leads-prod-recovery"],
  ]) {
    const database = receipt.cloudflare.d1[kind];
    exactObject(database, ["databaseName", "databaseId"], kind + " D1 receipt");
    if (database.databaseName !== expectedName) throw new Error(kind + " D1 name changed");
    exactUuid(database.databaseId, kind + " D1 ID");
  }
  if (
    receipt.cloudflare.d1.jurisdiction !== "eu" ||
    receipt.cloudflare.d1.primary.databaseId === receipt.cloudflare.d1.recovery.databaseId ||
    materialized.configurationTemplate.databaseName !== receipt.cloudflare.d1.primary.databaseName ||
    materialized.configurationTemplate.workerName !== receipt.cloudflare.workerName ||
    materialized.configurationTemplate.productionInfrastructureReceiptSha256 !== expectedSha256
  ) {
    throw new Error("production upload configuration differs from bootstrapped Cloudflare state");
  }
  validateAccessReceipt(receipt.cloudflare.access, materialized);
  exactObject(
    receipt.resend,
    [
      "domain",
      "domainId",
      "domainStatus",
      "sendingCapability",
      "senderAddress",
      "webhookId",
      "webhookEndpointSha256",
      "webhookEvents",
      "webhookStatus",
      "sendingKeyId",
      "sendingKeyName",
      "sendingKeyLeastPrivilegeProbeSha256",
    ],
    "Resend receipt",
  );
  if (
    receipt.resend.domain !== "notify.freshtowels.gr" ||
    !/^[A-Za-z0-9_-]{1,200}$/.test(receipt.resend.domainId) ||
    receipt.resend.domainStatus !== "verified" ||
    receipt.resend.sendingCapability !== "enabled" ||
    receipt.resend.senderAddress !== expectedSender ||
    !/^[A-Za-z0-9_-]{1,200}$/.test(receipt.resend.webhookId) ||
    receipt.resend.webhookEndpointSha256 !==
      sha256(Buffer.from("https://freshtowels.gr/api/webhooks/resend", "utf8")) ||
    canonicalJson(receipt.resend.webhookEvents) !==
      canonicalJson([
        "email.bounced",
        "email.complained",
        "email.delivered",
        "email.delivery_delayed",
        "email.failed",
        "email.sent",
        "email.suppressed",
      ]) ||
    receipt.resend.webhookStatus !== "enabled" ||
    !/^[A-Za-z0-9_-]{1,200}$/.test(receipt.resend.sendingKeyId) ||
    receipt.resend.sendingKeyName !== "Fresh Towels Production Worker" ||
    !digestPattern.test(receipt.resend.sendingKeyLeastPrivilegeProbeSha256)
  ) {
    throw new Error("Resend bootstrap receipt identity changed");
  }
  exactObject(
    receipt.runtimeSecrets,
    ["dashboardAuthorizedEmails", "leadRateLimitSecret", "resendApiKey", "resendWebhookSecret"],
    "bootstrap runtime secret custody",
  );
  const runtimeSecrets = Object.freeze({
    DASHBOARD_AUTHORIZED_EMAILS: exactBootstrapSecret(
      receipt.runtimeSecrets.dashboardAuthorizedEmails,
      "DASHBOARD_AUTHORIZED_EMAILS",
    ),
    LEAD_RATE_LIMIT_SECRET: exactBootstrapSecret(
      receipt.runtimeSecrets.leadRateLimitSecret,
      "LEAD_RATE_LIMIT_SECRET",
    ),
    RESEND_API_KEY: exactBootstrapSecret(receipt.runtimeSecrets.resendApiKey, "RESEND_API_KEY"),
    RESEND_WEBHOOK_SECRET: exactBootstrapSecret(
      receipt.runtimeSecrets.resendWebhookSecret,
      "RESEND_WEBHOOK_SECRET",
    ),
  });
  return Object.freeze({ receipt, runtimeSecrets, receiptSha256: expectedSha256 });
}

function validateAccessReceipt(access, materialized) {
  exactObject(
    access,
    [
      "identityProviderId",
      "identityProviderType",
      "applicationId",
      "applicationDomain",
      "policyId",
      "aud",
      "destinations",
      "allowedIdentityProviderIds",
      "adminIdentitySha256",
      "policyDecision",
      "policyPrecedence",
      "extraPolicyCount",
      "httpOnlyCookieAttribute",
      "sameSiteCookieAttribute",
      "enableBindingCookie",
      "pathCookieAttribute",
      "allowIframe",
      "allowAuthenticateViaWarp",
      "skipInterstitial",
      "optionsPreflightBypass",
      "appLauncherVisible",
      "autoRedirectToIdentity",
      "teamDomain",
      "organizationSessionDuration",
      "applicationSessionDuration",
    ],
    "Access bootstrap receipt",
  );
  exactUuid(access.identityProviderId, "Access identity provider ID");
  exactUuid(access.applicationId, "Access application ID");
  exactUuid(access.policyId, "Access policy ID");
  const expectedDestinations = [
    { type: "public", uri: "freshtowels.gr/api/internal/*" },
    { type: "public", uri: "freshtowels.gr/internal/leads" },
    { type: "public", uri: "freshtowels.gr/internal/leads/*" },
  ];
  if (
    access.identityProviderType !== "onetimepin" ||
    access.applicationDomain !== "freshtowels.gr/internal/leads" ||
    access.policyDecision !== "allow" ||
    access.policyPrecedence !== 1 ||
    access.extraPolicyCount !== 0 ||
    access.organizationSessionDuration !== "8h" ||
    access.applicationSessionDuration !== "8h" ||
    canonicalJson(access.destinations) !== canonicalJson(expectedDestinations) ||
    canonicalJson(access.allowedIdentityProviderIds) !== canonicalJson([access.identityProviderId]) ||
    !digestPattern.test(access.adminIdentitySha256) ||
    access.httpOnlyCookieAttribute !== true ||
    access.sameSiteCookieAttribute !== "strict" ||
    access.enableBindingCookie !== true ||
    access.pathCookieAttribute !== false ||
    access.allowIframe !== false ||
    access.allowAuthenticateViaWarp !== false ||
    access.skipInterstitial !== false ||
    access.optionsPreflightBypass !== false ||
    access.appLauncherVisible !== false ||
    access.autoRedirectToIdentity !== true ||
    typeof access.aud !== "string" ||
    !/^[A-Za-z0-9_-]{16,200}$/.test(access.aud) ||
    typeof access.teamDomain !== "string" ||
    !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(access.teamDomain)
  ) {
    throw new Error("Access bootstrap receipt security contract changed");
  }
}

function hydrateTemplateValue(value, replacements) {
  if (typeof value === "string") return replacements.get(value) ?? value;
  if (Array.isArray(value)) return value.map((item) => hydrateTemplateValue(item, replacements));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, hydrateTemplateValue(item, replacements)]),
    );
  }
  return value;
}

export async function hydrateProductionConfiguration({ materialized, infrastructure }) {
  const template = materialized.configurationTemplate.template;
  const receipt = infrastructure.receipt;
  const replacements = new Map([
    [productionDeploymentPlaceholders.accountId, receipt.cloudflare.accountId],
    [productionDeploymentPlaceholders.databaseId, receipt.cloudflare.d1.primary.databaseId],
    [productionDeploymentPlaceholders.accessAudience, receipt.cloudflare.access.aud],
    [productionDeploymentPlaceholders.accessTeamDomain, receipt.cloudflare.access.teamDomain],
    [
      productionDeploymentPlaceholders.previewSuffix,
      `${receipt.cloudflare.workerName}.${receipt.cloudflare.workersDevSubdomain}.workers.dev`,
    ],
  ]);
  const serializedTemplate = JSON.stringify(template);
  for (const placeholder of Object.values(productionDeploymentPlaceholders)) {
    if (serializedTemplate.split(placeholder).length !== 2) {
      throw new Error("production deployment placeholder cardinality changed");
    }
  }
  const configuration = hydrateTemplateValue(template, replacements);
  const bytes = Buffer.from(JSON.stringify(configuration, null, 2) + "\n", "utf8");
  if (Object.values(productionDeploymentPlaceholders).some((value) => bytes.includes(value))) {
    throw new Error("production deployment configuration retains a placeholder");
  }
  const outputPath = resolve(materialized.root, "wrangler.jsonc");
  if (dirname(outputPath) !== materialized.root || (await lstat(outputPath).catch(() => null))) {
    throw new Error("hydrated production configuration target is unsafe");
  }
  await writeFile(outputPath, bytes, { flag: "wx", mode: 0o600 });
  const status = await lstat(outputPath);
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== 1 ||
    (await realpath(outputPath)) !== outputPath ||
    !bytes.equals(await readFile(outputPath))
  ) {
    throw new Error("hydrated production configuration write changed");
  }
  return Object.freeze({
    path: outputPath,
    sha256: sha256(bytes),
    runtimeVariables: Object.freeze(structuredClone(configuration.vars)),
    runtimeVariablesSha256: sha256(Buffer.from(JSON.stringify(configuration.vars))),
    compatibilityDate: configuration.compatibility_date,
    compatibilityFlags: Object.freeze([...(configuration.compatibility_flags ?? [])]),
    assetsBindingName: configuration.assets?.binding ?? null,
  });
}

function strongRateLimitSecret(value) {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    !/^[\x21-\x7e]{32,256}$/.test(value) ||
    /(?:placeholder|dummy|example|synthetic|local|development|test|password|secret)/i.test(value) ||
    new Set(value).size < 8
  ) {
    return false;
  }
  for (let size = 1; size <= Math.min(16, Math.floor(value.length / 2)); size += 1) {
    if (value.length % size === 0 && value.slice(0, size).repeat(value.length / size) === value) {
      return false;
    }
  }
  return true;
}

function validWebhookSecret(value) {
  if (typeof value !== "string" || !value.startsWith("whsec_") || /[\r\n\0]/.test(value)) {
    return false;
  }
  const encoded = value.slice(6).replaceAll("-", "+").replaceAll("_", "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.length % 4 === 1) return false;
  try {
    return Buffer.from(encoded, "base64").byteLength >= 16;
  } catch {
    return false;
  }
}

export function validateMaterializedRuntimeSecrets({ materializedSecrets, receipt }) {
  exactObject(materializedSecrets, requiredSecretBindings, "materialized runtime secrets");
  const values = {};
  for (const binding of requiredSecretBindings) {
    const value = materializedSecrets[binding];
    exactObject(
      value,
      [
        "bindingVersionSha256",
        "bytes",
        "custodySha256",
        "payloadKind",
        "plaintextSha256",
        "resourceIdentitySha256",
      ],
      "materialized runtime secret " + binding,
    );
    const expected = receipt.runtimeSecrets[binding];
    if (
      value.payloadKind !== "secret" ||
      !Buffer.isBuffer(value.bytes) ||
      value.bytes.byteLength < 1 ||
      value.bytes.byteLength > 4096 ||
      sha256(value.bytes) !== value.plaintextSha256 ||
      value.bindingVersionSha256 !== expected.bindingVersionSha256 ||
      value.resourceIdentitySha256 !== expected.resourceIdentitySha256 ||
      !digestPattern.test(value.custodySha256)
    ) {
      throw new Error("materialized runtime secret differs from bootstrap custody");
    }
    values[binding] = new TextDecoder("utf-8", { fatal: true }).decode(value.bytes);
  }
  if (
    !emailPattern.test(values.DASHBOARD_AUTHORIZED_EMAILS) ||
    values.DASHBOARD_AUTHORIZED_EMAILS !== values.DASHBOARD_AUTHORIZED_EMAILS.toLowerCase() ||
    values.DASHBOARD_AUTHORIZED_EMAILS.includes(",") ||
    sha256(Buffer.from(values.DASHBOARD_AUTHORIZED_EMAILS, "utf8")) !==
      receipt.receipt.cloudflare.access.adminIdentitySha256 ||
    !strongRateLimitSecret(values.LEAD_RATE_LIMIT_SECRET) ||
    !/^re_[^\s]{17,}$/.test(values.RESEND_API_KEY) ||
    !validWebhookSecret(values.RESEND_WEBHOOK_SECRET)
  ) {
    throw new Error("materialized production runtime secret semantics are invalid");
  }
  // Do not return immutable JavaScript strings containing provider/runtime
  // secrets.  The caller keeps the bounded Buffer instances only long enough
  // to create Wrangler's private secrets file, then zeroes them in `finally`.
  // The strings above are intentionally scoped to this validation call.
  return true;
}

function validateDatabaseState(value, expected, expectedMigrations, label) {
  exactObject(
    value,
    [
      "databaseId",
      "databaseName",
      "jurisdiction",
      "appliedMigrations",
      "schemaVersion",
      "schemaSha256",
      "leadCount",
    ],
    label,
  );
  if (
    value.databaseId !== expected.databaseId ||
    value.databaseName !== expected.databaseName ||
    value.jurisdiction !== "eu" ||
    !Array.isArray(value.appliedMigrations) ||
    !Number.isSafeInteger(value.schemaVersion) ||
    value.schemaVersion < 0 ||
    !digestPattern.test(value.schemaSha256) ||
    !Number.isSafeInteger(value.leadCount) ||
    value.leadCount !== 0
  ) {
    throw new Error(label + " identity or empty-state proof changed");
  }
  for (const item of value.appliedMigrations) {
    exactObject(item, ["version", "name"], label + " migration");
  }
  const expectedPrefix = expectedMigrations.slice(0, value.appliedMigrations.length);
  if (
    canonicalJson(value.appliedMigrations) !==
      canonicalJson(expectedPrefix.map((item) => ({ version: item.version, name: item.name })))
  ) {
    throw new Error(label + " migration history is not an exact prefix");
  }
  return value;
}

function migrationPlan(materialized) {
  return Object.freeze(
    materialized.files
      .filter((entry) => /^migrations\/\d{4}_[a-z0-9_]+\.sql$/.test(entry.path))
      .map((entry) => ({
        version: Number(entry.path.slice("migrations/".length, "migrations/0000".length)),
        name: entry.path.slice("migrations/".length),
        path: entry.path,
        bytes: entry.bytes,
        sha256: entry.sha256,
      })),
  );
}

function validateRecoveryProof(value, expected) {
  exactObject(
    value,
    [
      "primaryDatabaseIdSha256",
      "recoveryDatabaseIdSha256",
      "plaintextBackupSha256",
      "encryptedBackupSha256",
      "encryptionKeySha256",
      "decryptionProofSha256",
      "encryptedCustodyBindingVersionSha256",
      "encryptedCustodyCiphertextSha256",
      "encryptedCustodySha256",
      "encryptedCustodyDecryptionProofSha256",
      "primarySchemaSha256",
      "recoverySchemaSha256",
      "timeTravelBookmarkSha256",
      "recoveryLeadCount",
      "plaintextRetained",
    ],
    "encrypted D1 recovery proof",
  );
  if (
    value.primaryDatabaseIdSha256 !== sha256(Buffer.from(expected.primary.databaseId)) ||
    value.recoveryDatabaseIdSha256 !== sha256(Buffer.from(expected.recovery.databaseId)) ||
    value.primarySchemaSha256 !== expected.schemaSha256 ||
    value.recoverySchemaSha256 !== expected.schemaSha256 ||
    value.recoveryLeadCount !== 0 ||
    value.plaintextRetained !== false ||
    [
      value.plaintextBackupSha256,
      value.encryptedBackupSha256,
      value.encryptionKeySha256,
      value.decryptionProofSha256,
      value.encryptedCustodyBindingVersionSha256,
      value.encryptedCustodyCiphertextSha256,
      value.encryptedCustodySha256,
      value.encryptedCustodyDecryptionProofSha256,
      value.timeTravelBookmarkSha256,
    ].some((item) => !digestPattern.test(item))
  ) {
    throw new Error("encrypted D1 recovery proof is invalid");
  }
  return value;
}

function validateProviderVerification(value, receipt) {
  exactObject(
    value,
    ["cloudflare", "resend", "stateSha256"],
    "production provider revalidation",
  );
  exactDigest(value.stateSha256, "production provider state digest");
  if (
    canonicalJson(value.cloudflare) !== canonicalJson(receipt.cloudflare) ||
    canonicalJson(value.resend) !== canonicalJson(receipt.resend) ||
    value.stateSha256 !== digest({ cloudflare: value.cloudflare, resend: value.resend })
  ) {
    throw new Error("production provider revalidation is invalid");
  }
  return value;
}

function validateWorkerVersion(value, expected) {
  exactObject(
    value,
    [
      "versionId",
      "tag",
      "message",
      "workerName",
      "uploadArtifactSha256",
      "configurationSha256",
      "runtimeSecretsSha256",
      "workerModuleSha256",
      "staticAssetsTreeSha256",
      "runtimeVariables",
      "compatibilityDate",
      "compatibilityFlags",
      "assetsBindingName",
      "stateSha256",
    ],
    "Worker version",
  );
  exactUuid(value.versionId, "Worker version ID");
  if (
    value.tag !== expected.tag ||
    value.message !== expected.message ||
    value.workerName !== expected.workerName ||
    value.uploadArtifactSha256 !== expected.uploadArtifactSha256 ||
    value.configurationSha256 !== expected.configurationSha256 ||
    value.runtimeSecretsSha256 !== expected.runtimeSecretsSha256 ||
    value.workerModuleSha256 !== expected.workerModuleSha256 ||
    value.staticAssetsTreeSha256 !== expected.staticAssetsTreeSha256 ||
    canonicalJson(value.runtimeVariables) !== canonicalJson(expected.runtimeVariables) ||
    value.compatibilityDate !== expected.compatibilityDate ||
    canonicalJson(value.compatibilityFlags) !== canonicalJson(expected.compatibilityFlags) ||
    value.assetsBindingName !== expected.assetsBindingName ||
    !digestPattern.test(value.stateSha256)
  ) {
    throw new Error("Worker version differs from the approved immutable artifact");
  }
  return value;
}

function validateDeployment(value, versionId) {
  exactObject(value, ["versionId", "percentage", "stateSha256"], "Worker deployment");
  if (value.versionId !== versionId || value.percentage !== 100 || !digestPattern.test(value.stateSha256)) {
    throw new Error("Worker deployment is not the exact approved version at 100 percent");
  }
  return value;
}

function validateTriggerState(value) {
  exactObject(value, ["crons", "routes", "stateSha256"], "Worker trigger state");
  if (
    canonicalJson(value.crons) !== canonicalJson(["*/5 * * * *"]) ||
    !Array.isArray(value.routes) ||
    value.routes.length !== 0 ||
    !digestPattern.test(value.stateSha256)
  ) {
    throw new Error("Worker trigger state exceeds the pre-cutover allowlist");
  }
  return value;
}

function validateCandidateVerification(value, expectedStateSha256) {
  exactObject(
    value,
    [
      "candidateEvidenceSha256",
      "candidateRoutesPreCutoverStateSha256",
      "completedAt",
      "custodyBindingVersionSha256",
      "custodyCiphertextSha256",
      "custodyDecryptionProofSha256",
      "custodyProofSha256",
      "custodySha256",
      "leadArchivedStateSha256",
      "privateReceiptSha256",
      "productionReleaseStateSha256",
      "resendDeliveryStateSha256",
    ],
    "production candidate verification",
  );
  exactInstant(value.completedAt, "production candidate completedAt");
  if (
    value.productionReleaseStateSha256 !== expectedStateSha256 ||
    Object.entries(value).some(
      ([key, item]) => key.endsWith("Sha256") && !digestPattern.test(item ?? ""),
    ) ||
    value.custodyProofSha256 !==
      digest({
        bindingVersionSha256: value.custodyBindingVersionSha256,
        ciphertextSha256: value.custodyCiphertextSha256,
        custodySha256: value.custodySha256,
        decryptionProofSha256: value.custodyDecryptionProofSha256,
        privateReceiptSha256: value.privateReceiptSha256,
      })
  ) {
    throw new Error("production candidate verification is invalid");
  }
  return value;
}

function hashOnlyReceipt({
  release,
  provider,
  primary,
  recovery,
  recoveryProof,
  workerVersion,
  deployment,
  triggerState,
  candidateVerification,
  completedAt,
  protectedExecutionRunId,
}) {
  const body = {
    schema: "deployment-control/production-release-evidence/v1",
    operation: "production-release",
    releaseId: release.releaseId,
    applicationCommitSha: release.applicationCommitSha,
    controllerCommitSha: release.controllerCommitSha,
    buildArtifactSha256: release.buildArtifactSha256,
    uploadArtifactSha256: release.uploadArtifactSha256,
    productionInfrastructureReceiptSha256: release.productionInfrastructureReceiptSha256,
    protectedExecutionRunId,
    providerStateSha256: digest(provider),
    primaryDatabaseStateSha256: primary.schemaSha256,
    recoveryDatabaseStateSha256: recovery.schemaSha256,
    encryptedRecoveryProofSha256: digest(recoveryProof),
    workerVersionIdSha256: sha256(Buffer.from(workerVersion.versionId)),
    workerVersionStateSha256: workerVersion.stateSha256,
    deploymentStateSha256: deployment.stateSha256,
    triggerStateSha256: triggerState.stateSha256,
    productionCandidateEvidenceSha256:
      candidateVerification.candidateEvidenceSha256,
    productionCandidateReceiptSha256:
      candidateVerification.privateReceiptSha256,
    productionCandidateCustodyProofSha256:
      candidateVerification.custodyProofSha256,
    candidateRoutesPreCutoverStateSha256:
      candidateVerification.candidateRoutesPreCutoverStateSha256,
    result: "verified",
    completedAt,
  };
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

export async function executeProductionReleaseAdapter({
  adapter,
  infrastructure,
  materialized,
  runtimeSecrets,
  protectedExecutionRunId,
  now = () => new Date(),
}) {
  const requiredMethods = [
    "verifyProviderState",
    "inspectDatabase",
    "applyOrderedMigrations",
    "createEncryptedRecoveryProof",
    "inspectWorkerVersion",
    "uploadWorkerVersion",
    "inspectDeployment",
    "deployWorkerVersion",
    "rollbackWorkerDeployment",
    "inspectTriggers",
    "deployTriggers",
    "executeCandidateVerification",
  ];
  if (
    !adapter ||
    requiredMethods.some((name) => typeof adapter[name] !== "function") ||
    !decimalPattern.test(protectedExecutionRunId ?? "")
  ) {
    throw new Error("production release adapter dependency is unavailable");
  }
  try {
    validateMaterializedRuntimeSecrets({
      materializedSecrets: runtimeSecrets,
      receipt: infrastructure,
    });
    const migrations = migrationPlan(materialized);
    if (migrations.length !== materialized.database.currentLeadSchemaVersion) {
      throw new Error("production release migration plan changed");
    }
    const d1 = infrastructure.receipt.cloudflare.d1;
    const expected = {
      primary: d1.primary,
      recovery: d1.recovery,
      schemaSha256: null,
    };
    const provider = validateProviderVerification(
      await adapter.verifyProviderState({
        infrastructure: infrastructure.receipt,
        runtimeSecrets,
      }),
      infrastructure.receipt,
    );
    // This is the first production release. Any existing script/version is
    // outside the approved release and must be resolved before D1 is mutated.
    if ((await adapter.inspectWorkerVersion({ workerName: expectedWorkerName })) !== null) {
      throw new Error("pre-existing Worker/version blocks the initial production release");
    }
    const initialDeployment = await adapter.inspectDeployment({ workerName: expectedWorkerName });
    const initialTriggers = await adapter.inspectTriggers({ workerName: expectedWorkerName });
    if (
      initialDeployment !== null ||
      initialTriggers === null ||
      canonicalJson(initialTriggers.crons) !== canonicalJson([]) ||
      canonicalJson(initialTriggers.routes) !== canonicalJson([])
    ) {
      throw new Error("pre-existing Worker deployment or trigger blocks the initial release");
    }
    const hydratedConfiguration = await hydrateProductionConfiguration({
      materialized,
      infrastructure,
    });
    let primary = validateDatabaseState(
      await adapter.inspectDatabase({ database: d1.primary, kind: "primary", migrations }),
      d1.primary,
      migrations,
      "primary D1",
    );
    if (primary.appliedMigrations.length !== migrations.length) {
      await adapter.applyOrderedMigrations({
        database: d1.primary,
        kind: "primary",
        migrations,
        materializedRoot: materialized.root,
        idempotencyKey: digest({
          releaseId: materialized.release.releaseId,
          databaseId: d1.primary.databaseId,
          databasePayloadTreeSha256: materialized.manifest.databasePayloadTreeSha256,
        }),
      });
      primary = validateDatabaseState(
        await adapter.inspectDatabase({ database: d1.primary, kind: "primary", migrations }),
        d1.primary,
        migrations,
        "primary D1",
      );
    }
    if (
      primary.appliedMigrations.length !== migrations.length ||
      primary.schemaVersion !== materialized.database.currentLeadSchemaVersion
    ) {
      throw new Error("primary D1 migrations did not converge exactly");
    }
    expected.schemaSha256 = primary.schemaSha256;
    let recovery = validateDatabaseState(
      await adapter.inspectDatabase({ database: d1.recovery, kind: "recovery", migrations }),
      d1.recovery,
      migrations,
      "recovery D1",
    );
    const recoveryProof = validateRecoveryProof(
      await adapter.createEncryptedRecoveryProof({
        primary: d1.primary,
        recovery: d1.recovery,
        migrations,
        materializedRoot: materialized.root,
        expectedSchemaVersion: materialized.database.currentLeadSchemaVersion,
        expectedSchemaSha256: expected.schemaSha256,
        releaseId: materialized.release.releaseId,
      }),
      expected,
    );
    recovery = validateDatabaseState(
      await adapter.inspectDatabase({ database: d1.recovery, kind: "recovery", migrations }),
      d1.recovery,
      migrations,
      "recovery D1",
    );
    if (
      recovery.appliedMigrations.length !== migrations.length ||
      recovery.schemaVersion !== materialized.database.currentLeadSchemaVersion ||
      recovery.schemaSha256 !== primary.schemaSha256
    ) {
      throw new Error("isolated recovery D1 did not reproduce the primary schema");
    }

    // A 24-hour bootstrap receipt is one-use evidence, not permission to rely
    // on stale provider state. Reconcile the exact provider targets again
    // immediately before the immutable Worker upload/deployment phase.
    const providerBeforeUpload = validateProviderVerification(
      await adapter.verifyProviderState({
        infrastructure: infrastructure.receipt,
        runtimeSecrets,
      }),
      infrastructure.receipt,
    );
    if (canonicalJson(providerBeforeUpload) !== canonicalJson(provider)) {
      throw new Error("production provider state changed during protected execution");
    }
    const runtimeSecretsSha256 = digest(
      Object.fromEntries(
        requiredSecretBindings.map((binding) => [
          binding,
          infrastructure.runtimeSecrets[binding].bindingVersionSha256,
        ]),
      ),
    );
    const versionExpected = Object.freeze({
      tag: "release-" + materialized.release.releaseId.slice(0, 32),
      message:
        "Fresh Towels release " +
        materialized.release.applicationCommitSha +
        " " +
        materialized.release.uploadArtifactSha256 +
        " " +
        hydratedConfiguration.sha256 +
        " " +
        runtimeSecretsSha256,
      workerName: infrastructure.receipt.cloudflare.workerName,
      uploadArtifactSha256: materialized.release.uploadArtifactSha256,
      configurationSha256: hydratedConfiguration.sha256,
      runtimeSecretsSha256,
      workerModuleSha256: materialized.manifest.workerModuleSha256,
      staticAssetsTreeSha256: materialized.manifest.staticAssetsTreeSha256,
      runtimeVariables: hydratedConfiguration.runtimeVariables,
      compatibilityDate: hydratedConfiguration.compatibilityDate,
      compatibilityFlags: hydratedConfiguration.compatibilityFlags,
      assetsBindingName: hydratedConfiguration.assetsBindingName,
    });
    // Never adopt a pre-existing remote version based only on mutable provider
    // annotations. A release ID/tag is one-use: the exact upload must occur in
    // this protected execution and return the version subsequently reconciled.
    if ((await adapter.inspectWorkerVersion({ workerName: versionExpected.workerName })) !== null) {
      throw new Error("Worker release tag already exists and cannot be adopted");
    }
    let workerVersion;
    let deployment;
    let triggers;
    let candidateVerification;
    let uploadAttempted = false;
    try {
      let uploadedWorkerVersion;
      try {
        uploadedWorkerVersion = await adapter.uploadWorkerVersion({
          expected: versionExpected,
          materialized,
          hydratedConfiguration,
          runtimeSecrets,
        });
        uploadAttempted = true;
      } catch (error) {
        uploadAttempted = error?.workerUploadAttempted === true;
        throw error;
      }
      workerVersion = validateWorkerVersion(uploadedWorkerVersion, versionExpected);
      const reconciledWorkerVersion = validateWorkerVersion(
        await adapter.inspectWorkerVersion(versionExpected, workerVersion.versionId),
        versionExpected,
      );
      if (canonicalJson(reconciledWorkerVersion) !== canonicalJson(workerVersion)) {
        throw new Error("Worker version changed after exact upload");
      }
      workerVersion = reconciledWorkerVersion;
      await adapter.deployWorkerVersion({
        versionId: workerVersion.versionId,
        workerName: versionExpected.workerName,
        message: "Deploy exact release " + materialized.release.releaseId,
      });
      deployment = validateDeployment(
        await adapter.inspectDeployment({ workerName: versionExpected.workerName }),
        workerVersion.versionId,
      );
      triggers = await adapter.inspectTriggers({ workerName: versionExpected.workerName });
      if (
        !triggers ||
        canonicalJson(triggers.crons) !== canonicalJson(["*/5 * * * *"]) ||
        !Array.isArray(triggers.routes) ||
        triggers.routes.length !== 0
      ) {
        await adapter.deployTriggers({
          workerName: versionExpected.workerName,
          crons: ["*/5 * * * *"],
          routes: [],
        });
        triggers = await adapter.inspectTriggers({ workerName: versionExpected.workerName });
      }
      triggers = validateTriggerState(triggers);
      const productionReleaseStateSha256 = digest({
        release: materialized.release,
        protectedExecutionRunId,
        providerStateSha256: provider.stateSha256,
        primaryDatabaseStateSha256: primary.schemaSha256,
        recoveryDatabaseStateSha256: recovery.schemaSha256,
        encryptedRecoveryProofSha256: digest(recoveryProof),
        workerVersionId: workerVersion.versionId,
        workerVersionStateSha256: workerVersion.stateSha256,
        deploymentStateSha256: deployment.stateSha256,
        triggerStateSha256: triggers.stateSha256,
      });
      candidateVerification = validateCandidateVerification(
        await adapter.executeCandidateVerification({
          deployment,
          infrastructure,
          materialized,
          now,
          primary,
          productionReleaseStateSha256,
          protectedExecutionRunId,
          provider,
          recovery,
          recoveryProof,
          triggerState: triggers,
          workerVersion,
          workerVersionExpected: versionExpected,
        }),
        productionReleaseStateSha256,
      );
    } catch (error) {
      if (!uploadAttempted) throw error;
      try {
        await adapter.rollbackWorkerDeployment({
          workerName: versionExpected.workerName,
          createdVersionId: workerVersion?.versionId ?? null,
          previousDeployment: initialDeployment,
          previousTriggers: initialTriggers,
        });
      } catch {
        throw new Error("production release failed and Worker rollback is ambiguous");
      }
      throw error;
    }
    const completedAt = candidateVerification.completedAt;
    return hashOnlyReceipt({
      release: materialized.release,
      provider,
      primary,
      recovery,
      recoveryProof,
      workerVersion,
      deployment,
      triggerState: triggers,
      candidateVerification,
      completedAt,
      protectedExecutionRunId,
    });
  } finally {
    if (runtimeSecrets && typeof runtimeSecrets === "object") {
      for (const value of Object.values(runtimeSecrets)) {
        if (Buffer.isBuffer(value?.bytes)) value.bytes.fill(0);
      }
    }
  }
}

export const productionReleaseConstants = Object.freeze({
  requiredSecretBindings,
});
