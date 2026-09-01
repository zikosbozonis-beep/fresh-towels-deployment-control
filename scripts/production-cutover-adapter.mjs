import { canonicalJson, sha256 } from "./control-contract.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const accountPattern = /^[a-f0-9]{32}$/;

const expectedApplicationRepository = "zikosbozonis-beep/fresh-towels-website";
const expectedApplicationRepositoryId = "1350923567";
const expectedControllerRepository =
  "zikosbozonis-beep/fresh-towels-deployment-control";
const expectedWorkerName = "fresh-towels-production";
const expectedZoneName = "freshtowels.gr";
const expectedResendDomain = "notify.freshtowels.gr";
const expectedResendSender = "notifications@notify.freshtowels.gr";
const expectedAccessDomain = "freshtowels.gr/internal/leads";
const expectedD1Name = "fresh-towels-leads-prod";

export const productionCandidateRoutes = Object.freeze([
  "freshtowels.gr/api/internal/*",
  "freshtowels.gr/api/leads",
  "freshtowels.gr/api/webhooks/resend",
  "freshtowels.gr/internal/leads",
  "freshtowels.gr/internal/leads/*",
]);

export const productionFullRoutes = Object.freeze([
  "freshtowels.gr/*",
  "www.freshtowels.gr/*",
]);
export const productionPreCutoverRoutes = Object.freeze([
  "freshtowels.gr/api/internal/*",
  "freshtowels.gr/internal/leads",
  "freshtowels.gr/internal/leads/*",
]);

const criticalRoutes = Object.freeze([
  "/",
  "/petsetes-kommotiriou",
  "/petsetes-massage",
  "/\u03c4\u03b9\u03bc\u03bf\u03ba\u03b1\u03c4\u03ac\u03bb\u03bf\u03b3\u03bf\u03c2/",
  "/pos-leitourgei",
  "/perioches-eksypiretisis",
  "/epikoinonia",
  "/politiki-aporritou",
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
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(label + " contains missing or unexpected fields");
  }
}

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
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

function exactInstant(value, label) {
  if (typeof value !== "string") throw new Error(label + " is invalid");
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(label + " is not canonical UTC");
  }
  return timestamp;
}

function sortedExact(values, expected, label) {
  if (
    !Array.isArray(values) ||
    values.some((value) => typeof value !== "string") ||
    canonicalJson(values) !== canonicalJson([...values].sort()) ||
    canonicalJson(values) !== canonicalJson(expected)
  ) {
    throw new Error(label + " differs from the exact allowlist");
  }
}

function selfDigest(value, stateKey = "stateSha256") {
  return digest(Object.fromEntries(Object.entries(value).filter(([key]) => key !== stateKey)));
}

function exactSelfDigest(value, label, stateKey = "stateSha256") {
  exactDigest(value[stateKey], label + " digest");
  if (value[stateKey] !== selfDigest(value, stateKey)) {
    throw new Error(label + " digest changed");
  }
}

export function validateProductionCutoverInput(input, { now = new Date() } = {}) {
  exactObject(
    input,
    [
      "schemaVersion",
      "operation",
      "environment",
      "issuedAt",
      "validUntil",
      "cutoverRequestId",
      "release",
      "productionReleasePrerequisite",
      "worker",
      "provider",
      "candidate",
    ],
    "production cutover input",
  );
  const issuedAt = exactInstant(input.issuedAt, "cutover issuedAt");
  const validUntil = exactInstant(input.validUntil, "cutover validUntil");
  if (
    input.schemaVersion !== 1 ||
    input.operation !== "production-cutover" ||
    input.environment !== "production" ||
    validUntil <= issuedAt ||
    validUntil - issuedAt > 4 * 60 * 60 * 1000 ||
    now.valueOf() < issuedAt - 60_000 ||
    now.valueOf() >= validUntil
  ) {
    throw new Error("production cutover input is stale or invalid");
  }
  exactUuid(input.cutoverRequestId, "cutover request ID");

  exactObject(
    input.release,
    [
      "releaseId",
      "applicationRepository",
      "applicationRepositoryId",
      "applicationCommitSha",
      "controllerRepository",
      "controllerCommitSha",
      "buildArtifactSha256",
      "uploadArtifactSha256",
      "productionInfrastructureReceiptSha256",
    ],
    "production cutover release",
  );
  if (
    !digestPattern.test(input.release.releaseId) ||
    input.release.applicationRepository !== expectedApplicationRepository ||
    input.release.applicationRepositoryId !== expectedApplicationRepositoryId ||
    !commitPattern.test(input.release.applicationCommitSha) ||
    input.release.controllerRepository !== expectedControllerRepository ||
    !commitPattern.test(input.release.controllerCommitSha)
  ) {
    throw new Error("production cutover release identity changed");
  }
  for (const key of [
    "buildArtifactSha256",
    "uploadArtifactSha256",
    "productionInfrastructureReceiptSha256",
  ]) {
    exactDigest(input.release[key], "release " + key);
  }

  exactObject(
    input.productionReleasePrerequisite,
    ["requestId", "runId", "receiptSha256", "completedAt"],
    "production release prerequisite",
  );
  exactUuid(input.productionReleasePrerequisite.requestId, "production release request ID");
  if (!decimalPattern.test(input.productionReleasePrerequisite.runId)) {
    throw new Error("production release run ID is invalid");
  }
  exactDigest(
    input.productionReleasePrerequisite.receiptSha256,
    "production release receipt",
  );
  const releaseCompletedAt = exactInstant(
    input.productionReleasePrerequisite.completedAt,
    "production release completedAt",
  );
  if (releaseCompletedAt > issuedAt) {
    throw new Error("production release prerequisite is newer than the cutover request");
  }

  exactObject(
    input.worker,
    ["name", "versionId", "versionStateSha256", "deploymentStateSha256"],
    "approved Worker",
  );
  if (input.worker.name !== expectedWorkerName) {
    throw new Error("production Worker identity changed");
  }
  exactUuid(input.worker.versionId, "Worker version ID");
  exactDigest(input.worker.versionStateSha256, "Worker version state");
  exactDigest(input.worker.deploymentStateSha256, "Worker deployment state");

  exactObject(
    input.provider,
    [
      "accountId",
      "zoneId",
      "zoneName",
      "fullDnsInventorySha256",
      "primaryDatabaseIdSha256",
      "primaryDatabaseName",
      "primaryDatabaseJurisdiction",
      "primaryDatabaseSchemaVersion",
      "primaryDatabaseSchemaSha256",
      "primaryDatabaseStateSha256",
      "accessApplicationId",
      "accessApplicationDomain",
      "accessAdminIdentitySha256",
      "accessStateSha256",
      "resendDomain",
      "resendStateSha256",
      "providerStateSha256",
    ],
    "approved provider state",
  );
  if (
    !accountPattern.test(input.provider.accountId) ||
    !accountPattern.test(input.provider.zoneId) ||
    input.provider.zoneName !== expectedZoneName ||
    input.provider.primaryDatabaseName !== expectedD1Name ||
    input.provider.primaryDatabaseJurisdiction !== "eu" ||
    !Number.isSafeInteger(input.provider.primaryDatabaseSchemaVersion) ||
    input.provider.primaryDatabaseSchemaVersion < 1 ||
    input.provider.accessApplicationDomain !== expectedAccessDomain ||
    input.provider.resendDomain !== expectedResendDomain
  ) {
    throw new Error("production provider identity changed");
  }
  exactUuid(input.provider.accessApplicationId, "Access application ID");
  for (const key of [
    "fullDnsInventorySha256",
    "primaryDatabaseIdSha256",
    "primaryDatabaseSchemaSha256",
    "primaryDatabaseStateSha256",
    "accessAdminIdentitySha256",
    "accessStateSha256",
    "resendStateSha256",
    "providerStateSha256",
  ]) {
    exactDigest(input.provider[key], "provider " + key);
  }

  exactObject(
    input.candidate,
    [
      "completedAt",
      "routesStateSha256",
      "syntheticMarkerSha256",
      "e2eEvidenceSha256",
      "d1EvidenceSha256",
      "outboxEvidenceSha256",
      "resendDeliveryEvidenceSha256",
      "accessAuditEvidenceSha256",
      "productionReleaseStateSha256",
      "productionReleaseCandidateReceiptSha256",
    ],
    "production candidate evidence",
  );
  const candidateCompletedAt = exactInstant(
    input.candidate.completedAt,
    "production candidate completedAt",
  );
  if (candidateCompletedAt > releaseCompletedAt || candidateCompletedAt > issuedAt) {
    throw new Error("production candidate evidence has an invalid chronology");
  }
  for (const key of [
    "routesStateSha256",
    "syntheticMarkerSha256",
    "e2eEvidenceSha256",
    "d1EvidenceSha256",
    "outboxEvidenceSha256",
    "resendDeliveryEvidenceSha256",
    "accessAuditEvidenceSha256",
    "productionReleaseStateSha256",
    "productionReleaseCandidateReceiptSha256",
  ]) {
    exactDigest(input.candidate[key], "candidate " + key);
  }
  return Object.freeze({ input });
}

function validateProviderState(value, expected) {
  exactObject(value, ["cloudflare", "resend", "stateSha256"], "provider state");
  exactObject(
    value.cloudflare,
    ["account", "zone", "dns", "d1", "access"],
    "Cloudflare state",
  );
  exactObject(value.cloudflare.account, ["accountId", "stateSha256"], "Cloudflare account");
  exactObject(
    value.cloudflare.zone,
    ["zoneId", "name", "status", "stateSha256"],
    "Cloudflare zone",
  );
  exactObject(
    value.cloudflare.dns,
    ["recordCount", "inventorySha256", "stateSha256"],
    "Cloudflare DNS",
  );
  exactObject(
    value.cloudflare.d1,
    [
      "databaseIdSha256",
      "databaseName",
      "jurisdiction",
      "schemaVersion",
      "schemaSha256",
      "stateSha256",
    ],
    "production D1",
  );
  exactObject(
    value.cloudflare.access,
    [
      "applicationId",
      "applicationDomain",
      "status",
      "adminIdentitySha256",
      "policyDecision",
      "extraPolicyCount",
      "stateSha256",
    ],
    "Cloudflare Access",
  );
  exactObject(
    value.resend,
    [
      "domain",
      "status",
      "sendingEnabled",
      "senderAddress",
      "webhookEndpointSha256",
      "webhookStatus",
      "stateSha256",
    ],
    "Resend state",
  );
  for (const [label, state] of [
    ["Cloudflare account", value.cloudflare.account],
    ["Cloudflare zone", value.cloudflare.zone],
    ["Cloudflare DNS", value.cloudflare.dns],
    ["production D1", value.cloudflare.d1],
    ["Cloudflare Access", value.cloudflare.access],
    ["Resend", value.resend],
    ["provider", value],
  ]) {
    exactSelfDigest(state, label);
  }
  if (
    value.cloudflare.account.accountId !== expected.accountId ||
    value.cloudflare.zone.zoneId !== expected.zoneId ||
    value.cloudflare.zone.name !== expected.zoneName ||
    value.cloudflare.zone.status !== "active" ||
    !Number.isSafeInteger(value.cloudflare.dns.recordCount) ||
    value.cloudflare.dns.recordCount < 1 ||
    value.cloudflare.dns.inventorySha256 !== expected.fullDnsInventorySha256 ||
    value.cloudflare.d1.databaseIdSha256 !== expected.primaryDatabaseIdSha256 ||
    value.cloudflare.d1.databaseName !== expected.primaryDatabaseName ||
    value.cloudflare.d1.jurisdiction !== expected.primaryDatabaseJurisdiction ||
    value.cloudflare.d1.schemaVersion !== expected.primaryDatabaseSchemaVersion ||
    value.cloudflare.d1.schemaSha256 !== expected.primaryDatabaseSchemaSha256 ||
    value.cloudflare.d1.stateSha256 !== expected.primaryDatabaseStateSha256 ||
    value.cloudflare.access.applicationId !== expected.accessApplicationId ||
    value.cloudflare.access.applicationDomain !== expected.accessApplicationDomain ||
    value.cloudflare.access.adminIdentitySha256 !== expected.accessAdminIdentitySha256 ||
    value.cloudflare.access.status !== "active" ||
    value.cloudflare.access.policyDecision !== "allow" ||
    value.cloudflare.access.extraPolicyCount !== 0 ||
    value.cloudflare.access.stateSha256 !== expected.accessStateSha256 ||
    value.resend.domain !== expected.resendDomain ||
    value.resend.status !== "verified" ||
    value.resend.sendingEnabled !== true ||
    value.resend.senderAddress !== expectedResendSender ||
    value.resend.webhookEndpointSha256 !==
      sha256(Buffer.from("https://freshtowels.gr/api/webhooks/resend", "utf8")) ||
    value.resend.webhookStatus !== "enabled" ||
    value.resend.stateSha256 !== expected.resendStateSha256 ||
    value.stateSha256 !== expected.providerStateSha256
  ) {
    throw new Error("production provider state differs from the approved release");
  }
  return value;
}

function validateWorkerState(value, expected) {
  exactObject(
    value,
    [
      "workerName",
      "versionId",
      "percentage",
      "versionStateSha256",
      "deploymentStateSha256",
      "stateSha256",
    ],
    "Worker state",
  );
  exactSelfDigest(value, "Worker state");
  if (
    value.workerName !== expected.name ||
    value.versionId !== expected.versionId ||
    value.percentage !== 100 ||
    value.versionStateSha256 !== expected.versionStateSha256 ||
    value.deploymentStateSha256 !== expected.deploymentStateSha256
  ) {
    throw new Error("deployed Worker differs from the exact approved version");
  }
  return value;
}

function validateRouteState(value, expectedPatterns, worker, expectedStateSha256 = null) {
  exactObject(
    value,
    ["workerName", "patterns", "inventoryStateSha256", "stateSha256"],
    "Worker route state",
  );
  exactSelfDigest(value, "Worker route state");
  exactDigest(value.inventoryStateSha256, "Worker route inventory");
  sortedExact(value.patterns, expectedPatterns, "Worker routes");
  if (
    value.workerName !== worker.name ||
    (expectedStateSha256 !== null &&
      value.inventoryStateSha256 !== expectedStateSha256)
  ) {
    throw new Error("Worker route state differs from the approved candidate");
  }
  return value;
}

function validateAccessAudit(value, input, now) {
  exactObject(
    value,
    [
      "applicationId",
      "applicationDomain",
      "identitySha256",
      "decision",
      "eventType",
      "occurredAt",
      "eventSha256",
      "stateSha256",
    ],
    "Access audit evidence",
  );
  exactSelfDigest(value, "Access audit evidence");
  const occurredAt = exactInstant(value.occurredAt, "Access audit occurredAt");
  const after = exactInstant(input.candidate.completedAt, "candidate completedAt");
  if (
    value.applicationId !== input.provider.accessApplicationId ||
    value.applicationDomain !== input.provider.accessApplicationDomain ||
    value.identitySha256 !== input.provider.accessAdminIdentitySha256 ||
    value.decision !== "allow" ||
    value.eventType !== "login" ||
    occurredAt < after ||
    occurredAt > now.valueOf() + 60_000 ||
    value.eventSha256 !== input.candidate.accessAuditEvidenceSha256
  ) {
    throw new Error("Access audit does not prove the approved owner login");
  }
  return value;
}

function validateCandidateE2e(value, input) {
  exactObject(
    value,
    [
      "schema",
      "receiptType",
      "environment",
      "completedAt",
      "release",
      "worker",
      "routes",
      "accessUnauthorized",
      "leadFlow",
      "resend",
      "lifecycle",
      "receiptSha256",
    ],
    "candidate E2E evidence",
  );
  exactSelfDigest(value, "candidate E2E evidence", "receiptSha256");
  exactObject(
    value.release,
    [
      "applicationCommitSha",
      "artifactSha256",
      "controllerCommitSha",
      "executionClaimSha256",
      "executionRequestId",
      "infrastructureReceiptSha256",
      "productionReleaseStateSha256",
      "releaseBindingSha256",
    ],
    "candidate release evidence",
  );
  exactObject(
    value.worker,
    ["stateSha256", "versionId", "workerNameSha256"],
    "candidate Worker evidence",
  );
  exactObject(
    value.routes,
    [
      "activeStateSha256",
      "candidatePatternsSha256",
      "preCutoverStateSha256",
      "preStateSha256",
      "rollbackVerified",
    ],
    "candidate route evidence",
  );
  exactObject(
    value.accessUnauthorized,
    ["challengeSha256", "responseBodySha256", "status"],
    "candidate Access denial evidence",
  );
  exactObject(
    value.leadFlow,
    [
      "d1StateSha256",
      "deliveryEventIdSha256",
      "deliveryStateSha256",
      "duplicateEffectCount",
      "finalStatusSha256",
      "leadCount",
      "leadIdSha256",
      "outboxIdSha256",
      "outboxStateSha256",
      "providerMessageIdSha256",
      "syntheticMarkerSha256",
      "testRunIdSha256",
    ],
    "candidate lead evidence",
  );
  exactObject(
    value.resend,
    ["deliveryStateSha256", "messageIdSha256", "recipientSha256", "senderSha256"],
    "candidate Resend evidence",
  );
  exactObject(
    value.lifecycle,
    ["finalStateSha256", "transitionSha256s"],
    "candidate lifecycle evidence",
  );
  for (const digestValue of [
    ...Object.values(value.release).filter((item) => typeof item === "string" && item.length === 64),
    value.worker.stateSha256,
    value.worker.workerNameSha256,
    ...Object.values(value.routes).filter((item) => typeof item === "string"),
    value.accessUnauthorized.challengeSha256,
    value.accessUnauthorized.responseBodySha256,
    ...Object.values(value.leadFlow).filter((item) => typeof item === "string"),
    ...Object.values(value.resend),
    value.lifecycle.finalStateSha256,
    ...(Array.isArray(value.lifecycle.transitionSha256s)
      ? value.lifecycle.transitionSha256s
      : []),
  ]) {
    exactDigest(digestValue, "candidate evidence digest");
  }
  const completedAt = exactInstant(value.completedAt, "candidate E2E completedAt");
  if (
    value.schema !== "deployment-control/production-candidate-e2e/v1" ||
    value.receiptType !== "fresh-towels-production-candidate-e2e" ||
    value.environment !== "production-candidate-e2e" ||
    completedAt !== exactInstant(input.candidate.completedAt, "candidate completedAt") ||
    value.release.applicationCommitSha !== input.release.applicationCommitSha ||
    value.release.artifactSha256 !== input.release.uploadArtifactSha256 ||
    value.release.controllerCommitSha !== input.release.controllerCommitSha ||
    value.release.executionRequestId !== input.productionReleasePrerequisite.requestId ||
    value.release.infrastructureReceiptSha256 !==
      input.release.productionInfrastructureReceiptSha256 ||
    value.release.productionReleaseStateSha256 !==
      input.candidate.productionReleaseStateSha256 ||
    value.worker.versionId !== input.worker.versionId ||
    value.worker.workerNameSha256 !==
      sha256(Buffer.from(input.worker.name, "utf8")) ||
    value.routes.candidatePatternsSha256 !== digest(productionCandidateRoutes) ||
    value.routes.preCutoverStateSha256 !== input.candidate.routesStateSha256 ||
    value.routes.rollbackVerified !== true ||
    ![302, 403].includes(value.accessUnauthorized.status) ||
    value.leadFlow.leadCount !== 1 ||
    value.leadFlow.duplicateEffectCount !== 1 ||
    value.leadFlow.finalStatusSha256 !== sha256(Buffer.from("archived", "utf8")) ||
    value.leadFlow.syntheticMarkerSha256 !==
      input.candidate.syntheticMarkerSha256 ||
    value.leadFlow.d1StateSha256 !== input.candidate.d1EvidenceSha256 ||
    value.leadFlow.outboxStateSha256 !== input.candidate.outboxEvidenceSha256 ||
    value.resend.deliveryStateSha256 !==
      input.candidate.resendDeliveryEvidenceSha256 ||
    value.resend.recipientSha256 !== sha256(Buffer.from("info@freshtowels.gr", "utf8")) ||
    value.resend.senderSha256 !==
      sha256(Buffer.from(expectedResendSender, "utf8")) ||
    !Array.isArray(value.lifecycle.transitionSha256s) ||
    value.lifecycle.transitionSha256s.length !== 3 ||
    new Set(value.lifecycle.transitionSha256s).size !== 3 ||
    value.receiptSha256 !== input.candidate.e2eEvidenceSha256
  ) {
    throw new Error("candidate E2E evidence is not exact or complete");
  }
  return value;
}

function validateSmoke(value) {
  exactObject(
    value,
    [
      "origin",
      "wwwOrigin",
      "httpsValid",
      "wwwRedirectStatus",
      "wwwRedirectLocation",
      "robotsStatus",
      "robotsIndexable",
      "sitemapStatus",
      "productionNoindexCount",
      "stagingReferenceCount",
      "criticalRoutes",
      "stateSha256",
    ],
    "production external smoke evidence",
  );
  exactSelfDigest(value, "production external smoke evidence");
  if (!Array.isArray(value.criticalRoutes) || value.criticalRoutes.length !== criticalRoutes.length) {
    throw new Error("production external smoke route set changed");
  }
  for (let index = 0; index < criticalRoutes.length; index += 1) {
    const route = value.criticalRoutes[index];
    exactObject(route, ["path", "status", "canonical"], "production smoke route");
    if (
      route.path !== criticalRoutes[index] ||
      route.status !== 200 ||
      route.canonical !== `https://freshtowels.gr${route.path}`
    ) {
      throw new Error("production external smoke route failed");
    }
  }
  if (
    value.origin !== "https://freshtowels.gr" ||
    value.wwwOrigin !== "https://www.freshtowels.gr" ||
    value.httpsValid !== true ||
    value.wwwRedirectStatus !== 301 ||
    value.wwwRedirectLocation !== "https://freshtowels.gr/" ||
    value.robotsStatus !== 200 ||
    value.robotsIndexable !== true ||
    value.sitemapStatus !== 200 ||
    value.productionNoindexCount !== 0 ||
    value.stagingReferenceCount !== 0
  ) {
    throw new Error("production external smoke failed a material release invariant");
  }
  return value;
}

function cutoverReceipt({
  input,
  provider,
  worker,
  accessAudit,
  e2e,
  fullRoutes,
  smoke,
  protectedExecutionRunId,
  completedAt,
}) {
  const body = {
    schema: "deployment-control/production-cutover-evidence/v1",
    operation: "production-cutover",
    releaseId: input.release.releaseId,
    applicationCommitSha: input.release.applicationCommitSha,
    controllerCommitSha: input.release.controllerCommitSha,
    productionReleaseReceiptSha256:
      input.productionReleasePrerequisite.receiptSha256,
    productionReleaseCandidateReceiptSha256:
      input.candidate.productionReleaseCandidateReceiptSha256,
    protectedExecutionRunId,
    providerStateSha256: provider.stateSha256,
    workerVersionIdSha256: sha256(Buffer.from(worker.versionId, "utf8")),
    workerStateSha256: worker.stateSha256,
    accessAuditStateSha256: accessAudit.stateSha256,
    candidateE2eStateSha256: e2e.receiptSha256,
    fullRoutesStateSha256: fullRoutes.stateSha256,
    externalSmokeStateSha256: smoke.stateSha256,
    rollbackPerformed: false,
    result: "verified",
    completedAt,
  };
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

async function restorePreCutoverRoutes({ adapter, input, previousRoutes, cutoverKey }) {
  try {
    await adapter.setExactRoutes({
      workerName: input.worker.name,
      expectedPreviousPatterns: productionFullRoutes,
      desiredPatterns: productionPreCutoverRoutes,
      idempotencyKey: digest({ cutoverKey, action: "restore-pre-cutover-routes" }),
    });
  } catch {
    // A transport error is not evidence that the mutation failed. Reconcile below.
  }
  const restored = await adapter.inspectRoutes({ workerName: input.worker.name });
  validateRouteState(restored, productionPreCutoverRoutes, input.worker);
  if (restored.stateSha256 !== previousRoutes.stateSha256) {
    throw new Error("production cutover failed and pre-cutover route rollback is ambiguous");
  }
}

export async function executeProductionCutoverAdapter({
  adapter,
  cutoverInput,
  protectedExecutionRunId,
  now = () => new Date(),
}) {
  const methods = [
    "inspectProviderState",
    "inspectWorkerState",
    "inspectRoutes",
    "inspectAccessAudit",
    "inspectCandidateE2e",
    "setExactRoutes",
    "inspectExternalSmoke",
  ];
  if (
    !adapter ||
    methods.some((name) => typeof adapter[name] !== "function") ||
    !decimalPattern.test(protectedExecutionRunId ?? "")
  ) {
    throw new Error("production cutover adapter dependency is unavailable");
  }
  const invocationTime = now();
  const { input } = validateProductionCutoverInput(cutoverInput, {
    now: invocationTime,
  });
  const provider = validateProviderState(
    await adapter.inspectProviderState({ input }),
    input.provider,
  );
  const worker = validateWorkerState(
    await adapter.inspectWorkerState({ workerName: input.worker.name }),
    input.worker,
  );
  const preCutoverRoutes = validateRouteState(
    await adapter.inspectRoutes({ workerName: input.worker.name }),
    productionPreCutoverRoutes,
    input.worker,
    input.candidate.routesStateSha256,
  );
  const accessAudit = validateAccessAudit(
    await adapter.inspectAccessAudit({
      applicationId: input.provider.accessApplicationId,
      applicationDomain: input.provider.accessApplicationDomain,
      adminIdentitySha256: input.provider.accessAdminIdentitySha256,
      after: input.candidate.completedAt,
    }),
    input,
    invocationTime,
  );
  const e2e = validateCandidateE2e(
    await adapter.inspectCandidateE2e({
      markerSha256: input.candidate.syntheticMarkerSha256,
      receiptSha256: input.candidate.e2eEvidenceSha256,
    }),
    input,
  );

  // The provider, exact Worker deployment and candidate routes are reconciled
  // again immediately before the only traffic mutation. An approval is never
  // permission to deploy after remote drift.
  const providerBeforeMutation = validateProviderState(
    await adapter.inspectProviderState({ input }),
    input.provider,
  );
  const workerBeforeMutation = validateWorkerState(
    await adapter.inspectWorkerState({ workerName: input.worker.name }),
    input.worker,
  );
  const routesBeforeMutation = validateRouteState(
    await adapter.inspectRoutes({ workerName: input.worker.name }),
    productionPreCutoverRoutes,
    input.worker,
    input.candidate.routesStateSha256,
  );
  if (
    canonicalJson(providerBeforeMutation) !== canonicalJson(provider) ||
    canonicalJson(workerBeforeMutation) !== canonicalJson(worker) ||
    canonicalJson(routesBeforeMutation) !== canonicalJson(preCutoverRoutes)
  ) {
    throw new Error("production state changed before cutover mutation");
  }

  const cutoverKey = digest({
    operation: input.operation,
    cutoverRequestId: input.cutoverRequestId,
    releaseId: input.release.releaseId,
    productionReleaseReceiptSha256:
      input.productionReleasePrerequisite.receiptSha256,
    workerVersionId: input.worker.versionId,
    preCutoverRoutesStateSha256: input.candidate.routesStateSha256,
  });
  let fullRoutes;
  try {
    try {
      await adapter.setExactRoutes({
        workerName: input.worker.name,
        expectedPreviousPatterns: productionPreCutoverRoutes,
        desiredPatterns: productionFullRoutes,
        idempotencyKey: cutoverKey,
      });
    } catch {
      // Reconcile an ambiguous response instead of blindly retrying it.
    }
    fullRoutes = validateRouteState(
      await adapter.inspectRoutes({ workerName: input.worker.name }),
      productionFullRoutes,
      input.worker,
    );
    const workerAfterMutation = validateWorkerState(
      await adapter.inspectWorkerState({ workerName: input.worker.name }),
      input.worker,
    );
    if (canonicalJson(workerAfterMutation) !== canonicalJson(worker)) {
      throw new Error("Worker deployment changed during route cutover");
    }
    const smoke = validateSmoke(
      await adapter.inspectExternalSmoke({
        origin: "https://freshtowels.gr",
        wwwOrigin: "https://www.freshtowels.gr",
        criticalRoutes,
        releaseId: input.release.releaseId,
      }),
    );
    const providerAfterMutation = validateProviderState(
      await adapter.inspectProviderState({ input }),
      input.provider,
    );
    if (canonicalJson(providerAfterMutation) !== canonicalJson(provider)) {
      throw new Error("production provider state changed during cutover");
    }
    const completedAt = now().toISOString();
    exactInstant(completedAt, "production cutover completedAt");
    return cutoverReceipt({
      input,
      provider,
      worker,
      accessAudit,
      e2e,
      fullRoutes,
      smoke,
      protectedExecutionRunId,
      completedAt,
    });
  } catch (error) {
    try {
      await restorePreCutoverRoutes({
        adapter,
        input,
        previousRoutes: preCutoverRoutes,
        cutoverKey,
      });
    } catch {
      throw new Error("production cutover failed and pre-cutover route rollback is ambiguous");
    }
    throw new Error("production cutover failed and protected pre-cutover routes were restored", {
      cause: error,
    });
  }
}

export const productionCutoverConstants = Object.freeze({
  criticalRoutes,
  expectedAccessDomain,
  expectedApplicationRepository,
  expectedApplicationRepositoryId,
  expectedControllerRepository,
  expectedD1Name,
  expectedResendDomain,
  expectedResendSender,
  expectedWorkerName,
  expectedZoneName,
  productionCandidateRoutes,
  productionPreCutoverRoutes,
  productionFullRoutes,
});
