import { randomBytes } from "node:crypto";
import { canonicalDnsInventory, decodeCloudflareTxtContent } from "./dns-inventory.mjs";

import { canonicalJson, sha256 } from "./control-contract.mjs";
import {
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "./provider-adapter.mjs";
import { verifyConvergedDnsDelegation } from "./dns-delegation-verifier.mjs";
import { verifyWordPressFallback } from "./wordpress-fallback-verifier.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const accountPattern = /^[a-f0-9]{32}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const uuidV4Pattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const safeIdPattern = /^[A-Za-z0-9_-]{1,128}$/;
const safeNamePattern = /^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,199}$/;
const applicationRepository = "zikosbozonis-beep/fresh-towels-website";
const applicationRepositoryId = "1350923567";
const applicationWorkflow = ".github/workflows/release-handoff.yml";
const controllerRepository = "zikosbozonis-beep/fresh-towels-deployment-control";
const controllerWorkflow = ".github/workflows/package-release.yml";
const publicDomain = "freshtowels.gr";
const sendingDomain = "notify.freshtowels.gr";
const resendSendingKeyLeastPrivilegeProbeSha256 = targetDigest({
  expectedProviderErrorCode: "restricted_api_key",
  expectedResult: "management-access-denied",
  expectedStatus: 401,
  method: "GET",
  path: "/api-keys",
  provider: "resend",
  query: { limit: "100" },
  schema: "deployment-control/resend-runtime-least-privilege-probe/v1",
});
const maximumDnsRecords = 32;
const maximumCapsuleBytes = 16 * 1024;
const accessDestinations = Object.freeze([
  Object.freeze({ type: "public", uri: "freshtowels.gr/api/internal/*" }),
  Object.freeze({ type: "public", uri: "freshtowels.gr/internal/leads" }),
  Object.freeze({ type: "public", uri: "freshtowels.gr/internal/leads/*" }),
]);
const cloudflareNameServerPattern =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ns\.cloudflare\.com$/;

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

function canonicalInstant(value, label) {
  if (typeof value !== "string") throw new Error(label + " is invalid");
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(label + " is not canonical UTC");
  }
  return timestamp;
}

function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value) + "\n", "utf8");
}

function targetDigest(value) {
  return sha256(canonicalBytes(value));
}

function safeUrl(value, expectedPath) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Provider target URL is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    url.hostname !== publicDomain ||
    url.pathname !== expectedPath ||
    url.search ||
    url.hash
  ) {
    throw new Error("Provider target URL is outside the production allowlist");
  }
  return value;
}

function bootstrapRequestId(capsule) {
  return targetDigest({
    createdAt: capsule.createdAt,
    application: capsule.application,
    controller: capsule.controller,
    dnsStage: capsule.bootstrap.dnsStage,
    stableEvidence: capsule.bootstrap.stableEvidence,
    targets: capsule.bootstrap.targets,
  });
}

function validateCapsuleIdentity(capsule) {
  exactObject(
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
    "bootstrap application identity",
  );
  exactObject(capsule.controller, ["repository", "commitSha", "workflowRef"], "bootstrap controller identity");
  if (
    capsule.application.repository !== applicationRepository ||
    capsule.application.repositoryId !== applicationRepositoryId ||
    capsule.application.ref !== "refs/heads/main" ||
    !commitPattern.test(capsule.application.commitSha) ||
    capsule.application.workflowRef !==
      applicationRepository + "/" + applicationWorkflow + "@refs/heads/main" ||
    capsule.application.workflowSha !== capsule.application.commitSha ||
    !decimalPattern.test(capsule.application.runId) ||
    !Number.isSafeInteger(capsule.application.runAttempt) ||
    capsule.application.runAttempt < 1 ||
    capsule.application.runAttempt > 100 ||
    capsule.controller.repository !== controllerRepository ||
    !commitPattern.test(capsule.controller.commitSha) ||
    capsule.controller.workflowRef !==
      controllerRepository + "/" + controllerWorkflow + "@" + capsule.controller.commitSha
  ) {
    throw new Error("production bootstrap capsule identity is invalid");
  }
}

function validateD1Target(target, label) {
  exactObject(target, ["id", "name"], label);
  if (
    (target.id !== null && !uuidPattern.test(target.id)) ||
    !["fresh-towels-leads-prod", "fresh-towels-leads-prod-recovery"].includes(target.name)
  ) {
    throw new Error(label + " is invalid");
  }
}

function validateDnsRecord(record, index) {
  exactObject(record, ["id", "type", "name", "content", "ttl", "proxied", "priority"], "DNS target");
  if (
    (record.id !== null && !accountPattern.test(record.id)) ||
    !["A", "AAAA", "CNAME", "MX", "TXT"].includes(record.type) ||
    typeof record.name !== "string" ||
    (record.name !== publicDomain && !record.name.endsWith("." + publicDomain)) ||
    typeof record.content !== "string" ||
    record.content.length < 1 ||
    record.content.length > 4096 ||
    /[\r\n\0]/.test(record.content) ||
    (!Number.isSafeInteger(record.ttl) || (record.ttl !== 1 && (record.ttl < 60 || record.ttl > 86400))) ||
    typeof record.proxied !== "boolean" ||
    (record.proxied && record.ttl !== 1) ||
    (record.priority !== null &&
      (!Number.isSafeInteger(record.priority) || record.priority < 0 || record.priority > 65535)) ||
    (record.type === "MX" && record.priority === null) ||
    (record.type !== "MX" && record.priority !== null) ||
    (["MX", "TXT"].includes(record.type) && record.proxied)
  ) {
    throw new Error("DNS target " + (index + 1) + " is invalid");
  }
}

function validateProductionBootstrapTargets({ targets, safeguards, adminIdentity }) {
  exactObject(targets, ["cloudflare", "resend"], "production bootstrap targets");
  if (
    typeof adminIdentity !== "string" ||
    adminIdentity.length > 254 ||
    !/^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/.test(adminIdentity) ||
    adminIdentity !== adminIdentity.toLowerCase()
  ) {
    throw new Error("Access administrator identity is invalid");
  }
  exactObject(
    targets.cloudflare,
    ["accountId", "zone", "workerName", "workersDevSubdomain", "d1", "access"],
    "Cloudflare targets",
  );
  if (
    !accountPattern.test(targets.cloudflare.accountId) ||
    targets.cloudflare.workerName !== "fresh-towels-production" ||
    (targets.cloudflare.workersDevSubdomain !== null &&
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
        targets.cloudflare.workersDevSubdomain,
      ))
  ) {
    throw new Error("Cloudflare account/Worker target is invalid");
  }
  exactObject(targets.cloudflare.zone, ["id", "name", "type"], "Cloudflare zone target");
  if (
    (targets.cloudflare.zone.id !== null && !accountPattern.test(targets.cloudflare.zone.id)) ||
    targets.cloudflare.zone.name !== publicDomain ||
    targets.cloudflare.zone.type !== "full"
  ) {
    throw new Error("Cloudflare zone target is invalid");
  }
  exactObject(targets.cloudflare.d1, ["jurisdiction", "primary", "recovery"], "D1 targets");
  if (targets.cloudflare.d1.jurisdiction !== "eu") throw new Error("D1 jurisdiction must be eu");
  validateD1Target(targets.cloudflare.d1.primary, "primary D1 target");
  validateD1Target(targets.cloudflare.d1.recovery, "recovery D1 target");
  if (
    targets.cloudflare.d1.primary.name !== "fresh-towels-leads-prod" ||
    targets.cloudflare.d1.recovery.name !== "fresh-towels-leads-prod-recovery" ||
    (targets.cloudflare.d1.primary.id &&
      targets.cloudflare.d1.primary.id === targets.cloudflare.d1.recovery.id)
  ) {
    throw new Error("D1 primary/recovery isolation is invalid");
  }

  exactObject(
    targets.cloudflare.access,
    ["organization", "identityProvider", "application", "policy"],
    "Access targets",
  );
  exactObject(
    targets.cloudflare.access.organization,
    ["name", "teamDomain", "sessionDuration"],
    "Access organization target",
  );
  const requestedTeamDomain = targets.cloudflare.access.organization.teamDomain;
  let requestedTeamUrl = null;
  if (requestedTeamDomain !== null) {
    try {
      requestedTeamUrl = new URL(requestedTeamDomain);
    } catch {
      requestedTeamUrl = null;
    }
  }
  if (
    !safeNamePattern.test(targets.cloudflare.access.organization.name) ||
    (requestedTeamDomain !== null &&
      (!requestedTeamUrl ||
        requestedTeamUrl.protocol !== "https:" ||
        requestedTeamUrl.pathname !== "/" ||
        requestedTeamUrl.search ||
        requestedTeamUrl.hash ||
        requestedTeamUrl.username ||
        requestedTeamUrl.password ||
        requestedTeamUrl.port ||
        !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(requestedTeamUrl.hostname))) ||
    targets.cloudflare.access.organization.sessionDuration !== "8h"
  ) {
    throw new Error("Access organization target is invalid");
  }
  exactObject(
    targets.cloudflare.access.identityProvider,
    ["id", "name", "type"],
    "Access identity-provider target",
  );
  const identityProvider = targets.cloudflare.access.identityProvider;
  if (
    (identityProvider.id !== null && !uuidPattern.test(identityProvider.id)) ||
    identityProvider.name !== "Fresh Towels owner OTP" ||
    identityProvider.type !== "onetimepin"
  ) {
    throw new Error("Access identity-provider target is invalid");
  }
  exactObject(
    targets.cloudflare.access.application,
    [
      "allowAuthenticateViaWarp",
      "allowIframe",
      "appLauncherVisible",
      "autoRedirectToIdentity",
      "destinations",
      "domain",
      "enableBindingCookie",
      "httpOnlyCookieAttribute",
      "id",
      "name",
      "optionsPreflightBypass",
      "pathCookieAttribute",
      "sameSiteCookieAttribute",
      "sessionDuration",
      "skipInterstitial",
      "type",
    ],
    "Access application target",
  );
  const application = targets.cloudflare.access.application;
  if (!Array.isArray(application.destinations)) {
    throw new Error("Access application destination target is invalid");
  }
  application.destinations.forEach((destination) =>
    exactObject(destination, ["type", "uri"], "Access application destination target"),
  );
  if (
    (application.id !== null && !uuidPattern.test(application.id)) ||
    !safeNamePattern.test(application.name) ||
    application.domain !== "freshtowels.gr/internal/leads" ||
    canonicalJson(application.destinations) !== canonicalJson(accessDestinations) ||
    application.type !== "self_hosted" ||
    application.sessionDuration !== "8h" ||
    application.httpOnlyCookieAttribute !== true ||
    application.sameSiteCookieAttribute !== "strict" ||
    application.enableBindingCookie !== true ||
    application.pathCookieAttribute !== false ||
    application.allowIframe !== false ||
    application.allowAuthenticateViaWarp !== false ||
    application.skipInterstitial !== false ||
    application.optionsPreflightBypass !== false ||
    application.appLauncherVisible !== false ||
    application.autoRedirectToIdentity !== true
  ) {
    throw new Error("Access application target is invalid");
  }
  exactObject(
    targets.cloudflare.access.policy,
    ["id", "name", "decision", "precedence", "adminIdentitySha256"],
    "Access policy target",
  );
  const policy = targets.cloudflare.access.policy;
  if (
    (policy.id !== null && !uuidPattern.test(policy.id)) ||
    !safeNamePattern.test(policy.name) ||
    policy.decision !== "allow" ||
    policy.precedence !== 1 ||
    policy.adminIdentitySha256 !== sha256(Buffer.from(adminIdentity, "utf8"))
  ) {
    throw new Error("Access policy target is invalid");
  }
  exactObject(targets.resend, ["domain", "senderAddress", "webhook", "sendingKey"], "Resend targets");
  exactObject(targets.resend.domain, ["id", "name", "region"], "Resend domain target");
  if (
    !safeIdPattern.test(targets.resend.domain.id ?? "") ||
    targets.resend.domain.name !== sendingDomain ||
    targets.resend.domain.region !== "eu-west-1" ||
    targets.resend.senderAddress !== "notifications@" + targets.resend.domain.name
  ) {
    throw new Error("Resend sending-domain target is invalid");
  }
  exactObject(
    targets.resend.webhook,
    ["id", "endpoint", "events", "secretBinding"],
    "Resend webhook target",
  );
  if (
    (targets.resend.webhook.id !== null && !safeIdPattern.test(targets.resend.webhook.id)) ||
    safeUrl(targets.resend.webhook.endpoint, "/api/webhooks/resend") !==
      "https://freshtowels.gr/api/webhooks/resend" ||
    JSON.stringify(targets.resend.webhook.events) !==
      JSON.stringify([
        "email.sent",
        "email.delivered",
        "email.bounced",
        "email.complained",
        "email.delivery_delayed",
        "email.failed",
        "email.suppressed",
      ]) ||
    targets.resend.webhook.secretBinding !== "RESEND_WEBHOOK_SECRET"
  ) {
    throw new Error("Resend webhook target is invalid");
  }
  exactObject(
    targets.resend.sendingKey,
    ["id", "name", "permission", "secretBinding"],
    "Resend sending-key target",
  );
  if (
    (targets.resend.sendingKey.id !== null && !safeIdPattern.test(targets.resend.sendingKey.id)) ||
    targets.resend.sendingKey.name !== "Fresh Towels Production Worker" ||
    targets.resend.sendingKey.permission !== "sending_access" ||
    targets.resend.sendingKey.secretBinding !== "RESEND_API_KEY"
  ) {
    throw new Error("Resend sending-key target is invalid");
  }
  return Object.freeze({ targets, adminIdentity });
}

export function validateProductionBootstrapCapsule({
  capsule,
  capsuleBytes,
  expectedCapsuleSha256,
  adminIdentity,
  now = new Date(),
}) {
  exactObject(
    capsule,
    [
      "application",
      "bootstrap",
      "capsuleType",
      "controller",
      "createdAt",
      "operation",
      "schemaVersion",
      "validUntil",
    ],
    "production bootstrap capsule",
  );
  if (
    capsule.schemaVersion !== 1 ||
    capsule.capsuleType !== "fresh-towels-production-bootstrap-capsule" ||
    capsule.operation !== "production-bootstrap" ||
    !Buffer.isBuffer(capsuleBytes) ||
    capsuleBytes.byteLength < 1 ||
    capsuleBytes.byteLength > maximumCapsuleBytes ||
    !digestPattern.test(expectedCapsuleSha256 ?? "") ||
    sha256(capsuleBytes) !== expectedCapsuleSha256 ||
    !capsuleBytes.equals(canonicalBytes(capsule))
  ) {
    throw new Error("production bootstrap capsule byte binding is invalid");
  }
  validateCapsuleIdentity(capsule);
  const createdAt = canonicalInstant(capsule.createdAt, "bootstrap capsule createdAt");
  const validUntil = canonicalInstant(capsule.validUntil, "bootstrap capsule validUntil");
  if (
    validUntil - createdAt !== 2 * 60 * 60 * 1000 ||
    now.valueOf() < createdAt - 60_000 ||
    now.valueOf() >= validUntil
  ) {
    throw new Error("production bootstrap capsule is stale");
  }
  exactObject(
    capsule.bootstrap,
    ["requestId", "intent", "dnsStage", "stableEvidence", "targets", "safeguards"],
    "production bootstrap declaration",
  );
  if (
    capsule.bootstrap.intent !==
      "provision-production-identities-and-issue-credential-free-receipt" ||
    !digestPattern.test(capsule.bootstrap.requestId) ||
    capsule.bootstrap.requestId !== bootstrapRequestId(capsule)
  ) {
    throw new Error("production bootstrap request identity is invalid");
  }
  exactObject(
    capsule.bootstrap.dnsStage,
    ["requestId", "receiptSha256", "runId"],
    "production DNS-stage prerequisite",
  );
  if (
    !uuidV4Pattern.test(capsule.bootstrap.dnsStage.requestId) ||
    !digestPattern.test(capsule.bootstrap.dnsStage.receiptSha256) ||
    !decimalPattern.test(capsule.bootstrap.dnsStage.runId)
  ) {
    throw new Error("production DNS-stage prerequisite is invalid");
  }
  exactObject(
    capsule.bootstrap.stableEvidence,
    [
      "redirectCandidateEvidenceSha256",
      "privacyOperationsEvidenceSha256",
      "legacyWordPressRecoveryEvidenceSha256",
    ],
    "stable evidence prerequisite",
  );
  if (
    Object.values(capsule.bootstrap.stableEvidence).some(
      (value) => !digestPattern.test(value),
    )
  ) {
    throw new Error("stable evidence prerequisite is invalid");
  }
  exactObject(
    capsule.bootstrap.safeguards,
    [
      "credentialsPresent",
      "applicationBuildAuthorized",
      "applicationArtifactPresent",
      "productionTrafficMutationAuthorized",
      "productionDnsMutationAuthorized",
      "providerBootstrapMutationAuthorized",
    ],
    "production bootstrap safeguards",
  );
  const safeguards = capsule.bootstrap.safeguards;
  if (
    safeguards.credentialsPresent !== false ||
    safeguards.applicationBuildAuthorized !== false ||
    safeguards.applicationArtifactPresent !== false ||
    safeguards.productionTrafficMutationAuthorized !== false ||
    safeguards.productionDnsMutationAuthorized !== false ||
    safeguards.providerBootstrapMutationAuthorized !== true
  ) {
    throw new Error("production bootstrap safeguards are unsafe");
  }
  validateProductionBootstrapTargets({
    targets: capsule.bootstrap.targets,
    safeguards,
    adminIdentity,
  });
  return Object.freeze({
    capsule,
    capsuleSha256: expectedCapsuleSha256,
    requestId: capsule.bootstrap.requestId,
    application: capsule.application,
    controller: capsule.controller,
    dnsStage: capsule.bootstrap.dnsStage,
    stableEvidence: capsule.bootstrap.stableEvidence,
    targets: capsule.bootstrap.targets,
    adminIdentity,
  });
}

function requestInput({ method, path, query = null, body, idempotencyKey }) {
  const bytes = body === undefined ? undefined : canonicalBytes(body);
  return {
    method,
    path,
    query,
    body,
    bodyBytes: undefined,
    bodySha256: bytes ? sha256(bytes) : undefined,
    contentType: undefined,
    idempotencyKey: idempotencyKey ?? null,
  };
}

async function request(client, input) {
  if (!client || typeof client.request !== "function") {
    throw new Error("Production provider client is unavailable");
  }
  return client.request(requestInput(input));
}

function completeList(response, label) {
  exactObject(response.pagination, ["complete"], label + " pagination");
  if (response.pagination.complete !== true) {
    throw new ProductionBootstrapAmbiguousError(label + " pagination is incomplete");
  }
  const value = response.result;
  const items = Array.isArray(value) ? value : value?.data;
  if (!Array.isArray(items)) throw new Error(label + " list response is malformed");
  return items;
}

function one(items, predicate, label) {
  const matches = items.filter(predicate);
  if (matches.length > 1) throw new ProductionBootstrapAmbiguousError(label + " is duplicated");
  return matches[0] ?? null;
}

function state(value) {
  return Object.freeze({ value, sha256: targetDigest(value) });
}

function exactId(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(label + " identifier is malformed");
  }
  return value;
}

export class ProductionBootstrapAmbiguousError extends Error {
  constructor(stage) {
    super("Production provider bootstrap is ambiguous at " + stage);
    this.name = "ProductionBootstrapAmbiguousError";
    this.stage = stage;
  }
}

async function reconcile({ stage, inspect, mutate, desired }) {
  let before;
  try {
    before = await inspect();
  } catch (error) {
    if (error instanceof ProviderRejectedError) throw error;
    throw new ProductionBootstrapAmbiguousError(stage + ":inspect");
  }
  if (desired(before)) return Object.freeze({ result: "unchanged", resource: before, state: state(before) });
  let mutationResult;
  try {
    mutationResult = await mutate(before);
  } catch (error) {
    if (error instanceof ProviderRejectedError && ![408, 409, 425, 429].includes(error.status)) {
      throw error;
    }
  }
  let after;
  try {
    after = await inspect();
  } catch {
    throw new ProductionBootstrapAmbiguousError(stage + ":post-inspect");
  }
  if (!desired(after)) throw new ProductionBootstrapAmbiguousError(stage + ":not-converged");
  return Object.freeze({
    result: mutationResult?.result ?? "verified-after-ambiguous",
    resource: after,
    state: state(after),
  });
}

function idem(release, targetsSha256, stage) {
  return sha256(
    Buffer.from(
      [
        release.brokerRequestId,
        release.capsuleRequestSha256,
        release.application.commitSha,
        release.application.runId,
        String(release.application.runAttempt),
        release.controller.commitSha,
        targetsSha256,
        stage,
      ].join("\0"),
      "utf8",
    ),
  );
}

export async function verifyProductionCloudflareAccount(client, targets) {
  const id = targets.cloudflare.accountId;
  const response = await request(client, { method: "GET", path: "/accounts/" + id });
  if (response.result?.id !== id) throw new Error("Cloudflare account identity differs");
  return state({ verified: true, accountIdentitySha256: sha256(Buffer.from(id)) });
}

async function verifyWorkersDevSubdomain(client, targets) {
  const response = await request(client, {
    method: "GET",
    path: "/accounts/" + targets.cloudflare.accountId + "/workers/subdomain",
  });
  const subdomain = response.result?.subdomain;
  if (
    typeof subdomain !== "string" ||
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(subdomain) ||
    (targets.cloudflare.workersDevSubdomain !== null &&
      subdomain !== targets.cloudflare.workersDevSubdomain)
  ) {
    throw new Error("Cloudflare Workers account subdomain is unavailable");
  }
  return state({
    subdomain,
    identitySha256: sha256(Buffer.from(subdomain, "utf8")),
  });
}

function canonicalZoneNameServers(value) {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    value.some(
      (name) => typeof name !== "string" || !cloudflareNameServerPattern.test(name),
    ) ||
    new Set(value).size !== 2
  ) {
    throw new Error("Cloudflare zone nameserver identity is invalid");
  }
  return [...value].sort();
}

function normalizedZone(value, accountId) {
  if (!value) return null;
  if (value.account?.id !== accountId) {
    throw new Error("Cloudflare zone account identity differs");
  }
  return {
    id: exactId(value.id, accountPattern, "Cloudflare zone"),
    name: value.name,
    accountId: value.account.id,
    type: value.type,
    status: value.status,
    nameServers: canonicalZoneNameServers(value.name_servers),
  };
}

export async function inspectProductionZone(client, cloudflare) {
  let zoneId = cloudflare.zone.id;
  if (!zoneId) {
    const response = await request(client, {
      method: "GET",
      path: "/zones",
      query: {
        "account.id": cloudflare.accountId,
        name: cloudflare.zone.name,
        match: "all",
        page: "1",
        per_page: "50",
      },
    });
    const found = one(
      completeList(response, "Cloudflare zones"),
      (zone) => zone?.name === cloudflare.zone.name && zone?.account?.id === cloudflare.accountId,
      "Cloudflare zone",
    );
    if (!found) return null;
    zoneId = exactId(found.id, accountPattern, "Cloudflare zone");
  }
  try {
    const response = await request(client, { method: "GET", path: "/zones/" + zoneId });
    return normalizedZone(response.result, cloudflare.accountId);
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) return null;
    throw error;
  }
}

export async function ensureProductionZone(client, targets, release, targetsSha256) {
  const desiredTarget = targets.cloudflare.zone;
  return reconcile({
    stage: "cloudflare-zone",
    inspect: () => inspectProductionZone(client, targets.cloudflare),
    desired: (found) =>
      found !== null &&
      found.name === desiredTarget.name &&
      found.accountId === targets.cloudflare.accountId &&
      found.type === desiredTarget.type &&
      (!desiredTarget.id || found.id === desiredTarget.id) &&
      ["pending", "active"].includes(found.status),
    mutate: async (found) => {
      if (found) throw new Error("Existing Cloudflare zone drift cannot be overwritten");
      if (desiredTarget.id) {
        throw new Error("Reviewed Cloudflare zone ID is absent");
      }
      await request(client, {
        method: "POST",
        path: "/zones",
        body: {
          account: { id: targets.cloudflare.accountId },
          name: desiredTarget.name,
          type: desiredTarget.type,
        },
        idempotencyKey: idem(release, targetsSha256, "cloudflare-zone"),
      });
      return { result: "created" };
    },
  });
}

async function inspectD1(client, accountId, target) {
  if (target.id) {
    const response = await request(client, {
      method: "GET",
      path: "/accounts/" + accountId + "/d1/database/" + target.id,
    });
    const item = response.result;
    return item
      ? {
          id: exactId(item.uuid, uuidPattern, "D1 database"),
          name: item.name,
          jurisdiction: item.jurisdiction,
        }
      : null;
  }
  const response = await request(client, {
    method: "GET",
    path: "/accounts/" + accountId + "/d1/database",
    query: { name: target.name, page: "1", per_page: "10000" },
  });
  const item = one(
    completeList(response, "D1 databases"),
    (database) => database?.name === target.name,
    "D1 database",
  );
  return item
    ? {
        id: exactId(item.uuid, uuidPattern, "D1 database"),
        name: item.name,
        jurisdiction: item.jurisdiction,
      }
    : null;
}

async function ensureD1(client, targets, target, purpose, release, targetsSha256) {
  const accountId = targets.cloudflare.accountId;
  return reconcile({
    stage: "cloudflare-d1-" + purpose,
    inspect: () => inspectD1(client, accountId, target),
    desired: (found) =>
      found !== null &&
      found.name === target.name &&
      found.jurisdiction === "eu" &&
      (!target.id || found.id === target.id),
    mutate: async (found) => {
      if (found) throw new Error("Existing D1 jurisdiction/name drift cannot be overwritten");
      await request(client, {
        method: "POST",
        path: "/accounts/" + accountId + "/d1/database",
        body: { name: target.name, jurisdiction: "eu" },
        idempotencyKey: idem(release, targetsSha256, "cloudflare-d1-" + purpose),
      });
      return { result: "created" };
    },
  });
}

function teamHost(teamDomain) {
  return new URL(teamDomain).hostname;
}

async function inspectAccessOrganization(client, targets) {
  try {
    const response = await request(client, {
      method: "GET",
      path: "/accounts/" + targets.cloudflare.accountId + "/access/organizations",
    });
    const organization = response.result;
    return organization
      ? {
          teamDomain: "https://" + organization.auth_domain,
          name: organization.name,
          sessionDuration: organization.session_duration,
        }
      : null;
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) return null;
    throw error;
  }
}

async function ensureAccessOrganization(client, targets, release, targetsSha256) {
  const desiredTarget = targets.cloudflare.access.organization;
  const found = await inspectAccessOrganization(client, targets);
  const exact = (organization) =>
    organization !== null &&
    /^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(organization.teamDomain) &&
    (desiredTarget.teamDomain === null ||
      organization.teamDomain === desiredTarget.teamDomain) &&
    organization.name === desiredTarget.name &&
    organization.sessionDuration === desiredTarget.sessionDuration;
  if (found !== null) {
    if (!exact(found)) {
      throw new ProductionBootstrapAmbiguousError(
        "cloudflare-access-organization-existing-drift",
      );
    }
    return Object.freeze({ result: "unchanged", resource: found, state: state(found) });
  }
  if (desiredTarget.teamDomain === null) {
    throw new ProductionBootstrapAmbiguousError(
      "cloudflare-access-organization-exact-team-domain-required",
    );
  }
  return reconcile({
    stage: "cloudflare-access-organization",
    inspect: () => inspectAccessOrganization(client, targets),
    desired: exact,
    mutate: async (current) => {
      if (!current) {
        await request(client, {
          method: "POST",
          path: "/accounts/" + targets.cloudflare.accountId + "/access/organizations",
          body: {
            auth_domain: teamHost(desiredTarget.teamDomain),
            name: desiredTarget.name,
            session_duration: desiredTarget.sessionDuration,
          },
          idempotencyKey: idem(release, targetsSha256, "cloudflare-access-organization"),
        });
        return { result: "created" };
      }
      throw new ProductionBootstrapAmbiguousError(
        "cloudflare-access-organization-existing-drift",
      );
    },
  });
}

function normalizedAccessIdentityProvider(value) {
  return value
    ? {
        id: exactId(value.id, uuidPattern, "Access identity provider"),
        name: value.name,
        type: value.type,
      }
    : null;
}

async function inspectAccessIdentityProvider(client, targets) {
  const desiredTarget = targets.cloudflare.access.identityProvider;
  if (desiredTarget.id) {
    try {
      const response = await request(client, {
        method: "GET",
        path:
          "/accounts/" +
          targets.cloudflare.accountId +
          "/access/identity_providers/" +
          desiredTarget.id,
      });
      return normalizedAccessIdentityProvider(response.result);
    } catch (error) {
      if (error instanceof ProviderRejectedError && error.status === 404) return null;
      throw error;
    }
  }
  const response = await request(client, {
    method: "GET",
    path:
      "/accounts/" + targets.cloudflare.accountId + "/access/identity_providers",
    query: { page: "1", per_page: "1000" },
  });
  return normalizedAccessIdentityProvider(
    one(
      completeList(response, "Access identity providers"),
      (item) => item?.name === desiredTarget.name,
      "Access identity provider",
    ),
  );
}

async function ensureAccessIdentityProvider(client, targets, release, targetsSha256) {
  const desiredTarget = targets.cloudflare.access.identityProvider;
  return reconcile({
    stage: "cloudflare-access-identity-provider",
    inspect: () => inspectAccessIdentityProvider(client, targets),
    desired: (found) =>
      found !== null &&
      found.name === desiredTarget.name &&
      found.type === desiredTarget.type &&
      (!desiredTarget.id || found.id === desiredTarget.id),
    mutate: async (found) => {
      if (found || desiredTarget.id) {
        throw new Error("Existing Access identity-provider drift cannot be overwritten");
      }
      await request(client, {
        method: "POST",
        path:
          "/accounts/" + targets.cloudflare.accountId + "/access/identity_providers",
        body: { config: {}, name: desiredTarget.name, type: desiredTarget.type },
        idempotencyKey: idem(
          release,
          targetsSha256,
          "cloudflare-access-identity-provider",
        ),
      });
      return { result: "created" };
    },
  });
}

function normalizedAccessDestinations(value) {
  if (!Array.isArray(value) || value.length !== accessDestinations.length) return null;
  const destinations = value.map((destination) => {
    exactObject(destination, ["type", "uri"], "Access application destination");
    return { type: destination.type, uri: destination.uri };
  });
  destinations.sort((left, right) => left.uri.localeCompare(right.uri));
  return new Set(destinations.map((destination) => destination.uri)).size === destinations.length
    ? destinations
    : null;
}

function normalizedAccessApplication(application) {
  if (!application) return null;
  return {
    id: exactId(application.id, uuidPattern, "Access application"),
    aud: exactId(application.aud, /^[A-Za-z0-9_-]{16,200}$/, "Access audience"),
    name: application.name,
    domain: application.domain,
    destinations: normalizedAccessDestinations(application.destinations),
    type: application.type,
    sessionDuration: application.session_duration,
    httpOnlyCookieAttribute: application.http_only_cookie_attribute,
    sameSiteCookieAttribute: application.same_site_cookie_attribute,
    enableBindingCookie: application.enable_binding_cookie,
    pathCookieAttribute: application.path_cookie_attribute,
    allowIframe: application.allow_iframe,
    allowAuthenticateViaWarp: application.allow_authenticate_via_warp,
    skipInterstitial: application.skip_interstitial,
    appLauncherVisible: application.app_launcher_visible,
    optionsPreflightBypass: application.options_preflight_bypass,
    autoRedirectToIdentity: application.auto_redirect_to_identity,
    allowedIdps: Array.isArray(application.allowed_idps)
      ? [...application.allowed_idps]
      : null,
  };
}

async function inspectAccessApplication(client, targets, identityProviderId) {
  const desiredTarget = targets.cloudflare.access.application;
  let applicationId = desiredTarget.id;
  if (!applicationId) {
    const response = await request(client, {
      method: "GET",
      path: "/accounts/" + targets.cloudflare.accountId + "/access/apps",
      query: {
        name: desiredTarget.name,
        domain: desiredTarget.domain,
        exact: "true",
        page: "1",
        per_page: "1000",
      },
    });
    const application = one(
      completeList(response, "Access applications"),
      (item) => item?.name === desiredTarget.name && item?.domain === desiredTarget.domain,
      "Access application",
    );
    if (!application) return null;
    applicationId = exactId(application.id, uuidPattern, "Access application");
  }
  try {
    const response = await request(client, {
      method: "GET",
      path:
        "/accounts/" +
        targets.cloudflare.accountId +
        "/access/apps/" +
        applicationId,
    });
    return normalizedAccessApplication(response.result);
  } catch (error) {
    if (error instanceof ProviderRejectedError && error.status === 404) return null;
    throw error;
  }
}

async function ensureAccessApplication(
  client,
  targets,
  identityProviderId,
  release,
  targetsSha256,
) {
  const desiredTarget = targets.cloudflare.access.application;
  const body = {
    name: desiredTarget.name,
    domain: desiredTarget.domain,
    destinations: desiredTarget.destinations,
    type: desiredTarget.type,
    session_duration: desiredTarget.sessionDuration,
    http_only_cookie_attribute: desiredTarget.httpOnlyCookieAttribute,
    same_site_cookie_attribute: desiredTarget.sameSiteCookieAttribute,
    enable_binding_cookie: desiredTarget.enableBindingCookie,
    path_cookie_attribute: desiredTarget.pathCookieAttribute,
    allow_iframe: desiredTarget.allowIframe,
    allow_authenticate_via_warp: desiredTarget.allowAuthenticateViaWarp,
    skip_interstitial: desiredTarget.skipInterstitial,
    app_launcher_visible: desiredTarget.appLauncherVisible,
    options_preflight_bypass: desiredTarget.optionsPreflightBypass,
    allowed_idps: [identityProviderId],
    auto_redirect_to_identity: desiredTarget.autoRedirectToIdentity,
  };
  return reconcile({
    stage: "cloudflare-access-application",
    inspect: () => inspectAccessApplication(client, targets, identityProviderId),
    desired: (found) =>
      found !== null &&
      found.name === body.name &&
      found.domain === body.domain &&
      canonicalJson(found.destinations) === canonicalJson(body.destinations) &&
      found.type === body.type &&
      found.sessionDuration === body.session_duration &&
      found.httpOnlyCookieAttribute === body.http_only_cookie_attribute &&
      found.sameSiteCookieAttribute === body.same_site_cookie_attribute &&
      found.enableBindingCookie === body.enable_binding_cookie &&
      found.pathCookieAttribute === body.path_cookie_attribute &&
      found.allowIframe === body.allow_iframe &&
      found.allowAuthenticateViaWarp === body.allow_authenticate_via_warp &&
      found.skipInterstitial === body.skip_interstitial &&
      found.appLauncherVisible === body.app_launcher_visible &&
      found.optionsPreflightBypass === body.options_preflight_bypass &&
      found.autoRedirectToIdentity === body.auto_redirect_to_identity &&
      Array.isArray(found.allowedIdps) &&
      found.allowedIdps.length === 1 &&
      found.allowedIdps[0] === identityProviderId,
    mutate: async (found) => {
      if (!found && desiredTarget.id) {
        throw new Error("Reviewed Access application ID is absent");
      }
      const path =
        "/accounts/" +
        targets.cloudflare.accountId +
        "/access/apps" +
        (found ? "/" + found.id : "");
      await request(client, {
        method: found ? "PUT" : "POST",
        path,
        body,
        idempotencyKey: idem(release, targetsSha256, "cloudflare-access-application"),
      });
      return { result: found ? "updated" : "created" };
    },
  });
}

function normalizedPolicy(policy) {
  const include = Array.isArray(policy?.include) ? policy.include : [];
  const exclude = Array.isArray(policy?.exclude) ? policy.exclude : [];
  const requireRules = Array.isArray(policy?.require) ? policy.require : [];
  const emailRule = include.length === 1 ? include[0] : null;
  const exactEmailRule =
    emailRule !== null &&
    typeof emailRule === "object" &&
    !Array.isArray(emailRule) &&
    Object.keys(emailRule).length === 1 &&
    typeof emailRule.email === "object" &&
    emailRule.email !== null &&
    !Array.isArray(emailRule.email) &&
    Object.keys(emailRule.email).length === 1 &&
    typeof emailRule.email.email === "string";
  return policy
    ? {
        id: exactId(policy.id, uuidPattern, "Access policy"),
        name: policy.name,
        decision: policy.decision,
        precedence: policy.precedence,
        emailIdentitySha256: exactEmailRule
          ? sha256(Buffer.from(emailRule.email.email, "utf8"))
          : sha256(Buffer.from("invalid")),
        exactEmailRule,
        excludeRuleCount: exclude.length,
        requireRuleCount: requireRules.length,
      }
    : null;
}

async function inspectAccessPolicy(client, targets, applicationId) {
  const response = await request(client, {
    method: "GET",
    path:
      "/accounts/" +
      targets.cloudflare.accountId +
      "/access/apps/" +
      applicationId +
      "/policies",
    query: { page: "1", per_page: "1000" },
  });
  const desiredTarget = targets.cloudflare.access.policy;
  const policies = completeList(response, "Access policies");
  const selected = one(
    policies,
    (item) =>
      (desiredTarget.id && item?.id === desiredTarget.id) ||
      (!desiredTarget.id && item?.name === desiredTarget.name),
    "Access policy",
  );
  const unexpectedPolicies = policies.filter((item) => item !== selected);
  if (unexpectedPolicies.length > 0) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-access-unexpected-policy");
  }
  const normalized = normalizedPolicy(selected);
  return normalized ? { ...normalized, extraPolicyCount: unexpectedPolicies.length } : null;
}

async function ensureAccessPolicy(client, targets, applicationId, adminIdentity, release, targetsSha256) {
  const desiredTarget = targets.cloudflare.access.policy;
  const body = {
    name: desiredTarget.name,
    decision: desiredTarget.decision,
    precedence: desiredTarget.precedence,
    include: [{ email: { email: adminIdentity } }],
    exclude: [],
    require: [],
  };
  return reconcile({
    stage: "cloudflare-access-policy",
    inspect: () => inspectAccessPolicy(client, targets, applicationId),
    desired: (found) =>
      found !== null &&
      found.name === body.name &&
      found.decision === body.decision &&
      found.precedence === body.precedence &&
      found.emailIdentitySha256 === desiredTarget.adminIdentitySha256 &&
      found.exactEmailRule === true &&
      found.excludeRuleCount === 0 &&
      found.requireRuleCount === 0,
    mutate: async (found) => {
      const base =
        "/accounts/" +
        targets.cloudflare.accountId +
        "/access/apps/" +
        applicationId +
        "/policies";
      await request(client, {
        method: found ? "PUT" : "POST",
        path: base + (found ? "/" + found.id : ""),
        body,
        idempotencyKey: idem(release, targetsSha256, "cloudflare-access-policy"),
      });
      return { result: found ? "updated" : "created" };
    },
  });
}

function normalizedDns(record) {
  return record
    ? {
        id: exactId(record.id, accountPattern, "DNS record"),
        type: record.type,
        name: record.name,
        content: record.type === "TXT" ? decodeCloudflareTxtContent(record.content) : record.content,
        ttl: record.ttl,
        proxied: record.proxied,
        priority: record.priority ?? null,
      }
    : null;
}

async function inspectDnsRecord(client, targets, target) {
  if (target.id) {
    try {
      const response = await request(client, {
        method: "GET",
        path:
          "/zones/" +
          targets.cloudflare.zone.id +
          "/dns_records/" +
          target.id,
      });
      return normalizedDns(response.result);
    } catch (error) {
      if (error instanceof ProviderRejectedError && error.status === 404) return null;
      throw error;
    }
  }
  const response = await request(client, {
    method: "GET",
    path: "/zones/" + targets.cloudflare.zone.id + "/dns_records",
    query: {
      type: target.type,
      "name.exact": target.name,
      ...(target.type === "TXT" ? {} : { "content.exact": target.content }),
      match: "all",
      page: "1",
      per_page: "100",
    },
  });
  return normalizedDns(
    one(
      completeList(response, "DNS records").map(normalizedDns),
      (item) =>
        item?.type === target.type &&
        item?.name === target.name &&
        item?.content === target.content &&
        (target.type !== "MX" || item?.priority === target.priority),
      "DNS record",
    ),
  );
}

export async function ensureProductionDnsRecord(client, targets, target, release, targetsSha256) {
  const body = {
    type: target.type,
    name: target.name,
    content: target.content,
    ttl: target.ttl,
    proxied: target.proxied,
    ...(target.priority === null ? {} : { priority: target.priority }),
  };
  return reconcile({
    stage: "cloudflare-dns-" + sha256(Buffer.from(target.type + "\0" + target.name)).slice(0, 12),
    inspect: () => inspectDnsRecord(client, targets, target),
    desired: (found) =>
      found !== null &&
      found.type === target.type &&
      found.name === target.name &&
      found.content === target.content &&
      found.ttl === target.ttl &&
      found.proxied === target.proxied &&
      found.priority === target.priority,
    mutate: async (found) => {
      if (!found && target.id) {
        throw new Error("Known DNS record identity is missing and cannot be recreated implicitly");
      }
      const base = "/zones/" + targets.cloudflare.zone.id + "/dns_records";
      await request(client, {
        method: found ? "PUT" : "POST",
        path: base + (found ? "/" + found.id : ""),
        body,
        idempotencyKey: idem(
          release,
          targetsSha256,
          "cloudflare-dns-" + target.type + "-" + target.name,
        ),
      });
      return { result: found ? "updated" : "created" };
    },
  });
}

function comparableDnsRecord(record) {
  return {
    type: record.type,
    name: record.name,
    content: record.content,
    ttl: record.ttl,
    proxied: record.proxied,
    priority: record.priority ?? null,
  };
}

export async function verifyExactProductionDnsInventory(client, targets) {
  const response = await request(client, {
    method: "GET",
    path: "/zones/" + targets.cloudflare.zone.id + "/dns_records",
    query: { page: "1", per_page: "10000" },
  });
  const actual = canonicalDnsInventory(completeList(response, "Cloudflare DNS inventory"));
  const expected = canonicalDnsInventory(targets.cloudflare.dnsRecords);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-dns-inventory-drift");
  }
  return state({ count: actual.length, inventorySha256: targetDigest(actual) });
}

export async function requireActiveProductionZone(client, targets) {
  const zone = await inspectProductionZone(client, targets.cloudflare);
  if (
    !zone ||
    zone.name !== targets.cloudflare.zone.name ||
    zone.accountId !== targets.cloudflare.accountId ||
    zone.type !== targets.cloudflare.zone.type ||
    zone.status !== "active" ||
    (targets.cloudflare.zone.id && zone.id !== targets.cloudflare.zone.id)
  ) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-not-active");
  }
  return Object.freeze({ result: "verified", resource: zone, state: state(zone) });
}

async function verifyProductionZoneSettings(client, zoneId, expected) {
  const actual = {};
  for (const settingId of ["always_use_https", "min_tls_version", "ssl"]) {
    const response = await request(client, {
      method: "GET",
      path: "/zones/" + zoneId + "/settings/" + settingId,
    });
    if (response.result?.id !== settingId || typeof response.result?.value !== "string") {
      throw new ProductionBootstrapAmbiguousError("cloudflare-zone-setting-readback");
    }
    actual[settingId] = response.result.value;
  }
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-settings-dns-stage-drift");
  }
  return state(actual);
}

export function validateProductionDnsStageReceipt({
  receiptBytes,
  dnsStage,
  application,
  controller,
  expectedAccountId,
  expectedResendDomainId,
  now = new Date(),
}) {
  let receipt;
  try {
    receipt = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(receiptBytes));
  } catch {
    throw new Error("production DNS-stage receipt is invalid JSON");
  }
  if (!Buffer.from(receiptBytes).equals(canonicalBytes(receipt))) {
    throw new Error("production DNS-stage receipt is not canonical");
  }
  exactObject(
    receipt,
    [
      "application",
      "cloudflare",
      "controller",
      "environment",
      "issuedAt",
      "protectedExecution",
      "providerCanary",
      "providerStateSha256",
      "registrar",
      "receiptType",
      "resend",
      "schemaVersion",
      "validUntil",
    ],
    "production DNS-stage receipt",
  );
  exactObject(receipt.application, ["repository", "repositoryId", "commitSha"], "DNS-stage receipt application");
  exactObject(receipt.controller, ["repository", "commitSha"], "DNS-stage receipt controller");
  exactObject(receipt.providerCanary, ["requestId", "receiptSha256", "runId"], "DNS-stage receipt Canary");
  exactObject(receipt.protectedExecution, ["brokerRequestId", "capsuleRequestSha256", "runId"], "DNS-stage receipt execution");
  exactObject(
    receipt.cloudflare,
    ["accountId", "dnsInventoryCount", "dnsInventorySha256", "dnsRecords", "nameServers", "observedBeforeZoneSettings", "zoneId", "zoneName", "zoneSettings", "zoneStatus"],
    "DNS-stage receipt Cloudflare",
  );
  exactObject(
    receipt.resend,
    ["domainId", "domainName", "region", "verificationRecordsSha256"],
    "DNS-stage receipt Resend",
  );
  exactObject(receipt.registrar, ["priorNameServers"], "DNS-stage receipt registrar");
  const issuedAt = canonicalInstant(receipt.issuedAt, "DNS-stage receipt issuedAt");
  const validUntil = canonicalInstant(receipt.validUntil, "DNS-stage receipt validUntil");
  if (
    receipt.schemaVersion !== 1 ||
    receipt.receiptType !== "fresh-towels-production-dns-stage" ||
    receipt.environment !== "production" ||
    validUntil - issuedAt !== 24 * 60 * 60 * 1000 ||
    now.valueOf() < issuedAt - 60_000 ||
    now.valueOf() >= validUntil ||
    receipt.application.repository !== application.repository ||
    receipt.application.repositoryId !== application.repositoryId ||
    receipt.application.commitSha !== application.commitSha ||
    receipt.controller.repository !== controller.repository ||
    receipt.controller.commitSha !== controller.commitSha ||
    receipt.protectedExecution.brokerRequestId !== dnsStage.requestId ||
    receipt.protectedExecution.runId !== dnsStage.runId ||
    receipt.cloudflare.accountId !== expectedAccountId ||
    !accountPattern.test(receipt.cloudflare.zoneId ?? "") ||
    receipt.cloudflare.zoneName !== publicDomain ||
    !["pending", "active"].includes(receipt.cloudflare.zoneStatus) ||
    canonicalJson(receipt.cloudflare.zoneSettings) !==
      canonicalJson({ always_use_https: "on", min_tls_version: "1.2", ssl: "strict" }) ||
    receipt.cloudflare.observedBeforeZoneSettings === null ||
    typeof receipt.cloudflare.observedBeforeZoneSettings !== "object" ||
    Array.isArray(receipt.cloudflare.observedBeforeZoneSettings) ||
    Object.keys(receipt.cloudflare.observedBeforeZoneSettings).sort().join(",") !==
      "always_use_https,min_tls_version,ssl" ||
    !["off", "on"].includes(receipt.cloudflare.observedBeforeZoneSettings.always_use_https) ||
    !["1.0", "1.1", "1.2", "1.3"].includes(
      receipt.cloudflare.observedBeforeZoneSettings.min_tls_version,
    ) ||
    !["off", "flexible", "full", "strict", "origin_pull"].includes(
      receipt.cloudflare.observedBeforeZoneSettings.ssl,
    ) ||
    !Array.isArray(receipt.cloudflare.nameServers) ||
    canonicalJson(canonicalZoneNameServers(receipt.cloudflare.nameServers)) !==
      canonicalJson(receipt.cloudflare.nameServers) ||
    !Array.isArray(receipt.registrar.priorNameServers) ||
    receipt.registrar.priorNameServers.length !== 2 ||
    !Array.isArray(receipt.cloudflare.dnsRecords) ||
    receipt.cloudflare.dnsRecords.length < 1 ||
    receipt.cloudflare.dnsRecords.length > maximumDnsRecords ||
    receipt.cloudflare.dnsInventoryCount !== receipt.cloudflare.dnsRecords.length ||
    !digestPattern.test(receipt.cloudflare.dnsInventorySha256 ?? "") ||
    receipt.resend.domainName !== sendingDomain ||
    receipt.resend.domainId !== expectedResendDomainId ||
    receipt.resend.region !== "eu-west-1" ||
    !safeIdPattern.test(receipt.resend.domainId ?? "") ||
    !digestPattern.test(receipt.resend.verificationRecordsSha256 ?? "") ||
    !digestPattern.test(receipt.providerStateSha256 ?? "")
  ) {
    throw new Error("production DNS-stage receipt binding is invalid");
  }
  receipt.cloudflare.dnsRecords.forEach(validateDnsRecord);
  return Object.freeze(structuredClone(receipt));
}

async function inspectResendDomain(client, targets) {
  const target = targets.resend.domain;
  if (target.id) {
    const response = await request(client, {
      method: "GET",
      path: "/domains/" + target.id,
    });
    return response.result;
  }
  const response = await request(client, {
    method: "GET",
    path: "/domains",
    query: { limit: "100" },
  });
  return one(
    completeList(response, "Resend domains"),
    (item) => (target.id && item?.id === target.id) || (!target.id && item?.name === target.name),
    "Resend domain",
  );
}

function canonicalResendDnsName(value, domainName) {
  if (typeof value !== "string" || value.length < 1 || value.length > 253 || /[\r\n\0]/.test(value)) {
    throw new Error("Resend DNS record name is invalid");
  }
  const name = value.toLowerCase().replace(/\.$/, "");
  if (name === publicDomain || name.endsWith("." + publicDomain)) return name;
  const relativeDomain = domainName.slice(0, -(publicDomain.length + 1));
  return name === relativeDomain || name.endsWith("." + relativeDomain)
    ? name + "." + publicDomain
    : name + "." + domainName;
}

export async function verifyProductionResendRecordDigest(client, targets, expectedSha256) {
  if (!digestPattern.test(expectedSha256 ?? "")) {
    throw new Error("Resend verification-record digest is invalid");
  }
  const domain = await inspectResendDomain(client, targets);
  if (
    !domain ||
    domain.id !== targets.resend.domain.id ||
    domain.name !== targets.resend.domain.name ||
    domain.region !== targets.resend.domain.region ||
    !Array.isArray(domain.records)
  ) {
    throw new Error("Resend verification-record source differs");
  }
  const records = domain.records
    .filter((item) => ["DKIM", "SPF"].includes(item?.record))
    .map((item) => ({
      record: item.record,
      type: item.type,
      name: canonicalResendDnsName(item.name, domain.name),
      content:
        item.type === "TXT"
          ? decodeCloudflareTxtContent(item.value)
          : item.value,
      priority: item.type === "MX" ? item.priority : null,
    }))
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  if (
    records.length < 3 ||
    records.length > 5 ||
    targetDigest(records) !== expectedSha256 ||
    records.filter((record) => record.record === "SPF" && record.type === "MX").length !== 1 ||
    records.filter((record) => record.record === "SPF" && record.type === "TXT").length !== 1 ||
    records.filter((record) => record.record === "DKIM" && ["TXT", "CNAME"].includes(record.type)).length < 1 ||
    records.some(
      (record) =>
        !["SPF/MX", "SPF/TXT", "DKIM/TXT", "DKIM/CNAME"].includes(
          `${record.record}/${record.type}`,
        ),
    )
  ) {
    throw new ProductionBootstrapAmbiguousError("resend-verification-record-drift");
  }
  return state({ domainIdentitySha256: targetDigest({ id: domain.id, name: domain.name }), recordsSha256: expectedSha256 });
}

export async function verifyProductionResendDomain(
  client,
  targets,
  { attempts = 6, delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)) } = {},
) {
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 12 || typeof delay !== "function") {
    throw new Error("Resend verification reconciliation boundary is invalid");
  }
  const target = targets.resend.domain;
  let domain = await inspectResendDomain(client, targets);
  if (!domain || domain.id !== target.id || domain.name !== sendingDomain || domain.region !== target.region) {
    throw new Error("Resend production sending domain identity differs");
  }
  if (domain.status !== "verified" || domain.capabilities?.sending !== "enabled") {
    try {
      await request(client, {
        method: "POST",
        path: "/domains/" + target.id + "/verify",
        idempotencyKey: null,
      });
    } catch (error) {
      if (error instanceof ProviderRejectedError) throw error;
      // A transport-ambiguous verification request is reconciled read-only below.
    }
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (attempt > 0) await delay(5_000);
      domain = await inspectResendDomain(client, targets);
      if (
        domain?.id === target.id &&
        domain?.name === sendingDomain &&
        domain?.region === target.region &&
        domain?.status === "verified" &&
        domain?.capabilities?.sending === "enabled"
      ) {
        break;
      }
    }
  }
  if (
    !domain ||
    domain.id !== target.id ||
    domain.name !== sendingDomain ||
    domain.region !== target.region ||
    domain.status !== "verified" ||
    domain.capabilities?.sending !== "enabled"
  ) {
    throw new ProductionBootstrapAmbiguousError("resend-domain-not-verified");
  }
  return state({
    verified: true,
    sendingEnabled: true,
    domainIdentitySha256: sha256(Buffer.from(domain.id + "\0" + domain.name)),
  });
}

async function secretStatus(secretSink, binding, context) {
  if (!secretSink || typeof secretSink.inspect !== "function" || typeof secretSink.store !== "function") {
    throw new Error("One-time secret sink is unavailable");
  }
  const result = await secretSink.inspect({ binding, context });
  exactObject(
    result,
    ["present", "bindingVersionSha256", "resourceIdentitySha256"],
    "secret sink inspection",
  );
  if (
    typeof result.present !== "boolean" ||
    (result.present && !digestPattern.test(result.bindingVersionSha256)) ||
    (result.present && result.resourceIdentitySha256 !== context.resourceIdentitySha256) ||
    (!result.present &&
      (result.bindingVersionSha256 !== null || result.resourceIdentitySha256 !== null))
  ) {
    throw new Error("secret sink inspection is malformed");
  }
  return result;
}

async function storeOneTimeSecret(secretSink, binding, secret, context) {
  if (typeof secret !== "string" || secret.length < 16 || /[\r\n\0]/.test(secret)) {
    throw new ProductionBootstrapAmbiguousError("one-time-secret-material");
  }
  const bytes = Buffer.from(secret, "utf8");
  const secretSha256 = sha256(bytes);
  try {
    const result = await secretSink.store({
      binding,
      secretBytes: bytes,
      secretSha256,
      context,
    });
    exactObject(
      result,
      ["stored", "bindingVersionSha256", "resourceIdentitySha256"],
      "secret sink result",
    );
    if (
      result.stored !== true ||
      !digestPattern.test(result.bindingVersionSha256) ||
      result.resourceIdentitySha256 !== context.resourceIdentitySha256
    ) {
      throw new Error("secret sink did not confirm custody");
    }
    return Object.freeze({
      present: true,
      bindingVersionSha256: result.bindingVersionSha256,
      resourceIdentitySha256: result.resourceIdentitySha256,
    });
  } finally {
    bytes.fill(0);
  }
}

async function ensureBootstrapRuntimeSecret({
  binding,
  context,
  secretFactory,
  secretSink,
}) {
  const before = await secretStatus(secretSink, binding, context);
  if (before.present) return before;
  const secret = secretFactory();
  try {
    return await storeOneTimeSecret(secretSink, binding, secret, context);
  } finally {
    if (Buffer.isBuffer(secret)) secret.fill(0);
  }
}

async function inspectResendWebhook(client, targets, secretSink, context) {
  const response = await request(client, {
    method: "GET",
    path: "/webhooks",
    query: { limit: "100" },
  });
  const target = targets.resend.webhook;
  const webhook = one(
    completeList(response, "Resend webhooks"),
    (item) =>
      (target.id && item?.id === target.id) ||
      (!target.id && item?.endpoint === target.endpoint),
    "Resend webhook",
  );
  let signingSecretSha256 = null;
  if (webhook) {
    const detail = await request(client, {
      method: "GET",
      path: "/webhooks/" + exactId(webhook.id, safeIdPattern, "Resend webhook"),
    });
    if (
      detail.result?.id !== webhook.id ||
      detail.result?.endpoint !== webhook.endpoint ||
      JSON.stringify([...(detail.result?.events ?? [])].sort()) !==
        JSON.stringify([...(webhook.events ?? [])].sort()) ||
      detail.result?.status !== webhook.status ||
      typeof detail.result?.signing_secret !== "string" ||
      !detail.result.signing_secret.startsWith("whsec_") ||
      detail.result.signing_secret.length < 22 ||
      /[\r\n\0]/.test(detail.result.signing_secret)
    ) {
      throw new ProductionBootstrapAmbiguousError("resend-webhook-detail-drift");
    }
    signingSecretSha256 = sha256(Buffer.from(detail.result.signing_secret, "utf8"));
  }
  const resourceIdentitySha256 = webhook
    ? targetDigest({
        provider: "resend",
        resource: "webhook",
        id: webhook.id,
        endpoint: webhook.endpoint,
        events: [...(webhook.events ?? [])].sort(),
        signingSecretSha256,
      })
    : targetDigest({ provider: "resend", resource: "webhook", state: "absent" });
  const custody = await secretStatus(secretSink, target.secretBinding, {
    ...context,
    resourceIdentitySha256,
  });
  return webhook
    ? {
        id: exactId(webhook.id, safeIdPattern, "Resend webhook"),
        endpoint: webhook.endpoint,
        events: [...(webhook.events ?? [])].sort(),
        status: webhook.status,
        custody,
      }
    : { id: null, endpoint: null, events: [], status: null, custody };
}

async function ensureResendWebhook(client, targets, secretSink, release, targetsSha256) {
  const target = targets.resend.webhook;
  const context = Object.freeze({
    brokerRequestId: release.brokerRequestId,
    capsuleRequestSha256: release.capsuleRequestSha256,
    applicationCommitSha: release.application.commitSha,
    targetSha256: targetsSha256,
  });
  const desiredEvents = [...target.events].sort();
  return reconcile({
    stage: "resend-webhook",
    inspect: () => inspectResendWebhook(client, targets, secretSink, context),
    desired: (found) =>
      found.id !== null &&
      found.endpoint === target.endpoint &&
      JSON.stringify(found.events) === JSON.stringify(desiredEvents) &&
      found.status === "enabled" &&
      found.custody.present,
    mutate: async (found) => {
      if (found.id && !found.custody.present) {
        const detail = await request(client, {
          method: "GET",
          path: "/webhooks/" + found.id,
        });
        if (
          detail.result?.id !== found.id ||
          typeof detail.result?.signing_secret !== "string"
        ) {
          throw new ProductionBootstrapAmbiguousError("resend-webhook-secret-recovery");
        }
        await storeOneTimeSecret(
          secretSink,
          target.secretBinding,
          detail.result.signing_secret,
          {
            ...context,
            resourceIdentitySha256: targetDigest({
              provider: "resend",
              resource: "webhook",
              id: found.id,
              endpoint: found.endpoint,
              events: [...found.events].sort(),
              signingSecretSha256: sha256(
                Buffer.from(detail.result.signing_secret, "utf8"),
              ),
            }),
          },
        );
        return { result: "updated" };
      }
      if (found.id) {
        await request(client, {
          method: "PATCH",
          path: "/webhooks/" + found.id,
          body: { endpoint: target.endpoint, events: target.events, status: "enabled" },
          idempotencyKey: idem(release, targetsSha256, "resend-webhook"),
        });
        return { result: "updated" };
      }
      const response = await request(client, {
        method: "POST",
        path: "/webhooks",
        body: { endpoint: target.endpoint, events: target.events },
        idempotencyKey: idem(release, targetsSha256, "resend-webhook"),
      });
      const createdId = exactId(response.result?.id, safeIdPattern, "Resend webhook");
      try {
        await storeOneTimeSecret(
          secretSink,
          target.secretBinding,
          response.result?.signing_secret,
          {
            ...context,
            resourceIdentitySha256: targetDigest({
              provider: "resend",
              resource: "webhook",
              id: createdId,
              endpoint: target.endpoint,
              events: [...target.events].sort(),
              signingSecretSha256: sha256(
                Buffer.from(response.result?.signing_secret ?? "", "utf8"),
              ),
            }),
          },
        );
      } catch {
        try {
          await request(client, { method: "DELETE", path: "/webhooks/" + createdId });
        } catch {
          // Reconciliation below determines whether the exact orphan remains.
        }
        throw new ProductionBootstrapAmbiguousError("resend-webhook-secret-custody");
      }
      return { result: "created" };
    },
  });
}

async function inspectSendingKey(client, targets, domainId, secretSink, context) {
  const response = await request(client, {
    method: "GET",
    path: "/api-keys",
    query: { limit: "100" },
  });
  const target = targets.resend.sendingKey;
  const key = one(
    completeList(response, "Resend API keys"),
    (item) =>
      (target.id && item?.id === target.id) ||
      (!target.id && item?.name === target.name),
    "Resend sending key",
  );
  const resourceIdentitySha256 = key
    ? targetDigest({
        provider: "resend",
        resource: "sending-key",
        id: key.id,
        name: key.name,
        leastPrivilegeProbeSha256: resendSendingKeyLeastPrivilegeProbeSha256,
        provisioningIntentSha256: targetDigest({
          permission: target.permission,
          domainId,
        }),
      })
    : targetDigest({ provider: "resend", resource: "sending-key", state: "absent" });
  const custody = await secretStatus(secretSink, target.secretBinding, {
    ...context,
    resourceIdentitySha256,
  });
  return key
    ? {
        id: exactId(key.id, safeIdPattern, "Resend API key"),
        name: key.name,
        leastPrivilegeProbeSha256: resendSendingKeyLeastPrivilegeProbeSha256,
        custody,
      }
    : {
        id: null,
        name: null,
        leastPrivilegeProbeSha256: resendSendingKeyLeastPrivilegeProbeSha256,
        custody,
      };
}

async function proveResendSendingKeyLeastPrivilege(runtimeClientFactory, token) {
  if (typeof runtimeClientFactory !== "function") {
    throw new ProductionBootstrapAmbiguousError("resend-sending-key-runtime-client");
  }
  let runtimeClient;
  try {
    runtimeClient = runtimeClientFactory(token);
  } catch {
    throw new ProductionBootstrapAmbiguousError("resend-sending-key-runtime-client");
  }
  if (!runtimeClient || typeof runtimeClient.request !== "function") {
    throw new ProductionBootstrapAmbiguousError("resend-sending-key-runtime-client");
  }
  try {
    await request(runtimeClient, {
      method: "GET",
      path: "/api-keys",
      query: { limit: "100" },
    });
  } catch (error) {
    if (
      error instanceof ProviderRejectedError &&
      error.status === 401 &&
      error.providerErrorCode === "restricted_api_key"
    ) {
      return resendSendingKeyLeastPrivilegeProbeSha256;
    }
    throw new ProductionBootstrapAmbiguousError("resend-sending-key-least-privilege-probe");
  }
  throw new ProductionBootstrapAmbiguousError("resend-sending-key-overprivileged");
}

async function ensureResendSendingKey(
  client,
  runtimeClientFactory,
  targets,
  domainId,
  secretSink,
  release,
  targetsSha256,
) {
  const target = targets.resend.sendingKey;
  const context = Object.freeze({
    brokerRequestId: release.brokerRequestId,
    capsuleRequestSha256: release.capsuleRequestSha256,
    applicationCommitSha: release.application.commitSha,
    targetSha256: targetsSha256,
  });
  return reconcile({
    stage: "resend-sending-key",
    inspect: () => inspectSendingKey(client, targets, domainId, secretSink, context),
    desired: (found) =>
      found.id !== null &&
      found.name === target.name &&
      found.custody.present,
    mutate: async (found) => {
      if (found.id || found.custody.present) {
        throw new ProductionBootstrapAmbiguousError("resend-sending-key-custody");
      }
      const response = await request(client, {
        method: "POST",
        path: "/api-keys",
        body: {
          name: target.name,
          permission: target.permission,
          domain_id: domainId,
        },
        idempotencyKey: idem(release, targetsSha256, "resend-sending-key"),
      });
      const createdId = exactId(response.result?.id, safeIdPattern, "Resend API key");
      try {
        const leastPrivilegeProbeSha256 = await proveResendSendingKeyLeastPrivilege(
          runtimeClientFactory,
          response.result?.token,
        );
        await storeOneTimeSecret(
          secretSink,
          target.secretBinding,
          response.result?.token,
          {
            ...context,
            resourceIdentitySha256: targetDigest({
              provider: "resend",
              resource: "sending-key",
              id: createdId,
              name: target.name,
              leastPrivilegeProbeSha256,
              provisioningIntentSha256: targetDigest({
                permission: target.permission,
                domainId,
              }),
            }),
          },
        );
      } catch {
        try {
          await request(client, { method: "DELETE", path: "/api-keys/" + createdId });
        } catch {
          // Reconciliation below determines whether the exact orphan remains.
        }
        throw new ProductionBootstrapAmbiguousError("resend-sending-key-secret-custody");
      }
      return { result: "created" };
    },
  });
}

function hashOnlyEvidence({
  release,
  capsuleSha256,
  privateReceiptSha256,
  encryptedCustodyProofSha256,
  providerStateSha256,
  wordpressFallbackSha256,
  protectedExecution,
  completedAt,
}) {
  const body = {
    schema: "deployment-control/production-provider-bootstrap-evidence/v1",
    operation: "production-bootstrap",
    requestId: protectedExecution.brokerRequestId,
    capsuleRequestSha256: protectedExecution.capsuleRequestSha256,
    applicationCommitSha: release.application.commitSha,
    controllerCommitSha: release.controller.commitSha,
    applicationRunId: release.application.runId,
    applicationRunAttempt: release.application.runAttempt,
    protectedExecutionRunId: protectedExecution.runId,
    capsuleSha256,
    privateReceiptSha256,
    encryptedCustodyProofSha256,
    providerStateSha256,
    wordpressFallbackSha256,
    result: "verified",
    completedAt,
  };
  return Object.freeze({
    ...body,
    receiptSha256: sha256(canonicalBytes(body)),
  });
}

async function storePrivateReceipt(privateReceiptSink, receipt, release) {
  if (!privateReceiptSink || typeof privateReceiptSink.store !== "function") {
    throw new Error("Private infrastructure receipt sink is unavailable");
  }
  const bytes = Buffer.from(JSON.stringify(receipt) + "\n", "utf8");
  const receiptSha256 = sha256(bytes);
  try {
    const result = await privateReceiptSink.store({
      receiptBytes: bytes,
      receiptSha256,
      context: {
        brokerRequestId: release.brokerRequestId,
        capsuleRequestSha256: release.capsuleRequestSha256,
        applicationCommitSha: release.application.commitSha,
        controllerCommitSha: release.controller.commitSha,
      },
    });
    exactObject(
      result,
      [
        "stored",
        "encrypted",
        "decryptVerified",
        "custodySha256",
        "encryptedArtifactSha256",
        "decryptionProofSha256",
        "decryptedReceiptSha256",
      ],
      "private receipt custody result",
    );
    if (
      result.stored !== true ||
      result.encrypted !== true ||
      result.decryptVerified !== true ||
      !digestPattern.test(result.custodySha256) ||
      !digestPattern.test(result.encryptedArtifactSha256) ||
      !digestPattern.test(result.decryptionProofSha256) ||
      result.decryptedReceiptSha256 !== receiptSha256
    ) {
      throw new Error("Private infrastructure receipt custody was not confirmed");
    }
    return Object.freeze({
      receiptSha256,
      encryptedCustodyProofSha256: targetDigest({
        custodySha256: result.custodySha256,
        encryptedArtifactSha256: result.encryptedArtifactSha256,
        decryptionProofSha256: result.decryptionProofSha256,
      }),
    });
  } finally {
    bytes.fill(0);
  }
}

export async function executeProductionProviderBootstrap({
  capsule,
  capsuleBytes,
  expectedCapsuleSha256,
  adminIdentity,
  cloudflareClient,
  resendClient,
  resendRuntimeClientFactory,
  secretSink,
  privateReceiptSink,
  dnsStageReceiptBytes,
  dnsVerifier = verifyConvergedDnsDelegation,
  wordpressFallbackVerifier = verifyWordPressFallback,
  resendVerificationOptions,
  protectedExecution,
  expectedBrokerRequestId,
  now = () => new Date(),
}) {
  if (typeof resendRuntimeClientFactory !== "function") {
    throw new Error("Resend runtime client factory is unavailable");
  }
  const current = now();
  const validated = validateProductionBootstrapCapsule({
    capsule,
    capsuleBytes,
    expectedCapsuleSha256,
    adminIdentity,
    now: current,
  });
  const targets = validated.targets;
  const dnsStageReceipt = validateProductionDnsStageReceipt({
    receiptBytes: dnsStageReceiptBytes,
    dnsStage: validated.dnsStage,
    application: validated.application,
    controller: validated.controller,
    expectedAccountId: targets.cloudflare.accountId,
    expectedResendDomainId: targets.resend.domain.id,
    now: current,
  });
  const release = Object.freeze({
    capsuleRequestSha256: validated.requestId,
    brokerRequestId: protectedExecution?.brokerRequestId,
    application: validated.application,
    controller: validated.controller,
  });
  exactObject(
    protectedExecution,
    ["brokerRequestId", "capsuleRequestSha256", "runId"],
    "protected execution provenance",
  );
  if (
    !uuidV4Pattern.test(protectedExecution.brokerRequestId) ||
    protectedExecution.brokerRequestId !== expectedBrokerRequestId ||
    protectedExecution.capsuleRequestSha256 !== validated.requestId ||
    !decimalPattern.test(protectedExecution.runId)
  ) {
    throw new Error("protected execution provenance differs from the approved release");
  }
  // DNS staging and registrar activation are an exact prior operation. Bootstrap
  // proves that state and Resend verification before any D1/Access mutation.
  const cloudflareAccount = await verifyProductionCloudflareAccount(cloudflareClient, targets);
  const workersDev = await verifyWorkersDevSubdomain(cloudflareClient, targets);
  const zone = await requireActiveProductionZone(cloudflareClient, targets);
  const effectiveTargets = structuredClone(targets);
  effectiveTargets.cloudflare.zone.id = zone.resource.id;
  effectiveTargets.cloudflare.dnsRecords = dnsStageReceipt.cloudflare.dnsRecords;
  if (
    zone.resource.id !== dnsStageReceipt.cloudflare.zoneId ||
    canonicalJson(zone.resource.nameServers) !== canonicalJson(dnsStageReceipt.cloudflare.nameServers)
  ) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-dns-stage-drift");
  }
  const zoneSettings = await verifyProductionZoneSettings(
    cloudflareClient,
    zone.resource.id,
    dnsStageReceipt.cloudflare.zoneSettings,
  );
  if (typeof dnsVerifier !== "function") {
    throw new Error("DNS delegation verifier is unavailable");
  }
  const delegation = await dnsVerifier({
    domain: publicDomain,
    expectedNameServers: zone.resource.nameServers,
  });
  if (
    delegation.cloudflareVerified !== true ||
    delegation.googleVerified !== true ||
    delegation.dsNoData !== true
  ) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-dns-delegation-drift");
  }
  if (typeof wordpressFallbackVerifier !== "function") {
    throw new Error("WordPress fallback verifier is unavailable");
  }
  const wordpressFallback = await wordpressFallbackVerifier();
  if (wordpressFallback.verified !== true || !digestPattern.test(wordpressFallback.proofSha256 ?? "")) {
    throw new ProductionBootstrapAmbiguousError("wordpress-fallback-not-proven");
  }
  const dnsInventory = await verifyExactProductionDnsInventory(
    cloudflareClient,
    effectiveTargets,
  );
  if (
    dnsInventory.value.inventorySha256 !== dnsStageReceipt.cloudflare.dnsInventorySha256 ||
    dnsInventory.value.count !== dnsStageReceipt.cloudflare.dnsInventoryCount
  ) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-dns-stage-receipt-drift");
  }
  const resendVerificationRecords = await verifyProductionResendRecordDigest(
    resendClient,
    effectiveTargets,
    dnsStageReceipt.resend.verificationRecordsSha256,
  );
  const resendDomain = await verifyProductionResendDomain(
    resendClient,
    effectiveTargets,
    resendVerificationOptions,
  );
  const primary = await ensureD1(
    cloudflareClient,
    effectiveTargets,
    targets.cloudflare.d1.primary,
    "primary",
    release,
    validated.capsuleSha256,
  );
  const recovery = await ensureD1(
    cloudflareClient,
    effectiveTargets,
    targets.cloudflare.d1.recovery,
    "recovery",
    release,
    validated.capsuleSha256,
  );
  const organization = await ensureAccessOrganization(
    cloudflareClient,
    effectiveTargets,
    release,
    validated.capsuleSha256,
  );
  const identityProvider = await ensureAccessIdentityProvider(
    cloudflareClient,
    effectiveTargets,
    release,
    validated.capsuleSha256,
  );
  const application = await ensureAccessApplication(
    cloudflareClient,
    effectiveTargets,
    identityProvider.resource.id,
    release,
    validated.capsuleSha256,
  );
  const policy = await ensureAccessPolicy(
    cloudflareClient,
    effectiveTargets,
    application.resource.id,
    adminIdentity,
    release,
    validated.capsuleSha256,
  );
  const domainList = await request(resendClient, {
    method: "GET",
    path: "/domains",
    query: { limit: "100" },
  });
  const domain = one(
    completeList(domainList, "Resend domains"),
    (item) => item?.name === sendingDomain,
    "Resend domain",
  );
  const webhook = await ensureResendWebhook(
    resendClient,
    effectiveTargets,
    secretSink,
    release,
    validated.capsuleSha256,
  );
  const sendingKey = await ensureResendSendingKey(
    resendClient,
    resendRuntimeClientFactory,
    effectiveTargets,
    exactId(domain.id, safeIdPattern, "Resend domain"),
    secretSink,
    release,
    validated.capsuleSha256,
  );
  const bootstrapSecretContext = Object.freeze({
    brokerRequestId: release.brokerRequestId,
    capsuleRequestSha256: release.capsuleRequestSha256,
    applicationCommitSha: release.application.commitSha,
    targetSha256: validated.capsuleSha256,
  });
  const dashboardAuthorizedEmails = await ensureBootstrapRuntimeSecret({
    binding: "DASHBOARD_AUTHORIZED_EMAILS",
    context: Object.freeze({
      ...bootstrapSecretContext,
      resourceIdentitySha256: targetDigest({
        schema: "deployment-control/dashboard-authorized-emails/v1",
        applicationId: application.resource.id,
        policyId: policy.resource.id,
        adminIdentitySha256: policy.resource.emailIdentitySha256,
      }),
    }),
    secretFactory: () => adminIdentity,
    secretSink,
  });
  const leadRateLimitSecret = await ensureBootstrapRuntimeSecret({
    binding: "LEAD_RATE_LIMIT_SECRET",
    context: Object.freeze({
      ...bootstrapSecretContext,
      resourceIdentitySha256: targetDigest({
        schema: "deployment-control/lead-rate-limit-secret/v1",
        workerName: targets.cloudflare.workerName,
        algorithm: "hmac-sha256",
      }),
    }),
    secretFactory: () => randomBytes(32).toString("base64url"),
    secretSink,
  });
  const providerStates = {
    cloudflareAccount: cloudflareAccount.sha256,
    workersDevSubdomain: workersDev.sha256,
    zone: zone.state.sha256,
    zoneSettings: zoneSettings.sha256,
    primaryD1: primary.state.sha256,
    recoveryD1: recovery.state.sha256,
    accessOrganization: organization.state.sha256,
    accessIdentityProvider: identityProvider.state.sha256,
    accessApplication: application.state.sha256,
    accessPolicy: policy.state.sha256,
    dnsInventory: dnsInventory.sha256,
    wordpressFallback: wordpressFallback.proofSha256,
    resendDomain: resendDomain.sha256,
    resendVerificationRecords: resendVerificationRecords.sha256,
    resendWebhook: webhook.state.sha256,
    resendSendingKey: sendingKey.state.sha256,
    dashboardAuthorizedEmails: dashboardAuthorizedEmails.bindingVersionSha256,
    leadRateLimitSecret: leadRateLimitSecret.bindingVersionSha256,
  };
  const issuedAt = current.toISOString();
  const validUntil = new Date(current.valueOf() + 24 * 60 * 60 * 1000).toISOString();
  const privateReceipt = {
    schemaVersion: 1,
    receiptType: "fresh-towels-production-infrastructure-bootstrap",
    environment: "production",
    issuedAt,
    validUntil,
    application: {
      repository: release.application.repository,
      repositoryId: release.application.repositoryId,
      commitSha: release.application.commitSha,
    },
    controller: {
      repository: release.controller.repository,
      commitSha: release.controller.commitSha,
    },
    dnsStage: validated.dnsStage,
    protectedExecution,
    verifiedState: {
      cloudflareTargetVerified: true,
      cloudflareZoneActive: zone.resource.status === "active",
      d1TargetsVerified: true,
      accessConfigurationVerified: true,
      resendDomainVerified: true,
      resendWebhookVerified: true,
      wordpressFallbackVerified: true,
    },
    stableEvidence: validated.stableEvidence,
    cloudflare: {
      accountId: targets.cloudflare.accountId,
      zoneId: zone.resource.id,
      zoneName: targets.cloudflare.zone.name,
      zoneStatus: zone.resource.status,
      nameServers: zone.resource.nameServers,
      zoneSettings: zoneSettings.value,
      dnsInventoryCount: dnsInventory.value.count,
      dnsInventorySha256: dnsInventory.value.inventorySha256,
      workerName: targets.cloudflare.workerName,
      workersDevSubdomain: workersDev.value.subdomain,
      d1: {
        jurisdiction: "eu",
        primary: { databaseName: primary.resource.name, databaseId: primary.resource.id },
        recovery: { databaseName: recovery.resource.name, databaseId: recovery.resource.id },
      },
      access: {
        identityProviderId: identityProvider.resource.id,
        identityProviderType: identityProvider.resource.type,
        applicationId: application.resource.id,
        applicationDomain: application.resource.domain,
        policyId: policy.resource.id,
        aud: application.resource.aud,
        destinations: application.resource.destinations,
        allowedIdentityProviderIds: application.resource.allowedIdps,
        adminIdentitySha256: policy.resource.emailIdentitySha256,
        policyDecision: policy.resource.decision,
        policyPrecedence: policy.resource.precedence,
        extraPolicyCount: policy.resource.extraPolicyCount,
        httpOnlyCookieAttribute: application.resource.httpOnlyCookieAttribute,
        sameSiteCookieAttribute: application.resource.sameSiteCookieAttribute,
        enableBindingCookie: application.resource.enableBindingCookie,
        pathCookieAttribute: application.resource.pathCookieAttribute,
        allowIframe: application.resource.allowIframe,
        allowAuthenticateViaWarp: application.resource.allowAuthenticateViaWarp,
        skipInterstitial: application.resource.skipInterstitial,
        optionsPreflightBypass: application.resource.optionsPreflightBypass,
        appLauncherVisible: application.resource.appLauncherVisible,
        autoRedirectToIdentity: application.resource.autoRedirectToIdentity,
        teamDomain: organization.resource.teamDomain,
        organizationSessionDuration:
          organization.resource.sessionDuration,
        applicationSessionDuration:
          application.resource.sessionDuration,
      },
    },
    resend: {
      domain: targets.resend.domain.name,
      domainId: exactId(domain.id, safeIdPattern, "Resend domain"),
      domainStatus: domain.status,
      sendingCapability: domain.capabilities.sending,
      senderAddress: targets.resend.senderAddress,
      webhookId: webhook.resource.id,
      webhookEndpointSha256: sha256(Buffer.from(webhook.resource.endpoint, "utf8")),
      webhookEvents: webhook.resource.events,
      webhookStatus: webhook.resource.status,
      sendingKeyId: sendingKey.resource.id,
      sendingKeyName: sendingKey.resource.name,
      sendingKeyLeastPrivilegeProbeSha256:
        sendingKey.resource.leastPrivilegeProbeSha256,
    },
    runtimeSecrets: {
      dashboardAuthorizedEmails: {
        binding: "DASHBOARD_AUTHORIZED_EMAILS",
        bindingVersionSha256: dashboardAuthorizedEmails.bindingVersionSha256,
        resourceIdentitySha256: dashboardAuthorizedEmails.resourceIdentitySha256,
      },
      leadRateLimitSecret: {
        binding: "LEAD_RATE_LIMIT_SECRET",
        bindingVersionSha256: leadRateLimitSecret.bindingVersionSha256,
        resourceIdentitySha256: leadRateLimitSecret.resourceIdentitySha256,
      },
      resendApiKey: {
        binding: "RESEND_API_KEY",
        bindingVersionSha256: sendingKey.resource.custody.bindingVersionSha256,
        resourceIdentitySha256: sendingKey.resource.custody.resourceIdentitySha256,
      },
      resendWebhookSecret: {
        binding: "RESEND_WEBHOOK_SECRET",
        bindingVersionSha256: webhook.resource.custody.bindingVersionSha256,
        resourceIdentitySha256: webhook.resource.custody.resourceIdentitySha256,
      },
    },
  };
  const privateReceiptCustody = await storePrivateReceipt(
    privateReceiptSink,
    privateReceipt,
    release,
  );
  return hashOnlyEvidence({
    release,
    capsuleSha256: validated.capsuleSha256,
    privateReceiptSha256: privateReceiptCustody.receiptSha256,
    encryptedCustodyProofSha256:
      privateReceiptCustody.encryptedCustodyProofSha256,
    providerStateSha256: targetDigest(providerStates),
    wordpressFallbackSha256: wordpressFallback.proofSha256,
    protectedExecution,
    completedAt: now().toISOString(),
  });
}

export const productionProviderBootstrapConstants = Object.freeze({
  publicDomain,
  resendSendingKeyLeastPrivilegeProbeSha256,
  sendingDomain,
});
