import { canonicalJson, sha256 } from "./control-contract.mjs";
import {
  ensureProductionDnsRecord,
  ensureProductionZone,
  inspectProductionZone,
  ProductionBootstrapAmbiguousError,
  verifyExactProductionDnsInventory,
  verifyProductionCloudflareAccount,
} from "./production-provider-bootstrap.mjs";
import { verifyDnsDelegationOnce } from "./dns-delegation-verifier.mjs";
import { decodeCloudflareTxtContent } from "./dns-inventory.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const accountPattern = /^[a-f0-9]{32}$/;
const uuidV4Pattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const safeIdPattern = /^[A-Za-z0-9_-]{1,128}$/;
const publicDomain = "freshtowels.gr";
const sendingDomain = "notify.freshtowels.gr";
const maximumCapsuleBytes = 32 * 1024;
const maximumDnsRecords = 64;

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

async function storePrivateDnsStageReceipt(sink, receipt, release) {
  if (!sink || typeof sink.store !== "function") {
    throw new Error("Private DNS-stage receipt sink is unavailable");
  }
  const bytes = canonicalBytes(receipt);
  const receiptSha256 = sha256(bytes);
  try {
    const result = await sink.store({
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
      "private DNS-stage receipt custody",
    );
    if (
      result.stored !== true ||
      result.encrypted !== true ||
      result.decryptVerified !== true ||
      result.decryptedReceiptSha256 !== receiptSha256 ||
      !digestPattern.test(result.custodySha256) ||
      !digestPattern.test(result.encryptedArtifactSha256) ||
      !digestPattern.test(result.decryptionProofSha256)
    ) {
      throw new Error("Private DNS-stage receipt custody was not confirmed");
    }
    return Object.freeze({
      receiptSha256,
      encryptedCustodyProofSha256: digest({
        custodySha256: result.custodySha256,
        encryptedArtifactSha256: result.encryptedArtifactSha256,
        decryptionProofSha256: result.decryptionProofSha256,
      }),
    });
  } finally {
    bytes.fill(0);
  }
}

function canonicalInstant(value, label) {
  const time = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    throw new Error(label + " is not canonical UTC");
  }
  return time;
}

function requestInput({ method, path, query = null, body, idempotencyKey = null }) {
  const bytes = body === undefined ? undefined : canonicalBytes(body);
  return {
    method,
    path,
    query,
    body,
    bodyBytes: undefined,
    bodySha256: bytes ? sha256(bytes) : undefined,
    contentType: undefined,
    idempotencyKey,
  };
}

async function request(client, input) {
  if (!client || typeof client.request !== "function") {
    throw new Error("Production DNS-stage provider client is unavailable");
  }
  return client.request(requestInput(input));
}

function validateIdentity(capsule) {
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
    "DNS-stage application identity",
  );
  exactObject(capsule.controller, ["repository", "commitSha", "workflowRef"], "DNS-stage controller identity");
  if (
    capsule.application.repository !== "zikosbozonis-beep/fresh-towels-website" ||
    capsule.application.repositoryId !== "1350923567" ||
    capsule.application.ref !== "refs/heads/main" ||
    !commitPattern.test(capsule.application.commitSha) ||
    capsule.application.workflowRef !==
      "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main" ||
    capsule.application.workflowSha !== capsule.application.commitSha ||
    !decimalPattern.test(capsule.application.runId) ||
    !Number.isSafeInteger(capsule.application.runAttempt) ||
    capsule.application.runAttempt < 1 ||
    capsule.application.runAttempt > 100 ||
    capsule.controller.repository !== "zikosbozonis-beep/fresh-towels-deployment-control" ||
    !commitPattern.test(capsule.controller.commitSha) ||
    capsule.controller.workflowRef !==
      "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@" +
        capsule.controller.commitSha
  ) {
    throw new Error("production DNS-stage capsule identity is invalid");
  }
}

function validateDnsRecord(record) {
  exactObject(record, ["id", "type", "name", "content", "ttl", "proxied", "priority"], "DNS-stage record");
  if (
    (record.id !== null && !accountPattern.test(record.id)) ||
    !["A", "AAAA", "CNAME", "MX", "TXT"].includes(record.type) ||
    typeof record.name !== "string" ||
    (record.name !== publicDomain && !record.name.endsWith("." + publicDomain)) ||
    typeof record.content !== "string" ||
    record.content.length < 1 ||
    record.content.length > 4096 ||
    /[\r\n\0]/.test(record.content) ||
    !Number.isSafeInteger(record.ttl) ||
    (record.ttl !== 1 && (record.ttl < 60 || record.ttl > 86400)) ||
    typeof record.proxied !== "boolean" ||
    (record.proxied && record.ttl !== 1) ||
    (record.priority !== null &&
      (!Number.isSafeInteger(record.priority) || record.priority < 0 || record.priority > 65535)) ||
    (record.type === "MX" && record.priority === null) ||
    (record.type !== "MX" && record.priority !== null) ||
    (["MX", "TXT"].includes(record.type) && record.proxied)
  ) {
    throw new Error("production DNS-stage record is invalid");
  }
}

function validateVerificationRecord(record) {
  exactObject(record, ["record", "type", "name", "content", "priority"], "Resend verification record");
  if (
    !["DKIM", "SPF"].includes(record.record) ||
    !["CNAME", "MX", "TXT"].includes(record.type) ||
    typeof record.name !== "string" ||
    !record.name.endsWith("." + publicDomain) ||
    typeof record.content !== "string" ||
    record.content.length < 1 ||
    record.content.length > 4096 ||
    /[\r\n\0]/.test(record.content) ||
    (record.type === "CNAME" && record.record !== "DKIM") ||
    (record.type === "MX" &&
      (!Number.isSafeInteger(record.priority) || record.priority < 0 || record.priority > 65535)) ||
    (record.type !== "MX" && record.priority !== null)
  ) {
    throw new Error("Resend verification record is invalid");
  }
}

function validateDnsTargets(targets) {
  exactObject(targets, ["cloudflare", "registrar", "resend"], "DNS-stage targets");
  exactObject(targets.cloudflare, ["accountId", "zone", "dnsRecords", "zoneSettings"], "DNS-stage Cloudflare target");
  exactObject(targets.registrar, ["priorNameServers"], "DNS-stage registrar target");
  exactObject(targets.cloudflare.zone, ["id", "name", "type"], "DNS-stage zone target");
  if (
    !accountPattern.test(targets.cloudflare.accountId) ||
    (targets.cloudflare.zone.id !== null && !accountPattern.test(targets.cloudflare.zone.id)) ||
    targets.cloudflare.zone.name !== publicDomain ||
    targets.cloudflare.zone.type !== "full" ||
    !Array.isArray(targets.registrar.priorNameServers) ||
    targets.registrar.priorNameServers.length !== 2 ||
    targets.registrar.priorNameServers.some(
      (name) => typeof name !== "string" || !/^[a-z0-9.-]{4,253}$/.test(name),
    ) ||
    new Set(targets.registrar.priorNameServers).size !== 2 ||
    !Array.isArray(targets.cloudflare.dnsRecords) ||
    targets.cloudflare.dnsRecords.length < 1 ||
    targets.cloudflare.dnsRecords.length > maximumDnsRecords
  ) {
    throw new Error("production DNS-stage Cloudflare target is invalid");
  }
  exactObject(
    targets.cloudflare.zoneSettings,
    ["always_use_https", "min_tls_version", "ssl"],
    "DNS-stage Cloudflare zone settings",
  );
  if (
    targets.cloudflare.zoneSettings.ssl !== "strict" ||
    targets.cloudflare.zoneSettings.always_use_https !== "on" ||
    targets.cloudflare.zoneSettings.min_tls_version !== "1.2"
  ) {
    throw new Error("production DNS-stage Cloudflare zone settings are invalid");
  }
  targets.cloudflare.dnsRecords.forEach(validateDnsRecord);
  const identities = targets.cloudflare.dnsRecords.map((record) =>
    record.type === "TXT"
      ? [record.type, record.name, record.content].join("\0")
      : record.type === "MX"
        ? [record.type, record.name, record.content, record.priority].join("\0")
        : [record.type, record.name].join("\0"),
  );
  if (new Set(identities).size !== identities.length) {
    throw new Error("production DNS-stage contains duplicate DNS identities");
  }
  const apexAddresses = targets.cloudflare.dnsRecords.filter(
    (record) => record.name === publicDomain && ["A", "AAAA"].includes(record.type),
  );
  const www = targets.cloudflare.dnsRecords.filter(
    (record) =>
      record.type === "CNAME" &&
      record.name === "www." + publicDomain &&
      record.content.replace(/\.$/, "") === publicDomain,
  );
  if (
    apexAddresses.length < 1 ||
    apexAddresses.some((record) => record.proxied !== true) ||
    www.length !== 1 ||
    www[0].proxied !== true
  ) {
    throw new Error("production DNS-stage origin records must preserve proxied apex/www fallback");
  }

  exactObject(targets.resend, ["domain", "verificationRecords"], "DNS-stage Resend target");
  exactObject(targets.resend.domain, ["id", "name", "region"], "DNS-stage Resend domain");
  if (
    !safeIdPattern.test(targets.resend.domain.id ?? "") ||
    targets.resend.domain.name !== sendingDomain ||
    targets.resend.domain.region !== "eu-west-1" ||
    !Array.isArray(targets.resend.verificationRecords) ||
    targets.resend.verificationRecords.length < 3 ||
    targets.resend.verificationRecords.length > 5
  ) {
    throw new Error("production DNS-stage Resend target is invalid");
  }
  targets.resend.verificationRecords.forEach(validateVerificationRecord);
  const roleTypes = targets.resend.verificationRecords.map((record) => `${record.record}/${record.type}`);
  if (
    roleTypes.filter((value) => value === "SPF/MX").length !== 1 ||
    roleTypes.filter((value) => value === "SPF/TXT").length !== 1 ||
    roleTypes.filter((value) => value.startsWith("DKIM/")).length < 1 ||
    roleTypes.some((value) => !["SPF/MX", "SPF/TXT", "DKIM/TXT", "DKIM/CNAME"].includes(value))
  ) {
    throw new Error("production DNS-stage Resend record roles are incomplete");
  }
  const mirror = new Set(
    targets.cloudflare.dnsRecords.map((record) =>
      [record.type, record.name, record.content, record.priority ?? ""].join("\0"),
    ),
  );
  if (
    targets.resend.verificationRecords.some(
      (record) =>
        !mirror.has([record.type, record.name, record.content, record.priority ?? ""].join("\0")),
    )
  ) {
    throw new Error("Resend verification records are absent from the exact DNS mirror");
  }
}

const zoneSettingAllowedValues = Object.freeze({
  ssl: new Set(["off", "flexible", "full", "strict", "origin_pull"]),
  always_use_https: new Set(["off", "on"]),
  min_tls_version: new Set(["1.0", "1.1", "1.2", "1.3"]),
});

async function inspectZoneSettings(client, zoneId) {
  const result = {};
  for (const settingId of Object.keys(zoneSettingAllowedValues).sort()) {
    const response = await request(client, {
      method: "GET",
      path: "/zones/" + zoneId + "/settings/" + settingId,
    });
    const setting = response.result;
    if (setting?.id !== settingId || !zoneSettingAllowedValues[settingId].has(setting.value)) {
      throw new ProductionBootstrapAmbiguousError("cloudflare-zone-setting-readback");
    }
    result[settingId] = setting.value;
  }
  return Object.freeze(result);
}

async function ensureZoneSettings(client, zoneId, targetSettings, allowMutation) {
  const before = await inspectZoneSettings(client, zoneId);
  const drifted = Object.keys(targetSettings).filter((key) => before[key] !== targetSettings[key]);
  if (drifted.length === 0) return Object.freeze({ before, after: before, result: "unchanged" });
  if (!allowMutation) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-settings-active-drift");
  }
  for (const settingId of drifted.sort()) {
    try {
      await request(client, {
        method: "PATCH",
        path: "/zones/" + zoneId + "/settings/" + settingId,
        body: { value: targetSettings[settingId] },
        idempotencyKey: null,
      });
    } catch {
      // A transport-ambiguous setting update is reconciled by exact readback below.
    }
  }
  const after = await inspectZoneSettings(client, zoneId);
  if (canonicalJson(after) !== canonicalJson(targetSettings)) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-settings-not-converged");
  }
  return Object.freeze({ before, after, result: "updated" });
}

function dnsStageRequestId(capsule) {
  return digest({
    application: capsule.application,
    controller: capsule.controller,
    createdAt: capsule.createdAt,
    providerCanary: capsule.dnsStage.providerCanary,
    safeguards: capsule.dnsStage.safeguards,
    targets: capsule.dnsStage.targets,
  });
}

export function validateProductionDnsStageCapsule({
  capsule,
  capsuleBytes,
  expectedCapsuleSha256,
  now = new Date(),
}) {
  exactObject(
    capsule,
    ["application", "capsuleType", "controller", "createdAt", "dnsStage", "operation", "schemaVersion", "validUntil"],
    "production DNS-stage capsule",
  );
  if (
    capsule.schemaVersion !== 1 ||
    capsule.capsuleType !== "fresh-towels-production-dns-stage-capsule" ||
    capsule.operation !== "production-dns-stage" ||
    !Buffer.isBuffer(capsuleBytes) ||
    capsuleBytes.byteLength < 1 ||
    capsuleBytes.byteLength > maximumCapsuleBytes ||
    !digestPattern.test(expectedCapsuleSha256 ?? "") ||
    sha256(capsuleBytes) !== expectedCapsuleSha256 ||
    !capsuleBytes.equals(canonicalBytes(capsule))
  ) {
    throw new Error("production DNS-stage capsule byte binding is invalid");
  }
  validateIdentity(capsule);
  const createdAt = canonicalInstant(capsule.createdAt, "DNS-stage createdAt");
  const validUntil = canonicalInstant(capsule.validUntil, "DNS-stage validUntil");
  if (
    validUntil - createdAt !== 2 * 60 * 60 * 1000 ||
    now.valueOf() < createdAt - 60_000 ||
    now.valueOf() >= validUntil
  ) {
    throw new Error("production DNS-stage capsule is stale");
  }
  exactObject(capsule.dnsStage, ["intent", "providerCanary", "requestId", "safeguards", "targets"], "DNS-stage declaration");
  exactObject(capsule.dnsStage.providerCanary, ["requestId", "receiptSha256", "runId"], "provider Canary prerequisite");
  exactObject(
    capsule.dnsStage.safeguards,
    [
      "applicationArtifactPresent",
      "applicationBuildAuthorized",
      "credentialsPresent",
      "productionDnsStageMutationAuthorized",
      "productionTrafficMutationAuthorized",
      "registrarMutationAuthorized",
    ],
    "DNS-stage safeguards",
  );
  if (
    capsule.dnsStage.intent !== "stage-exact-production-dns-without-traffic-switch" ||
    !digestPattern.test(capsule.dnsStage.requestId) ||
    capsule.dnsStage.requestId !== dnsStageRequestId(capsule) ||
    !uuidV4Pattern.test(capsule.dnsStage.providerCanary.requestId) ||
    !digestPattern.test(capsule.dnsStage.providerCanary.receiptSha256) ||
    !decimalPattern.test(capsule.dnsStage.providerCanary.runId) ||
    capsule.dnsStage.safeguards.credentialsPresent !== false ||
    capsule.dnsStage.safeguards.applicationBuildAuthorized !== false ||
    capsule.dnsStage.safeguards.applicationArtifactPresent !== false ||
    capsule.dnsStage.safeguards.productionTrafficMutationAuthorized !== false ||
    capsule.dnsStage.safeguards.registrarMutationAuthorized !== false ||
    capsule.dnsStage.safeguards.productionDnsStageMutationAuthorized !== true
  ) {
    throw new Error("production DNS-stage declaration is invalid");
  }
  validateDnsTargets(capsule.dnsStage.targets);
  return Object.freeze({
    capsule,
    capsuleSha256: expectedCapsuleSha256,
    requestId: capsule.dnsStage.requestId,
    application: capsule.application,
    controller: capsule.controller,
    providerCanary: capsule.dnsStage.providerCanary,
    targets: capsule.dnsStage.targets,
  });
}

function canonicalDnsName(value, domainName) {
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

function normalizedResendVerificationRecords(domain) {
  if (!Array.isArray(domain?.records)) throw new Error("Resend domain records are unavailable");
  const records = domain.records
    .filter((item) => ["DKIM", "SPF"].includes(item?.record))
    .map((item) => ({
      record: item.record,
      type: item.type,
      name: canonicalDnsName(item.name, domain.name),
      content:
        item.type === "TXT"
          ? decodeCloudflareTxtContent(item.value)
          : item.value,
      priority: item.type === "MX" ? item.priority : null,
    }));
  records.forEach(validateVerificationRecord);
  return records.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

async function verifyResendRecordSource(client, targets) {
  const response = await request(client, {
    method: "GET",
    path: "/domains/" + targets.resend.domain.id,
  });
  const domain = response.result;
  if (
    domain?.id !== targets.resend.domain.id ||
    domain?.name !== targets.resend.domain.name ||
    domain?.region !== targets.resend.domain.region
  ) {
    throw new Error("Resend production domain identity differs");
  }
  const actual = normalizedResendVerificationRecords(domain);
  const expected = [...targets.resend.verificationRecords].sort((left, right) =>
    canonicalJson(left).localeCompare(canonicalJson(right)),
  );
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new ProductionBootstrapAmbiguousError("resend-verification-record-drift");
  }
  return Object.freeze({ recordsSha256: digest(actual), domainIdentitySha256: digest({ id: domain.id, name: domain.name }) });
}

export async function executeProductionDnsStage({
  capsule,
  capsuleBytes,
  expectedCapsuleSha256,
  cloudflareClient,
  resendClient,
  privateReceiptSink,
  dnsVerifier = verifyDnsDelegationOnce,
  protectedExecution,
  expectedBrokerRequestId,
  now = () => new Date(),
}) {
  const current = now();
  const validated = validateProductionDnsStageCapsule({
    capsule,
    capsuleBytes,
    expectedCapsuleSha256,
    now: current,
  });
  exactObject(protectedExecution, ["brokerRequestId", "capsuleRequestSha256", "runId"], "DNS-stage protected execution");
  if (
    !uuidV4Pattern.test(protectedExecution.brokerRequestId) ||
    protectedExecution.brokerRequestId !== expectedBrokerRequestId ||
    protectedExecution.capsuleRequestSha256 !== validated.requestId ||
    !decimalPattern.test(protectedExecution.runId)
  ) {
    throw new Error("DNS-stage protected execution differs from the approved release");
  }
  const release = Object.freeze({
    brokerRequestId: protectedExecution.brokerRequestId,
    capsuleRequestSha256: protectedExecution.capsuleRequestSha256,
    application: validated.application,
    controller: validated.controller,
  });
  if (typeof dnsVerifier !== "function") throw new Error("DNS delegation verifier is unavailable");
  const resend = await verifyResendRecordSource(resendClient, validated.targets);
  const account = await verifyProductionCloudflareAccount(cloudflareClient, validated.targets);
  const zone = await ensureProductionZone(
    cloudflareClient,
    validated.targets,
    release,
    validated.capsuleSha256,
  );
  const effectiveTargets = structuredClone(validated.targets);
  effectiveTargets.cloudflare.zone.id = zone.resource.id;
  const zoneSettings = await ensureZoneSettings(
    cloudflareClient,
    zone.resource.id,
    effectiveTargets.cloudflare.zoneSettings,
    zone.resource.status === "pending",
  );
  const expectedDelegation =
    zone.resource.status === "pending"
      ? effectiveTargets.registrar.priorNameServers
      : zone.resource.status === "active"
        ? zone.resource.nameServers
        : null;
  if (!expectedDelegation) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-stage-status");
  }
  const delegation = await dnsVerifier({
    domain: publicDomain,
    expectedNameServers: expectedDelegation,
  });
  if (
    delegation.cloudflareVerified !== true ||
    delegation.googleVerified !== true ||
    delegation.dsNoData !== true
  ) {
    throw new ProductionBootstrapAmbiguousError("dns-delegation-drift");
  }
  const recordStates = [];
  if (zone.resource.status === "pending") {
    for (const record of effectiveTargets.cloudflare.dnsRecords) {
      recordStates.push(
        await ensureProductionDnsRecord(
          cloudflareClient,
          effectiveTargets,
          record,
          release,
          validated.capsuleSha256,
        ),
      );
    }
  }
  const inventory = await verifyExactProductionDnsInventory(cloudflareClient, effectiveTargets);
  const rereadZone = await inspectProductionZone(cloudflareClient, effectiveTargets.cloudflare);
  if (!rereadZone || rereadZone.status !== zone.resource.status || rereadZone.id !== zone.resource.id) {
    throw new ProductionBootstrapAmbiguousError("cloudflare-zone-stage-reread");
  }
  const providerStateSha256 = digest({
    account: account.sha256,
    zone: zone.state.sha256,
    zoneSettings: digest(zoneSettings),
    dnsRecords:
      zone.resource.status === "pending"
        ? recordStates.map((item) => item.state.sha256)
        : [inventory.sha256],
    dnsInventory: inventory.sha256,
    resendDomainIdentity: resend.domainIdentitySha256,
    resendVerificationRecords: resend.recordsSha256,
  });
  const issuedAt = current.toISOString();
  const validUntil = new Date(current.valueOf() + 24 * 60 * 60 * 1000).toISOString();
  const privateReceipt = {
    schemaVersion: 1,
    receiptType: "fresh-towels-production-dns-stage",
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
    providerCanary: validated.providerCanary,
    protectedExecution,
    cloudflare: {
      accountId: effectiveTargets.cloudflare.accountId,
      zoneId: zone.resource.id,
      zoneName: effectiveTargets.cloudflare.zone.name,
      zoneStatus: zone.resource.status,
      nameServers: zone.resource.nameServers,
      observedBeforeZoneSettings: zoneSettings.before,
      zoneSettings: zoneSettings.after,
      dnsRecords: effectiveTargets.cloudflare.dnsRecords,
      dnsInventoryCount: inventory.value.count,
      dnsInventorySha256: inventory.value.inventorySha256,
    },
    registrar: {
      priorNameServers: effectiveTargets.registrar.priorNameServers,
    },
    resend: {
      domainId: effectiveTargets.resend.domain.id,
      domainName: effectiveTargets.resend.domain.name,
      region: effectiveTargets.resend.domain.region,
      verificationRecordsSha256: resend.recordsSha256,
    },
    providerStateSha256,
  };
  const custody = await storePrivateDnsStageReceipt(privateReceiptSink, privateReceipt, release);
  const body = {
    schema: "deployment-control/production-dns-stage-evidence/v1",
    operation: "production-dns-stage",
    requestId: protectedExecution.brokerRequestId,
    capsuleRequestSha256: protectedExecution.capsuleRequestSha256,
    applicationCommitSha: validated.application.commitSha,
    controllerCommitSha: validated.controller.commitSha,
    applicationRunId: validated.application.runId,
    applicationRunAttempt: validated.application.runAttempt,
    protectedExecutionRunId: protectedExecution.runId,
    capsuleSha256: validated.capsuleSha256,
    cloudflareZoneStateSha256: zone.state.sha256,
    dnsInventorySha256: inventory.value.inventorySha256,
    resendVerificationRecordsSha256: resend.recordsSha256,
    providerStateSha256,
    privateReceiptSha256: custody.receiptSha256,
    encryptedCustodyProofSha256: custody.encryptedCustodyProofSha256,
    result: "verified",
    completedAt: now().toISOString(),
  };
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

export const productionDnsStageConstants = Object.freeze({ publicDomain, sendingDomain });
