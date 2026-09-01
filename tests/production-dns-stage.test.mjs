import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  executeProductionDnsStage,
  validateProductionDnsStageCapsule,
} from "../scripts/production-dns-stage.mjs";
import { ProductionBootstrapAmbiguousError } from "../scripts/production-provider-bootstrap.mjs";

const now = new Date("2026-09-01T17:00:00.000Z");
const accountId = "a".repeat(32);
const zoneId = "b".repeat(32);
const assignedNameServers = ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"];
const priorNameServers = ["ns355.grserver.gr", "ns356.grserver.gr"];
const resendDomainId = "c63fd375-20ce-406a-a13a-85b0a85db733";
const verificationRecords = [
  { record: "DKIM", type: "TXT", name: "resend._domainkey.notify.freshtowels.gr", content: "p=synthetic", priority: null },
  { record: "SPF", type: "MX", name: "bounce.notify.freshtowels.gr", content: "feedback-smtp.eu-west-1.amazonses.com", priority: 10 },
  { record: "SPF", type: "TXT", name: "bounce.notify.freshtowels.gr", content: "v=spf1 include:amazonses.com ~all", priority: null },
];
const dnsRecords = [
  { id: null, type: "A", name: "freshtowels.gr", content: "192.0.2.10", ttl: 1, proxied: true, priority: null },
  { id: null, type: "CNAME", name: "www.freshtowels.gr", content: "freshtowels.gr", ttl: 1, proxied: true, priority: null },
  ...verificationRecords.map((record) => ({ id: null, type: record.type, name: record.name, content: record.content, ttl: 300, proxied: false, priority: record.priority })),
];

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n"));
}

function response(result) {
  return { providerRequestId: null, status: 200, result, responseSha256: digest(result), pagination: { complete: true } };
}

function capsule() {
  const value = {
    application: {
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1350923567",
      ref: "refs/heads/main",
      commitSha: "2".repeat(40),
      workflowRef: "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
      workflowSha: "2".repeat(40),
      runId: "39000000001",
      runAttempt: 1,
    },
    capsuleType: "fresh-towels-production-dns-stage-capsule",
    controller: {
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      commitSha: "3".repeat(40),
      workflowRef: "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@" + "3".repeat(40),
    },
    createdAt: "2026-09-01T16:59:00.000Z",
    dnsStage: {
      requestId: "0".repeat(64),
      intent: "stage-exact-production-dns-without-traffic-switch",
      providerCanary: { requestId: "66666666-6666-4666-8666-666666666666", receiptSha256: "7".repeat(64), runId: "33524593667" },
      targets: {
        cloudflare: {
          accountId,
          zone: { id: null, name: "freshtowels.gr", type: "full" },
          dnsRecords: structuredClone(dnsRecords),
          zoneSettings: { always_use_https: "on", min_tls_version: "1.2", ssl: "strict" },
        },
        registrar: { priorNameServers: [...priorNameServers] },
        resend: { domain: { id: resendDomainId, name: "notify.freshtowels.gr", region: "eu-west-1" }, verificationRecords: structuredClone(verificationRecords) },
      },
      safeguards: {
        credentialsPresent: false,
        applicationBuildAuthorized: false,
        applicationArtifactPresent: false,
        productionTrafficMutationAuthorized: false,
        registrarMutationAuthorized: false,
        productionDnsStageMutationAuthorized: true,
      },
    },
    operation: "production-dns-stage",
    schemaVersion: 1,
    validUntil: "2026-09-01T18:59:00.000Z",
  };
  value.dnsStage.requestId = digest({
    application: value.application,
    controller: value.controller,
    createdAt: value.createdAt,
    providerCanary: value.dnsStage.providerCanary,
    safeguards: value.dnsStage.safeguards,
    targets: value.dnsStage.targets,
  });
  return value;
}

function capsuleInput(value = capsule()) {
  const capsuleBytes = Buffer.from(canonicalJson(value) + "\n");
  return { capsule: value, capsuleBytes, expectedCapsuleSha256: sha256(capsuleBytes) };
}

function resendClient({ records = verificationRecords, region = "eu-west-1", id = resendDomainId, quotedTxt = false } = {}) {
  return {
    async request(input) {
      assert.equal(input.method, "GET");
      assert.equal(input.path, "/domains/" + resendDomainId);
      return response({
        id,
        name: "notify.freshtowels.gr",
        region,
        records: records.map((record) => ({
          record: record.record,
          type: record.type,
          name: record.name.replace(/\.freshtowels\.gr$/, ""),
          value:
            quotedTxt && record.type === "TXT"
              ? `"${record.content.slice(0, Math.max(1, Math.floor(record.content.length / 2)))}" "${record.content.slice(Math.max(1, Math.floor(record.content.length / 2)))}"`
              : record.content,
          priority: record.priority,
        })),
      });
    },
  };
}

function cloudflareClient({ initialStatus = null, duplicateZone = false, zoneSettingOverrides = {}, quotedTxt = false } = {}) {
  let status = initialStatus;
  const zoneSettings = initialStatus === "active"
    ? { always_use_https: "on", min_tls_version: "1.2", ssl: "strict" }
    : { always_use_https: "off", min_tls_version: "1.0", ssl: "full" };
  Object.assign(zoneSettings, zoneSettingOverrides);
  const records = [];
  const mutations = [];
  const requests = [];
  const client = {
    mutations,
    requests,
    async request(input) {
      requests.push(input);
      if (input.path === "/accounts/" + accountId) return response({ id: accountId });
      if (input.path === "/zones" && input.method === "GET") {
        if (status === null) return response([]);
        const zone = { id: zoneId, name: "freshtowels.gr", type: "full", status, account: { id: accountId } };
        return response(duplicateZone ? [zone, { ...zone }] : [zone]);
      }
      if (input.path === "/zones" && input.method === "POST") {
        mutations.push("zone:create");
        status = "pending";
        return response({ id: zoneId });
      }
      if (input.path === "/zones/" + zoneId && input.method === "GET") {
        return response({ id: zoneId, name: "freshtowels.gr", type: "full", status, account: { id: accountId }, name_servers: assignedNameServers });
      }
      const settingMatch = input.path.match(new RegExp("^/zones/" + zoneId + "/settings/(always_use_https|min_tls_version|ssl)$"));
      if (settingMatch && input.method === "GET") {
        return response({ id: settingMatch[1], value: zoneSettings[settingMatch[1]] });
      }
      if (settingMatch && input.method === "PATCH") {
        mutations.push("setting:" + settingMatch[1]);
        zoneSettings[settingMatch[1]] = input.body.value;
        return response({ id: settingMatch[1], value: zoneSettings[settingMatch[1]] });
      }
      if (input.path === "/zones/" + zoneId + "/dns_records" && input.method === "GET") {
        return response(records.map((record) => {
          if (!quotedTxt || record.type !== "TXT") return record;
          const middle = Math.max(1, Math.floor(record.content.length / 2));
          return { ...record, content: `"${record.content.slice(0, middle)}" "${record.content.slice(middle)}"` };
        }));
      }
      if (input.path === "/zones/" + zoneId + "/dns_records" && input.method === "POST") {
        mutations.push("dns:create");
        records.push({ ...input.body, id: String(records.length + 1).repeat(32).slice(0, 32), priority: input.body.priority ?? null });
        return response(records.at(-1));
      }
      throw new Error("unexpected Cloudflare request " + input.method + " " + input.path);
    },
  };
  if (initialStatus === "active") {
    records.push(...dnsRecords.map((record, index) => ({ ...record, id: String(index + 1).repeat(32).slice(0, 32) })));
  }
  return client;
}

function custody(receipts) {
  return {
    async store({ receiptBytes, receiptSha256 }) {
      receipts.push(JSON.parse(receiptBytes.toString("utf8")));
      return {
        stored: true,
        encrypted: true,
        decryptVerified: true,
        custodySha256: "a".repeat(64),
        encryptedArtifactSha256: "b".repeat(64),
        decryptionProofSha256: "c".repeat(64),
        decryptedReceiptSha256: receiptSha256,
      };
    },
  };
}

function execution(value, cloudflare, receipts, dnsVerifier) {
  return {
    ...capsuleInput(value),
    cloudflareClient: cloudflare,
    resendClient: resendClient(),
    privateReceiptSink: custody(receipts),
    dnsVerifier,
    protectedExecution: {
      brokerRequestId: "55555555-5555-4555-8555-555555555555",
      capsuleRequestSha256: value.dnsStage.requestId,
      runId: "40000000001",
    },
    expectedBrokerRequestId: "55555555-5555-4555-8555-555555555555",
    now: () => now,
  };
}

test("validates the exact DNS-stage capsule and relative Resend names against the sending domain", () => {
  const input = capsuleInput();
  assert.equal(validateProductionDnsStageCapsule({ ...input, now }).targets.resend.domain.region, "eu-west-1");
});

test("proxied fallback records require Cloudflare automatic TTL", () => {
  const value = capsule();
  value.dnsStage.targets.cloudflare.dnsRecords[0].ttl = 300;
  value.dnsStage.requestId = digest({ application: value.application, controller: value.controller, createdAt: value.createdAt, providerCanary: value.dnsStage.providerCanary, safeguards: value.dnsStage.safeguards, targets: value.dnsStage.targets });
  assert.throws(
    () => validateProductionDnsStageCapsule({ ...capsuleInput(value), now }),
    /record is invalid/,
  );
});

test("fresh provider state creates only pending zone and exact DNS mirror with prior delegation intact", async () => {
  const value = capsule();
  const cloudflare = cloudflareClient();
  const receipts = [];
  const observedDelegations = [];
  const evidence = await executeProductionDnsStage(execution(value, cloudflare, receipts, async (input) => {
    observedDelegations.push(input.expectedNameServers);
    return { cloudflareVerified: true, googleVerified: true, dsNoData: true };
  }));
  assert.equal(evidence.result, "verified");
  assert.deepEqual(cloudflare.mutations, [
    "zone:create",
    "setting:always_use_https",
    "setting:min_tls_version",
    "setting:ssl",
    ...dnsRecords.map(() => "dns:create"),
  ]);
  assert.deepEqual(observedDelegations, [priorNameServers]);
  assert.equal(receipts[0].cloudflare.zoneStatus, "pending");
  assert.deepEqual(receipts[0].cloudflare.observedBeforeZoneSettings, {
    always_use_https: "off",
    min_tls_version: "1.0",
    ssl: "full",
  });
  assert.deepEqual(receipts[0].cloudflare.zoneSettings, {
    always_use_https: "on",
    min_tls_version: "1.2",
    ssl: "strict",
  });
  assert.deepEqual(receipts[0].registrar.priorNameServers, priorNameServers);
  assert.equal(receipts[0].resend.domainId, resendDomainId);
  assert.equal(receipts[0].resend.region, "eu-west-1");
  assert.ok(!JSON.stringify(evidence).includes("feedback-smtp"));
});

test("fresh DNS reconciliation accepts Cloudflare quoted and split TXT readback as exact logical content", async () => {
  const value = capsule();
  const cloudflare = cloudflareClient({ quotedTxt: true });
  const evidence = await executeProductionDnsStage(
    execution(value, cloudflare, [], async () => ({ cloudflareVerified: true, googleVerified: true, dsNoData: true })),
  );
  assert.equal(evidence.result, "verified");
  assert.equal(cloudflare.mutations.filter((item) => item === "dns:create").length, dnsRecords.length);
  const txtLookups = cloudflare.requests.filter(
    (input) => input.method === "GET" && input.query?.type === "TXT",
  );
  assert.ok(txtLookups.length >= 2);
  assert.ok(txtLookups.every((input) => !Object.hasOwn(input.query, "content.exact")));
});

test("Resend quoted and split TXT source values normalize to the exact logical DNS mirror", async () => {
  const value = capsule();
  const cloudflare = cloudflareClient();
  const evidence = await executeProductionDnsStage({
    ...execution(
      value,
      cloudflare,
      [],
      async () => ({ cloudflareVerified: true, googleVerified: true, dsNoData: true }),
    ),
    resendClient: resendClient({ quotedTxt: true }),
  });
  assert.equal(evidence.result, "verified");
});

test("active exact state issues a fresh read-only attestation and verifies assigned delegation", async () => {
  const value = capsule();
  value.dnsStage.targets.cloudflare.zone.id = zoneId;
  value.dnsStage.requestId = digest({ application: value.application, controller: value.controller, createdAt: value.createdAt, providerCanary: value.dnsStage.providerCanary, safeguards: value.dnsStage.safeguards, targets: value.dnsStage.targets });
  const cloudflare = cloudflareClient({ initialStatus: "active" });
  const receipts = [];
  await executeProductionDnsStage(execution(value, cloudflare, receipts, async ({ expectedNameServers }) => {
    assert.deepEqual(expectedNameServers, assignedNameServers);
    return { cloudflareVerified: true, googleVerified: true, dsNoData: true };
  }));
  assert.deepEqual(cloudflare.mutations, []);
  assert.equal(receipts[0].cloudflare.zoneStatus, "active");
});

test("active-zone security-setting drift fails closed without mutation", async () => {
  const value = capsule();
  value.dnsStage.targets.cloudflare.zone.id = zoneId;
  value.dnsStage.requestId = digest({ application: value.application, controller: value.controller, createdAt: value.createdAt, providerCanary: value.dnsStage.providerCanary, safeguards: value.dnsStage.safeguards, targets: value.dnsStage.targets });
  const cloudflare = cloudflareClient({ initialStatus: "active", zoneSettingOverrides: { ssl: "full" } });
  await assert.rejects(
    executeProductionDnsStage(execution(value, cloudflare, [], async () => ({ cloudflareVerified: true, googleVerified: true, dsNoData: true }))),
    /cloudflare-zone-settings-active-drift/,
  );
  assert.deepEqual(cloudflare.mutations, []);
});

test("duplicate fresh zone and mismatched Resend identity fail closed before mutation", async () => {
  const value = capsule();
  const duplicate = cloudflareClient({ initialStatus: "pending", duplicateZone: true });
  await assert.rejects(
    executeProductionDnsStage(execution(value, duplicate, [], async () => ({ cloudflareVerified: true, googleVerified: true, dsNoData: true }))),
    ProductionBootstrapAmbiguousError,
  );
  assert.deepEqual(duplicate.mutations, []);
  await assert.rejects(
    executeProductionDnsStage({ ...execution(value, cloudflareClient(), [], async () => ({ cloudflareVerified: true, googleVerified: true, dsNoData: true })), resendClient: resendClient({ region: "us-east-1" }) }),
    /Resend production domain identity differs/,
  );
});

test("unproven delegation blocks all DNS mutations", async () => {
  const value = capsule();
  const cloudflare = cloudflareClient();
  await assert.rejects(
    executeProductionDnsStage(execution(value, cloudflare, [], async () => ({ cloudflareVerified: false, googleVerified: true, dsNoData: true }))),
    /dns-delegation-drift/,
  );
  assert.deepEqual(cloudflare.mutations, [
    "zone:create",
    "setting:always_use_https",
    "setting:min_tls_version",
    "setting:ssl",
  ]);
});
