import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  executeProductionProviderBootstrap,
  productionProviderBootstrapConstants,
  ProductionBootstrapAmbiguousError,
  validateProductionBootstrapCapsule,
} from "../scripts/production-provider-bootstrap.mjs";
import {
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "../scripts/provider-adapter.mjs";

const adminIdentity = "owner-admin@example.net";
const accountId = "a".repeat(32);
const zoneId = "b".repeat(32);
const primaryId = "11111111-1111-4111-8111-111111111111";
const recoveryId = "22222222-2222-4222-8222-222222222222";
const identityProviderId = "66666666-6666-4666-8666-666666666666";
const applicationId = "33333333-3333-4333-8333-333333333333";
const policyId = "44444444-4444-4444-8444-444444444444";
const domainId = "domain_123";
const webhookId = "webhook_123";
const keyId = "key_123";
const fixedNow = new Date("2026-09-01T17:00:00.000Z");
const zoneNameServers = ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"];
const resendVerificationRecords = [
  { record: "DKIM", type: "TXT", name: "resend._domainkey.notify.freshtowels.gr", content: "p=synthetic-dkim", priority: null },
  { record: "SPF", type: "MX", name: "bounce.notify.freshtowels.gr", content: "feedback-smtp.eu-west-1.amazonses.com", priority: 10 },
  { record: "SPF", type: "TXT", name: "bounce.notify.freshtowels.gr", content: "v=spf1 include:amazonses.com ~all", priority: null },
];
const canonicalResendVerificationRecords = [...resendVerificationRecords].sort((left, right) =>
  canonicalJson(left).localeCompare(canonicalJson(right)),
);
const productionDnsRecords = [
  { id: null, type: "A", name: "freshtowels.gr", content: "192.0.2.10", ttl: 1, proxied: true, priority: null },
  { id: null, type: "CNAME", name: "www.freshtowels.gr", content: "freshtowels.gr", ttl: 1, proxied: true, priority: null },
  ...resendVerificationRecords.map((record) => ({ id: null, type: record.type, name: record.name, content: record.content, ttl: 300, proxied: false, priority: record.priority })),
];

function accessApplication(overrides = {}) {
  return {
    id: applicationId,
    aud: "access-audience_1234567890",
    name: "Fresh Towels Leads",
    domain: "freshtowels.gr/internal/leads",
    destinations: [
      { type: "public", uri: "freshtowels.gr/api/internal/*" },
      { type: "public", uri: "freshtowels.gr/internal/leads" },
      { type: "public", uri: "freshtowels.gr/internal/leads/*" },
    ],
    type: "self_hosted",
    session_duration: "8h",
    http_only_cookie_attribute: true,
    same_site_cookie_attribute: "strict",
    enable_binding_cookie: true,
    path_cookie_attribute: false,
    allow_iframe: false,
    allow_authenticate_via_warp: false,
    skip_interstitial: false,
    app_launcher_visible: false,
    options_preflight_bypass: false,
    allowed_idps: [identityProviderId],
    auto_redirect_to_identity: true,
    ...overrides,
  };
}

function targets(overrides = {}) {
  const value = {
    cloudflare: {
      accountId,
      zone: { id: zoneId, name: "freshtowels.gr", type: "full" },
      workerName: "fresh-towels-production",
      workersDevSubdomain: null,
      d1: {
        jurisdiction: "eu",
        primary: { id: primaryId, name: "fresh-towels-leads-prod" },
        recovery: { id: recoveryId, name: "fresh-towels-leads-prod-recovery" },
      },
      access: {
        organization: {
          name: "Fresh Towels",
          teamDomain: null,
          sessionDuration: "8h",
        },
        identityProvider: {
          id: identityProviderId,
          name: "Fresh Towels owner OTP",
          type: "onetimepin",
        },
        application: {
          id: applicationId,
          name: "Fresh Towels Leads",
          domain: "freshtowels.gr/internal/leads",
          destinations: [
            { type: "public", uri: "freshtowels.gr/api/internal/*" },
            { type: "public", uri: "freshtowels.gr/internal/leads" },
            { type: "public", uri: "freshtowels.gr/internal/leads/*" },
          ],
          type: "self_hosted",
          sessionDuration: "8h",
          httpOnlyCookieAttribute: true,
          sameSiteCookieAttribute: "strict",
          enableBindingCookie: true,
          pathCookieAttribute: false,
          allowIframe: false,
          allowAuthenticateViaWarp: false,
          skipInterstitial: false,
          optionsPreflightBypass: false,
          appLauncherVisible: false,
          autoRedirectToIdentity: true,
        },
        policy: {
          id: policyId,
          name: "Fresh Towels owner access",
          decision: "allow",
          precedence: 1,
          adminIdentitySha256: sha256(Buffer.from(adminIdentity)),
        },
      },
    },
    resend: {
      domain: { id: domainId, name: "notify.freshtowels.gr", region: "eu-west-1" },
      senderAddress: "notifications@notify.freshtowels.gr",
      webhook: {
        id: webhookId,
        endpoint: "https://freshtowels.gr/api/webhooks/resend",
        events: ["email.sent", "email.delivered", "email.bounced", "email.complained", "email.delivery_delayed", "email.failed", "email.suppressed"],
        secretBinding: "RESEND_WEBHOOK_SECRET",
      },
      sendingKey: {
        id: keyId,
        name: "Fresh Towels Production Worker",
        permission: "sending_access",
        secretBinding: "RESEND_API_KEY",
      },
    },
  };
  return Object.assign(value, overrides);
}

function capsule() {
  const value = {
    application: {
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1350923567",
      ref: "refs/heads/main",
      commitSha: "2".repeat(40),
      workflowRef:
        "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
      workflowSha: "2".repeat(40),
      runId: "39000000001",
      runAttempt: 1,
    },
    bootstrap: {
      requestId: "0".repeat(64),
      intent: "provision-production-identities-and-issue-credential-free-receipt",
      dnsStage: {
        requestId: "77777777-7777-4777-8777-777777777777",
        receiptSha256: "8".repeat(64),
        runId: "33524593667",
      },
      stableEvidence: {
        redirectCandidateEvidenceSha256: "9".repeat(64),
        privacyOperationsEvidenceSha256: "a".repeat(64),
        legacyWordPressRecoveryEvidenceSha256: "b".repeat(64),
      },
      targets: targets(),
      safeguards: {
        credentialsPresent: false,
        applicationBuildAuthorized: false,
        applicationArtifactPresent: false,
        productionTrafficMutationAuthorized: false,
        productionDnsMutationAuthorized: false,
        providerBootstrapMutationAuthorized: true,
      },
    },
    capsuleType: "fresh-towels-production-bootstrap-capsule",
    controller: {
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      commitSha: "3".repeat(40),
      workflowRef:
        "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@" +
        "3".repeat(40),
    },
    createdAt: "2026-09-01T16:59:00.000Z",
    operation: "production-bootstrap",
    schemaVersion: 1,
    validUntil: "2026-09-01T18:59:00.000Z",
  };
  value.bootstrap.requestId = digest({
    createdAt: value.createdAt,
    application: value.application,
    controller: value.controller,
    dnsStage: value.bootstrap.dnsStage,
    stableEvidence: value.bootstrap.stableEvidence,
    targets: value.bootstrap.targets,
  });
  return value;
}

function capsuleInput(value = capsule()) {
  const capsuleBytes = Buffer.from(canonicalJson(value) + "\n");
  return {
    capsule: value,
    capsuleBytes,
    expectedCapsuleSha256: sha256(capsuleBytes),
  };
}

function rebindCapsule(value) {
  value.bootstrap.requestId = digest({
    createdAt: value.createdAt,
    application: value.application,
    controller: value.controller,
    dnsStage: value.bootstrap.dnsStage,
    stableEvidence: value.bootstrap.stableEvidence,
    targets: value.bootstrap.targets,
  });
  return value;
}

function encryptedReceiptCustody(
  seed = "private-custody",
  decryptedReceiptSha256 = sha256(Buffer.from(seed + ":plaintext")),
) {
  return {
    stored: true,
    encrypted: true,
    decryptVerified: true,
    custodySha256: sha256(Buffer.from(seed + ":custody")),
    encryptedArtifactSha256: sha256(Buffer.from(seed + ":ciphertext")),
    decryptionProofSha256: sha256(Buffer.from(seed + ":round-trip")),
    decryptedReceiptSha256,
  };
}

function comparableDns(record) {
  return {
    type: record.type,
    name: record.name,
    content: record.content,
    ttl: record.ttl,
    proxied: record.proxied,
    priority: record.priority,
  };
}

function dnsStageReceiptBytes(value = capsule(), overrides = {}) {
  const inventory = productionDnsRecords
    .map(comparableDns)
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  const receipt = {
    schemaVersion: 1,
    receiptType: "fresh-towels-production-dns-stage",
    environment: "production",
    issuedAt: "2026-09-01T16:30:00.000Z",
    validUntil: "2026-09-02T16:30:00.000Z",
    application: {
      repository: value.application.repository,
      repositoryId: value.application.repositoryId,
      commitSha: value.application.commitSha,
    },
    controller: {
      repository: value.controller.repository,
      commitSha: value.controller.commitSha,
    },
    providerCanary: {
      requestId: "66666666-6666-4666-8666-666666666666",
      receiptSha256: "7".repeat(64),
      runId: "33524593667",
    },
    protectedExecution: {
      brokerRequestId: value.bootstrap.dnsStage.requestId,
      capsuleRequestSha256: "6".repeat(64),
      runId: value.bootstrap.dnsStage.runId,
    },
    cloudflare: {
      accountId,
      zoneId,
      zoneName: "freshtowels.gr",
      zoneStatus: "pending",
      nameServers: zoneNameServers,
      observedBeforeZoneSettings: { always_use_https: "off", min_tls_version: "1.0", ssl: "full" },
      zoneSettings: { always_use_https: "on", min_tls_version: "1.2", ssl: "strict" },
      dnsRecords: productionDnsRecords,
      dnsInventoryCount: inventory.length,
      dnsInventorySha256: digest(inventory),
    },
    registrar: { priorNameServers: ["ns355.grserver.gr", "ns356.grserver.gr"] },
    resend: {
      domainId,
      domainName: "notify.freshtowels.gr",
      region: "eu-west-1",
      verificationRecordsSha256: digest(canonicalResendVerificationRecords),
    },
    providerStateSha256: "8".repeat(64),
    ...overrides,
  };
  return Buffer.from(canonicalJson(receipt) + "\n");
}

function executionInput(value = capsule(), overrides = {}) {
  return {
    ...capsuleInput(value),
    adminIdentity,
    cloudflareClient: existingCloudflareClient(),
    resendClient: existingResendClient(),
    resendRuntimeClientFactory: () => ({
      async request() {
        throw new ProviderRejectedError(401, { providerErrorCode: "restricted_api_key" });
      },
    }),
    secretSink: existingSecretSink(),
    privateReceiptSink: {
      async store({ receiptSha256 }) {
        return encryptedReceiptCustody("private-custody", receiptSha256);
      },
    },
    dnsStageReceiptBytes: dnsStageReceiptBytes(value),
    dnsVerifier: async () => ({ cloudflareVerified: true, googleVerified: true, dsNoData: true }),
    wordpressFallbackVerifier: async () => ({ verified: true, proofSha256: "f".repeat(64) }),
    resendVerificationOptions: { attempts: 1, delay: async () => undefined },
    protectedExecution: {
      brokerRequestId: "55555555-5555-4555-8555-555555555555",
      capsuleRequestSha256: value.bootstrap.requestId,
      runId: "40000000001",
    },
    expectedBrokerRequestId: "55555555-5555-4555-8555-555555555555",
    now: () => fixedNow,
    ...overrides,
  };
}

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n"));
}

function response(result) {
  return {
    providerRequestId: null,
    status: 200,
    result,
    responseSha256: digest(result),
    pagination: { complete: true },
  };
}

function existingCloudflareClient({
  onRequest = () => undefined,
  extraAccessPolicy = null,
  applicationOverrides = {},
  identityProviderOverrides = {},
  organizationOverrides = {},
  zoneStatus = "active",
  zoneNameServerOverrides = zoneNameServers,
  dnsRecord = null,
  freshAccess = false,
} = {}) {
  let identityProviderExists = !freshAccess;
  let applicationExists = !freshAccess;
  let policyExists = !freshAccess;
  return {
    async request(input) {
      onRequest(input);
      const path = input.path;
      if (path === "/accounts/" + accountId) return response({ id: accountId });
      if (path === "/accounts/" + accountId + "/workers/subdomain") {
        return response({ subdomain: "fresh-towels-owner" });
      }
      if (path === "/zones") {
        return response([
          {
            id: zoneId,
            name: "freshtowels.gr",
            account: { id: accountId },
            type: "full",
            status: zoneStatus,
          },
        ]);
      }
      if (path === "/zones/" + zoneId) {
        return response({
          id: zoneId,
          name: "freshtowels.gr",
          account: { id: accountId },
          type: "full",
          status: zoneStatus,
          name_servers: zoneNameServerOverrides,
        });
      }
      if (path === "/zones/" + zoneId + "/settings/always_use_https") {
        return response({ id: "always_use_https", value: "on" });
      }
      if (path === "/zones/" + zoneId + "/settings/min_tls_version") {
        return response({ id: "min_tls_version", value: "1.2" });
      }
      if (path === "/zones/" + zoneId + "/settings/ssl") {
        return response({ id: "ssl", value: "strict" });
      }
      if (path === "/accounts/" + accountId + "/d1/database/" + primaryId) {
        return response({ uuid: primaryId, name: "fresh-towels-leads-prod", jurisdiction: "eu" });
      }
      if (path === "/accounts/" + accountId + "/d1/database/" + recoveryId) {
        return response({
          uuid: recoveryId,
          name: "fresh-towels-leads-prod-recovery",
          jurisdiction: "eu",
        });
      }
      if (path.endsWith("/access/organizations")) {
        return response({
          auth_domain: "fresh-towels.cloudflareaccess.com",
          name: "Fresh Towels",
          session_duration: "8h",
          ...organizationOverrides,
        });
      }
      if (path.endsWith("/access/identity_providers/" + identityProviderId)) {
        return response({
          id: identityProviderId,
          name: "Fresh Towels owner OTP",
          type: "onetimepin",
          ...identityProviderOverrides,
        });
      }
      if (path.endsWith("/access/identity_providers") && input.method === "GET") {
        return response(identityProviderExists ? [{
          id: identityProviderId,
          name: "Fresh Towels owner OTP",
          type: "onetimepin",
          ...identityProviderOverrides,
        }] : []);
      }
      if (path.endsWith("/access/identity_providers") && input.method === "POST") {
        identityProviderExists = true;
        return response({ id: identityProviderId });
      }
      if (path.endsWith("/access/apps") && input.method === "GET") {
        return response(applicationExists ? [accessApplication(applicationOverrides)] : []);
      }
      if (path.endsWith("/access/apps") && input.method === "POST") {
        applicationExists = true;
        return response({ id: applicationId });
      }
      if (path.endsWith("/access/apps/" + applicationId)) {
        return response(accessApplication(applicationOverrides));
      }
      if (path.endsWith("/access/apps/" + applicationId + "/policies")) {
        if (input.method === "POST") {
          policyExists = true;
          return response({ id: policyId });
        }
        return response(policyExists ? [
          {
            id: policyId,
            name: "Fresh Towels owner access",
            decision: "allow",
            precedence: 1,
            include: [{ email: { email: adminIdentity } }],
            exclude: [],
            require: [],
          },
          ...(extraAccessPolicy ? [extraAccessPolicy] : []),
        ] : []);
      }
      if (
        dnsRecord &&
        path === "/zones/" + zoneId + "/dns_records/" + dnsRecord.id &&
        input.method === "GET"
      ) {
        return response(dnsRecord);
      }
      if (path === "/zones/" + zoneId + "/dns_records" && input.method === "GET") {
        return response(dnsRecord ? [dnsRecord] : productionDnsRecords.map((record, index) => ({ ...record, id: String(index + 1).repeat(32).slice(0, 32) })));
      }
      throw new Error("Unexpected Cloudflare request: " + input.method + " " + path);
    },
  };
}

function existingResendClient({ onRequest = () => undefined, domainOverrides = {}, quotedTxt = false } = {}) {
  return {
    async request(input) {
      onRequest(input);
      if (input.path === "/domains") {
        return response({
          data: [{
            id: domainId,
            name: "notify.freshtowels.gr",
            region: "eu-west-1",
            status: "verified",
            capabilities: { sending: "enabled", receiving: "disabled" },
            ...domainOverrides,
          }],
        });
      }
      if (input.path === "/domains/" + domainId) {
        return response({
          id: domainId,
          name: "notify.freshtowels.gr",
          region: "eu-west-1",
          status: "verified",
          capabilities: { sending: "enabled", receiving: "disabled" },
          records: resendVerificationRecords.map((record) => ({
            record: record.record,
            type: record.type,
            name: record.name.replace(/\.freshtowels\.gr$/, ""),
            value:
              quotedTxt && record.type === "TXT"
                ? `"${record.content.slice(0, Math.max(1, Math.floor(record.content.length / 2)))}" "${record.content.slice(Math.max(1, Math.floor(record.content.length / 2)))}"`
                : record.content,
            priority: record.priority,
          })),
          ...domainOverrides,
        });
      }
      if (input.path === "/webhooks") {
        return response({
          data: [
            {
              id: webhookId,
              endpoint: "https://freshtowels.gr/api/webhooks/resend",
              events: ["email.sent", "email.delivered", "email.bounced", "email.complained", "email.delivery_delayed", "email.failed", "email.suppressed"],
              status: "enabled",
            },
          ],
        });
      }
      if (input.path === "/webhooks/" + webhookId && input.method === "GET") {
        return response({
          id: webhookId,
          endpoint: "https://freshtowels.gr/api/webhooks/resend",
          events: ["email.sent", "email.delivered", "email.bounced", "email.complained", "email.delivery_delayed", "email.failed", "email.suppressed"],
          status: "enabled",
          signing_secret: ["whsec", "synthetic", "existing", "secret", "value"].join("_"),
        });
      }
      if (input.path === "/api-keys") {
        return response({
          data: [
            {
              id: keyId,
              name: "Fresh Towels Production Worker",
            },
          ],
        });
      }
      throw new Error("Unexpected Resend request: " + input.method + " " + input.path);
    },
  };
}

function existingSecretSink() {
  return {
    async inspect({ binding, context }) {
      return {
        present: true,
        bindingVersionSha256: sha256(Buffer.from("version:" + binding)),
        resourceIdentitySha256: context.resourceIdentitySha256,
      };
    },
    async store() {
      throw new Error("Existing secret must not be rewritten");
    },
  };
}

function newSendingKeyHarness(
  value,
  token = ["re", "synthetic", "runtime", "delivery", "token", "value"].join("_"),
) {
  let keyPresent = false;
  let deleteCount = 0;
  const existing = existingResendClient();
  return {
    get deleteCount() {
      return deleteCount;
    },
    get keyPresent() {
      return keyPresent;
    },
    token,
    client: {
      async request(input) {
        if (input.path === "/api-keys" && input.method === "GET") {
          return response({
            data: keyPresent
              ? [{ id: keyId, name: value.bootstrap.targets.resend.sendingKey.name }]
              : [],
          });
        }
        if (input.path === "/api-keys" && input.method === "POST") {
          keyPresent = true;
          return response({ id: keyId, token });
        }
        if (input.path === "/api-keys/" + keyId && input.method === "DELETE") {
          deleteCount += 1;
          keyPresent = false;
          return response(null);
        }
        return existing.request(input);
      },
    },
  };
}

function newSendingKeySecretSink({ events = [], onStore = () => undefined } = {}) {
  let keyCustody = null;
  return {
    async inspect({ binding, context }) {
      if (
        binding === "RESEND_WEBHOOK_SECRET" ||
        binding === "DASHBOARD_AUTHORIZED_EMAILS" ||
        binding === "LEAD_RATE_LIMIT_SECRET"
      ) {
        return {
          present: true,
          bindingVersionSha256: sha256(Buffer.from("existing:" + binding)),
          resourceIdentitySha256: context.resourceIdentitySha256,
        };
      }
      return keyCustody
        ? {
            present: true,
            bindingVersionSha256: keyCustody.version,
            resourceIdentitySha256: keyCustody.resourceIdentitySha256,
          }
        : { present: false, bindingVersionSha256: null, resourceIdentitySha256: null };
    },
    async store(input) {
      events.push("custody-store");
      onStore(input);
      keyCustody = {
        version: sha256(Buffer.from("runtime-key-custody")),
        resourceIdentitySha256: input.context.resourceIdentitySha256,
      };
      return {
        bindingVersionSha256: keyCustody.version,
        resourceIdentitySha256: keyCustody.resourceIdentitySha256,
        stored: true,
      };
    },
  };
}

test("validates one exact short-lived pre-build bootstrap capsule", () => {
  const value = capsule();
  const validated = validateProductionBootstrapCapsule({
    ...capsuleInput(value),
    adminIdentity,
    now: fixedNow,
  });
  assert.equal(validated.requestId, value.bootstrap.requestId);
  assert.equal(validated.targets, value.bootstrap.targets);
  assert.equal(validated.dnsStage.requestId, "77777777-7777-4777-8777-777777777777");
});

test("rejects capsule substitution, stale prerequisites, admin drift, DNS overreach, and sender drift", () => {
  {
    const value = capsule();
    assert.throws(
      () =>
        validateProductionBootstrapCapsule({
          ...capsuleInput(value),
          expectedCapsuleSha256: "0".repeat(64),
          adminIdentity,
          now: fixedNow,
        }),
      /byte binding/,
    );
  }
  {
    const value = capsule();
    assert.throws(
      () =>
        validateProductionBootstrapCapsule({
          ...capsuleInput(value),
          adminIdentity: "different@example.net",
          now: fixedNow,
        }),
      /policy/,
    );
  }
  {
    const value = capsule();
    value.bootstrap.targets.cloudflare.dnsRecords = [
      {
        id: null,
        type: "TXT",
        name: "notify.freshtowels.gr",
        content: "public-verification-record",
        ttl: 300,
        proxied: false,
        priority: null,
      },
    ];
    rebindCapsule(value);
    assert.throws(
      () =>
        validateProductionBootstrapCapsule({
          ...capsuleInput(value),
          adminIdentity,
          now: fixedNow,
        }),
      /Cloudflare targets/,
    );
  }
  {
    const value = capsule();
    value.bootstrap.targets.resend.senderAddress = "notifications@freshtowels.gr";
    rebindCapsule(value);
    assert.throws(
      () =>
        validateProductionBootstrapCapsule({
          ...capsuleInput(value),
          adminIdentity,
          now: fixedNow,
        }),
      /Resend/,
    );
  }
  {
    const value = capsule();
    value.bootstrap.dnsStage.requestId = "not-a-uuid";
    rebindCapsule(value);
    assert.throws(
      () =>
        validateProductionBootstrapCapsule({
          ...capsuleInput(value),
          adminIdentity,
          now: fixedNow,
        }),
      /DNS-stage prerequisite/,
    );
  }
});

test("rejects any reviewed Access target that weakens exact coverage or browser-session controls", () => {
  for (const mutate of [
    (application) => {
      application.destinations = [{ type: "public", uri: "freshtowels.gr/internal/leads" }];
    },
    (application) => {
      application.httpOnlyCookieAttribute = false;
    },
    (application) => {
      application.sameSiteCookieAttribute = "lax";
    },
    (application) => {
      application.enableBindingCookie = false;
    },
    (application) => {
      application.autoRedirectToIdentity = false;
    },
  ]) {
    const value = capsule();
    mutate(value.bootstrap.targets.cloudflare.access.application);
    rebindCapsule(value);
    assert.throws(
      () =>
        validateProductionBootstrapCapsule({
          ...capsuleInput(value),
          adminIdentity,
          now: fixedNow,
        }),
      /Access application/,
    );
  }
});

test("existing exact provider state yields an encrypted private receipt and hash-only public evidence", async () => {
  const value = capsule();
  let privateReceipt;
  let receiptReference;
  const cloudflareMutations = [];
  const resendMutations = [];
  const evidence = await executeProductionProviderBootstrap(
    executionInput(value, {
      cloudflareClient: existingCloudflareClient({
        onRequest: (input) => {
          if (input.method !== "GET") cloudflareMutations.push(input);
        },
      }),
      resendClient: existingResendClient({
        onRequest: (input) => {
          if (input.method !== "GET") resendMutations.push(input);
        },
      }),
      privateReceiptSink: {
        async store({ receiptBytes, receiptSha256 }) {
          receiptReference = receiptBytes;
          privateReceipt = JSON.parse(Buffer.from(receiptBytes).toString("utf8"));
          assert.equal(sha256(receiptBytes), receiptSha256);
          return encryptedReceiptCustody("private-custody", receiptSha256);
        },
      },
    }),
  );
  assert.equal(cloudflareMutations.length, 0);
  assert.equal(resendMutations.length, 0);
  assert.equal(privateReceipt.receiptType, "fresh-towels-production-infrastructure-bootstrap");
  assert.equal(
    Date.parse(privateReceipt.validUntil) - Date.parse(privateReceipt.issuedAt),
    24 * 60 * 60 * 1000,
  );
  assert.deepEqual(privateReceipt.dnsStage, value.bootstrap.dnsStage);
  assert.deepEqual(privateReceipt.protectedExecution, {
    brokerRequestId: "55555555-5555-4555-8555-555555555555",
    capsuleRequestSha256: value.bootstrap.requestId,
    runId: "40000000001",
  });
  assert.equal(privateReceipt.cloudflare.workersDevSubdomain, "fresh-towels-owner");
  assert.equal(privateReceipt.cloudflare.zoneStatus, "active");
  assert.deepEqual(privateReceipt.cloudflare.nameServers, zoneNameServers);
  assert.equal(privateReceipt.verifiedState.cloudflareZoneActive, true);
  assert.equal(privateReceipt.cloudflare.d1.primary.databaseId, primaryId);
  assert.equal(privateReceipt.cloudflare.access.identityProviderId, identityProviderId);
  assert.equal(privateReceipt.cloudflare.access.identityProviderType, "onetimepin");
  assert.equal(privateReceipt.cloudflare.access.applicationDomain, "freshtowels.gr/internal/leads");
  assert.deepEqual(privateReceipt.cloudflare.access.allowedIdentityProviderIds, [identityProviderId]);
  assert.equal(privateReceipt.cloudflare.access.adminIdentitySha256, sha256(Buffer.from(adminIdentity)));
  assert.equal(privateReceipt.cloudflare.access.policyDecision, "allow");
  assert.equal(privateReceipt.cloudflare.access.policyPrecedence, 1);
  assert.equal(privateReceipt.cloudflare.access.extraPolicyCount, 0);
  assert.equal(privateReceipt.cloudflare.access.httpOnlyCookieAttribute, true);
  assert.equal(privateReceipt.cloudflare.access.sameSiteCookieAttribute, "strict");
  assert.equal(privateReceipt.cloudflare.access.enableBindingCookie, true);
  assert.equal(privateReceipt.cloudflare.access.pathCookieAttribute, false);
  assert.equal(privateReceipt.cloudflare.access.allowIframe, false);
  assert.equal(privateReceipt.cloudflare.access.allowAuthenticateViaWarp, false);
  assert.equal(privateReceipt.cloudflare.access.skipInterstitial, false);
  assert.equal(privateReceipt.cloudflare.access.optionsPreflightBypass, false);
  assert.equal(privateReceipt.cloudflare.access.appLauncherVisible, false);
  assert.equal(privateReceipt.cloudflare.access.autoRedirectToIdentity, true);
  assert.equal(privateReceipt.cloudflare.access.teamDomain, "https://fresh-towels.cloudflareaccess.com");
  assert.equal(privateReceipt.resend.domainId, domainId);
  assert.equal(privateReceipt.resend.domainStatus, "verified");
  assert.equal(privateReceipt.resend.sendingCapability, "enabled");
  assert.equal(privateReceipt.resend.senderAddress, "notifications@notify.freshtowels.gr");
  assert.equal(privateReceipt.resend.webhookId, webhookId);
  assert.equal(
    privateReceipt.resend.webhookEndpointSha256,
    sha256(Buffer.from("https://freshtowels.gr/api/webhooks/resend")),
  );
  assert.deepEqual(privateReceipt.resend.webhookEvents, [
    "email.bounced",
    "email.complained",
    "email.delivered",
    "email.delivery_delayed",
    "email.failed",
    "email.sent",
    "email.suppressed",
  ]);
  assert.equal(privateReceipt.resend.webhookStatus, "enabled");
  assert.equal(privateReceipt.resend.sendingKeyId, keyId);
  assert.equal(privateReceipt.resend.sendingKeyName, "Fresh Towels Production Worker");
  assert.deepEqual(
    Object.values(privateReceipt.runtimeSecrets).map((value) => value.binding).sort(),
    [
      "DASHBOARD_AUTHORIZED_EMAILS",
      "LEAD_RATE_LIMIT_SECRET",
      "RESEND_API_KEY",
      "RESEND_WEBHOOK_SECRET",
    ],
  );
  assert.ok(receiptReference.every((byte) => byte === 0));
  assert.equal(evidence.result, "verified");
  assert.match(evidence.encryptedCustodyProofSha256, /^[a-f0-9]{64}$/);
  const exposed = JSON.stringify(evidence);
  for (const forbidden of [
    adminIdentity,
    accountId,
    zoneId,
    primaryId,
    applicationId,
    "notifications@notify.freshtowels.gr",
  ]) {
    assert.ok(!exposed.includes(forbidden));
  }
});

test("incomplete provider pagination fails closed before a create decision", async () => {
  const value = capsule();
  value.bootstrap.targets.cloudflare.zone.id = null;
  rebindCapsule(value);
  let mutations = 0;
  const cloudflare = existingCloudflareClient();
  const original = cloudflare.request;
  cloudflare.request = async (input) => {
    const result = await original(input);
    if (input.path === "/zones") return { ...result, pagination: { complete: false } };
    if (input.method !== "GET") mutations += 1;
    return result;
  };
  await assert.rejects(
    executeProductionProviderBootstrap(executionInput(value, { cloudflareClient: cloudflare })),
    ProductionBootstrapAmbiguousError,
  );
  assert.equal(mutations, 0);
});

test("existing account-wide Access organization drift fails closed without update", async () => {
  const requests = [];
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(capsule(), {
        cloudflareClient: existingCloudflareClient({
          organizationOverrides: { name: "Unrelated account organization" },
          onRequest: (input) => requests.push(input),
        }),
      }),
    ),
    /cloudflare-access-organization-existing-drift/,
  );
  assert.equal(
    requests.some(
      (input) =>
        input.path.endsWith("/access/organizations") &&
        input.method !== "GET",
    ),
    false,
  );
});

test("Access binds the exact OTP provider and rejects application IdP substitution", async () => {
  const value = capsule();
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        cloudflareClient: existingCloudflareClient({
          applicationOverrides: {
            allowed_idps: ["77777777-7777-4777-8777-777777777777"],
          },
        }),
      }),
    ),
    /cloudflare-access-application:not-converged/,
  );
});

test("Access direct detail binds both protected destinations and every secure browser flag", async () => {
  const requests = [];
  let receipt;
  await executeProductionProviderBootstrap(
    executionInput(capsule(), {
      cloudflareClient: existingCloudflareClient({ onRequest: (input) => requests.push(input) }),
      privateReceiptSink: {
        async store({ receiptBytes, receiptSha256 }) {
          receipt = JSON.parse(Buffer.from(receiptBytes).toString("utf8"));
          return encryptedReceiptCustody("access-direct-detail", receiptSha256);
        },
      },
    }),
  );
  assert.ok(
    requests.some(
      (input) =>
        input.method === "GET" &&
        input.path.endsWith("/access/apps/" + applicationId),
    ),
  );
  assert.deepEqual(receipt.cloudflare.access.destinations, [
    { type: "public", uri: "freshtowels.gr/api/internal/*" },
    { type: "public", uri: "freshtowels.gr/internal/leads" },
    { type: "public", uri: "freshtowels.gr/internal/leads/*" },
  ]);

  for (const applicationOverrides of [
    { http_only_cookie_attribute: false },
    { same_site_cookie_attribute: "lax" },
    { enable_binding_cookie: false },
    { path_cookie_attribute: true },
    { allow_iframe: true },
    { allow_authenticate_via_warp: true },
    { skip_interstitial: true },
    { options_preflight_bypass: true },
    { app_launcher_visible: true },
    { auto_redirect_to_identity: false },
    { destinations: [{ type: "public", uri: "freshtowels.gr/internal/leads" }] },
  ]) {
    await assert.rejects(
      executeProductionProviderBootstrap(
        executionInput(capsule(), {
          cloudflareClient: existingCloudflareClient({ applicationOverrides }),
        }),
      ),
      /cloudflare-access-application:not-converged/,
    );
  }
});

test("zone inspection uses the exact endpoint and rejects non-canonical or duplicate nameservers", async () => {
  const requests = [];
  await executeProductionProviderBootstrap(
    executionInput(capsule(), {
      cloudflareClient: existingCloudflareClient({ onRequest: (input) => requests.push(input) }),
    }),
  );
  assert.ok(requests.some((input) => input.method === "GET" && input.path === "/zones/" + zoneId));
  assert.ok(!requests.some((input) => input.method === "GET" && input.path === "/zones"));

  for (const zoneNameServerOverrides of [
    ["ada.ns.cloudflare.com"],
    ["ada.ns.cloudflare.com", "ada.ns.cloudflare.com"],
    ["Ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
    ["ada.example.net", "bob.ns.cloudflare.com"],
  ]) {
    await assert.rejects(
      executeProductionProviderBootstrap(
        executionInput(capsule(), {
          cloudflareClient: existingCloudflareClient({ zoneNameServerOverrides }),
        }),
      ),
      /Cloudflare zone nameserver identity is invalid/,
    );
  }
});

test("Access discovers the exact OTP provider when its reviewed target has no provider ID", async () => {
  const value = capsule();
  value.bootstrap.targets.cloudflare.access.identityProvider.id = null;
  rebindCapsule(value);
  const requests = [];
  await executeProductionProviderBootstrap(
    executionInput(value, {
      cloudflareClient: existingCloudflareClient({
        onRequest: (input) => requests.push(input),
      }),
    }),
  );
  const discovery = requests.find(
    (input) => input.path.endsWith("/access/identity_providers") && input.method === "GET",
  );
  assert.deepEqual(discovery.query, { page: "1", per_page: "1000" });
  assert.ok(!requests.some(
    (input) => input.path.endsWith("/access/identity_providers") && input.method === "POST",
  ));
});

test("Access same-name identity-provider type collision fails closed without creating a duplicate", async () => {
  const value = capsule();
  value.bootstrap.targets.cloudflare.access.identityProvider.id = null;
  rebindCapsule(value);
  const requests = [];
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        cloudflareClient: existingCloudflareClient({
          identityProviderOverrides: { type: "google" },
          onRequest: (input) => requests.push(input),
        }),
      }),
    ),
    /cloudflare-access-identity-provider:not-converged/,
  );
  assert.equal(
    requests.some(
      (input) =>
        input.path.endsWith("/access/identity_providers") &&
        input.method === "POST",
    ),
    false,
  );
});

test("an absent Access IdP, application, and policy are created once then exactly read back", async () => {
  const value = capsule();
  value.bootstrap.targets.cloudflare.access.identityProvider.id = null;
  value.bootstrap.targets.cloudflare.access.application.id = null;
  value.bootstrap.targets.cloudflare.access.policy.id = null;
  rebindCapsule(value);
  const mutations = [];
  await executeProductionProviderBootstrap(
    executionInput(value, {
      cloudflareClient: existingCloudflareClient({
        freshAccess: true,
        onRequest: (input) => {
          if (input.method !== "GET") mutations.push(input.path);
        },
      }),
    }),
  );
  assert.deepEqual(mutations, [
    "/accounts/" + accountId + "/access/identity_providers",
    "/accounts/" + accountId + "/access/apps",
    "/accounts/" + accountId + "/access/apps/" + applicationId + "/policies",
  ]);
});

test("pending Cloudflare zone identity is explicit and is not reported traffic-ready", async () => {
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(capsule(), {
        cloudflareClient: existingCloudflareClient({ zoneStatus: "pending" }),
      }),
    ),
    /cloudflare-zone-not-active/,
  );
});

test("Resend domain without sending capability fails before D1 or Access mutation", async () => {
  let cloudflareMutations = 0;
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(capsule(), {
        cloudflareClient: {
          async request(input) {
            if (input.method !== "GET") cloudflareMutations += 1;
            return existingCloudflareClient().request(input);
          },
        },
        resendClient: existingResendClient({
          domainOverrides: {
            capabilities: { sending: "disabled", receiving: "disabled" },
          },
        }),
      }),
    ),
    /resend-domain-not-verified/,
  );
  assert.equal(cloudflareMutations, 0);
});

test("bootstrap accepts quoted and split Resend TXT readback only after exact logical normalization", async () => {
  const evidence = await executeProductionProviderBootstrap(
    executionInput(capsule(), {
      resendClient: existingResendClient({ quotedTxt: true }),
    }),
  );
  assert.equal(evidence.result, "verified");
});

test("DNS-stage receipt drift cannot masquerade as exact active DNS", async () => {
  const value = capsule();
  const record = {
    id: "c".repeat(32),
    type: "TXT",
    name: "notify.freshtowels.gr",
    content: "provider-verification-value",
    ttl: 300,
    proxied: false,
    priority: null,
  };
  const requests = [];
  await executeProductionProviderBootstrap(
    executionInput(value, {
      cloudflareClient: existingCloudflareClient({
        dnsRecord: { ...record, content: "drifted-provider-value" },
        onRequest: (input) => requests.push(input),
      }),
    }),
  ).then(
    () => assert.fail("drifted immutable fixture must not converge"),
    (error) => assert.match(error.message, /cloudflare-dns-inventory-drift/),
  );
  assert.ok(requests.some((input) => input.method === "GET" && input.path.endsWith("/dns_records")));
  assert.ok(!requests.some((input) => input.method !== "GET"));
});

for (const decision of ["bypass", "non_identity", "deny"]) {
  test(`an additional ${decision} Access policy fails closed`, async () => {
    const value = capsule();
    await assert.rejects(
      executeProductionProviderBootstrap(
        executionInput(value, {
          cloudflareClient: existingCloudflareClient({
            extraAccessPolicy: {
              id: "77777777-7777-4777-8777-777777777777",
              name: `unexpected ${decision} policy`,
              decision,
              precedence: 2,
              include: [{ everyone: {} }],
              exclude: [],
              require: [],
            },
          }),
        }),
      ),
      /cloudflare-access-policy:inspect/,
    );
  });
}

test("empty reviewed DNS plan performs only one bounded full-inventory read and no mutation", async () => {
  const value = capsule();
  const requests = [];
  await executeProductionProviderBootstrap(
    executionInput(value, {
      cloudflareClient: existingCloudflareClient({
        onRequest: (input) => requests.push({ method: input.method, path: input.path, query: input.query }),
      }),
    }),
  );
  assert.deepEqual(requests.filter((item) => item.path.includes("/dns_records")), [
    {
      method: "GET",
      path: "/zones/" + zoneId + "/dns_records",
      query: { page: "1", per_page: "10000" },
    },
  ]);
});

test("new one-time Resend secrets transfer directly to custody and buffers are zeroed", async () => {
  const value = capsule();
  value.bootstrap.targets.resend.webhook.id = null;
  value.bootstrap.targets.resend.sendingKey.id = null;
  rebindCapsule(value);
  const target = value.bootstrap.targets.resend;
  const secretState = new Map();
  const references = [];
  const webhookSecret = ["whsec", "synthetic", "one", "time", "value"].join("_");
  const resend = {
    async request(input) {
      if (input.path === "/domains/" + domainId) {
        return existingResendClient().request(input);
      }
      if (input.path === "/domains") {
        return response({ data: [{
          id: domainId,
          name: target.domain.name,
          status: "verified",
          capabilities: { sending: "enabled", receiving: "disabled" },
        }] });
      }
      if (input.path === "/webhooks" && input.method === "GET") {
        return response({
          data: secretState.has("RESEND_WEBHOOK_SECRET")
            ? [{ id: webhookId, endpoint: target.webhook.endpoint, events: target.webhook.events, status: "enabled" }]
            : [],
        });
      }
      if (input.path === "/webhooks" && input.method === "POST") {
        return response({
          id: webhookId,
          signing_secret: webhookSecret,
        });
      }
      if (input.path === "/webhooks/" + webhookId && input.method === "GET") {
        return response({
          id: webhookId,
          endpoint: target.webhook.endpoint,
          events: target.webhook.events,
          status: "enabled",
          signing_secret: webhookSecret,
        });
      }
      if (input.path === "/api-keys" && input.method === "GET") {
        return response({
          data: secretState.has("RESEND_API_KEY")
            ? [{ id: keyId, name: target.sendingKey.name }]
            : [],
        });
      }
      if (input.path === "/api-keys" && input.method === "POST") {
        return response({
          id: keyId,
          token: ["re", "synthetic", "one", "time", "delivery", "token"].join("_"),
        });
      }
      throw new Error("Unexpected request " + input.method + " " + input.path);
    },
  };
  const secretSink = {
    async inspect({ binding }) {
      return secretState.has(binding)
        ? {
            present: true,
            bindingVersionSha256: secretState.get(binding).version,
            resourceIdentitySha256: secretState.get(binding).resourceIdentitySha256,
          }
        : { present: false, bindingVersionSha256: null, resourceIdentitySha256: null };
    },
    async store({ binding, secretBytes, secretSha256, context }) {
      assert.equal(sha256(secretBytes), secretSha256);
      references.push(secretBytes);
      const version = sha256(Buffer.from("stored:" + binding));
      secretState.set(binding, {
        version,
        resourceIdentitySha256: context.resourceIdentitySha256,
      });
      return {
        stored: true,
        bindingVersionSha256: version,
        resourceIdentitySha256: context.resourceIdentitySha256,
      };
    },
  };
  const evidence = await executeProductionProviderBootstrap(
    executionInput(value, { resendClient: resend, secretSink }),
  );
  assert.equal(secretState.size, 4);
  assert.deepEqual([...secretState.keys()].sort(), [
    "DASHBOARD_AUTHORIZED_EMAILS",
    "LEAD_RATE_LIMIT_SECRET",
    "RESEND_API_KEY",
    "RESEND_WEBHOOK_SECRET",
  ]);
  assert.ok(references.every((bytes) => bytes.every((byte) => byte === 0)));
  assert.ok(!JSON.stringify(evidence).includes("synthetic_one_time"));
  assert.ok(!JSON.stringify(evidence).includes(adminIdentity));
});

test("a new Resend sending token is denied management access before custody and binds the proof digest", async () => {
  const value = capsule();
  value.bootstrap.targets.resend.sendingKey.id = null;
  rebindCapsule(value);
  const events = [];
  const harness = newSendingKeyHarness(value);
  let keyCustodyContext = null;
  let privateReceipt = null;
  let probeCount = 0;
  const secretSink = newSendingKeySecretSink({
    events,
    onStore(input) {
      keyCustodyContext = input.context;
      assert.equal(Buffer.from(input.secretBytes).toString("utf8"), harness.token);
    },
  });
  const result = await executeProductionProviderBootstrap(
    executionInput(value, {
      resendClient: {
        async request(input) {
          if (input.path === "/api-keys" && input.method === "POST") {
            events.push("key-created");
          }
          return harness.client.request(input);
        },
      },
      resendRuntimeClientFactory(token) {
        assert.equal(token, harness.token);
        return {
          async request(input) {
            events.push("runtime-management-probe");
            probeCount += 1;
            assert.equal(input.method, "GET");
            assert.equal(input.path, "/api-keys");
            assert.deepEqual(input.query, { limit: "100" });
            throw new ProviderRejectedError(401, {
              providerErrorCode: "restricted_api_key",
            });
          },
        };
      },
      secretSink,
      privateReceiptSink: {
        async store({ receiptBytes, receiptSha256 }) {
          privateReceipt = JSON.parse(Buffer.from(receiptBytes).toString("utf8"));
          return encryptedReceiptCustody("least-privilege-receipt", receiptSha256);
        },
      },
    }),
  );
  const probeSha256 =
    productionProviderBootstrapConstants.resendSendingKeyLeastPrivilegeProbeSha256;
  const expectedResourceIdentitySha256 = digest({
    provider: "resend",
    resource: "sending-key",
    id: keyId,
    name: value.bootstrap.targets.resend.sendingKey.name,
    leastPrivilegeProbeSha256: probeSha256,
    provisioningIntentSha256: digest({
      permission: "sending_access",
      domainId,
    }),
  });
  assert.deepEqual(events.slice(0, 3), [
    "key-created",
    "runtime-management-probe",
    "custody-store",
  ]);
  assert.equal(probeCount, 1);
  assert.equal(harness.deleteCount, 0);
  assert.equal(harness.keyPresent, true);
  assert.equal(keyCustodyContext.resourceIdentitySha256, expectedResourceIdentitySha256);
  assert.equal(privateReceipt.resend.sendingKeyLeastPrivilegeProbeSha256, probeSha256);
  assert.ok(!JSON.stringify(result).includes(harness.token));
  assert.ok(!JSON.stringify(privateReceipt).includes(harness.token));
});

test("an overprivileged new Resend runtime token is revoked before custody", async () => {
  const value = capsule();
  value.bootstrap.targets.resend.sendingKey.id = null;
  rebindCapsule(value);
  const harness = newSendingKeyHarness(value);
  let custodyStoreCount = 0;
  const secretSink = newSendingKeySecretSink({
    onStore() {
      custodyStoreCount += 1;
    },
  });
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        resendClient: harness.client,
        resendRuntimeClientFactory: () => ({
          async request() {
            return response({ data: [] });
          },
        }),
        secretSink,
      }),
    ),
    ProductionBootstrapAmbiguousError,
  );
  assert.equal(custodyStoreCount, 0);
  assert.equal(harness.deleteCount, 1);
  assert.equal(harness.keyPresent, false);
});

test("an ambiguous Resend least-privilege probe is revoked and never retried", async () => {
  const value = capsule();
  value.bootstrap.targets.resend.sendingKey.id = null;
  rebindCapsule(value);
  const harness = newSendingKeyHarness(value);
  let probeCount = 0;
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        resendClient: harness.client,
        resendRuntimeClientFactory: () => ({
          async request() {
            probeCount += 1;
            throw new ProviderTransportAmbiguousError("synthetic-timeout");
          },
        }),
        secretSink: newSendingKeySecretSink(),
      }),
    ),
    ProductionBootstrapAmbiguousError,
  );
  assert.equal(probeCount, 1);
  assert.equal(harness.deleteCount, 1);
  assert.equal(harness.keyPresent, false);
});

test("an unexpected Resend management rejection is revoked rather than accepted as least privilege", async () => {
  for (const rejection of [
    new ProviderRejectedError(400),
    new ProviderRejectedError(403, { providerErrorCode: "invalid_api_key" }),
    new ProviderRejectedError(401),
    new ProviderRejectedError(401, { providerErrorCode: "invalid_api_key" }),
  ]) {
    const value = capsule();
    value.bootstrap.targets.resend.sendingKey.id = null;
    rebindCapsule(value);
    const harness = newSendingKeyHarness(value);
    await assert.rejects(
      executeProductionProviderBootstrap(
        executionInput(value, {
          resendClient: harness.client,
          resendRuntimeClientFactory: () => ({
            async request() {
              throw rejection;
            },
          }),
          secretSink: newSendingKeySecretSink(),
        }),
      ),
      ProductionBootstrapAmbiguousError,
    );
    assert.equal(harness.deleteCount, 1);
    assert.equal(harness.keyPresent, false);
  }
});

test("a newly-created Resend API key is revoked when protected custody fails", async () => {
  const value = capsule();
  value.bootstrap.targets.resend.sendingKey.id = null;
  rebindCapsule(value);
  let keyPresent = false;
  let deleteCount = 0;
  const existing = existingResendClient();
  const resend = {
    async request(input) {
      if (input.path === "/api-keys" && input.method === "GET") {
        return response({
          data: keyPresent ? [{ id: keyId, name: value.bootstrap.targets.resend.sendingKey.name }] : [],
        });
      }
      if (input.path === "/api-keys" && input.method === "POST") {
        keyPresent = true;
        return response({ id: keyId, token: ["re", "synthetic", "orphan", "token", "value"].join("_") });
      }
      if (input.path === "/api-keys/" + keyId && input.method === "DELETE") {
        deleteCount += 1;
        keyPresent = false;
        return response(null);
      }
      return existing.request(input);
    },
  };
  const secretSink = {
    async inspect({ binding, context }) {
      return binding === "RESEND_WEBHOOK_SECRET"
        ? {
            present: true,
            bindingVersionSha256: sha256(Buffer.from("existing-webhook")),
            resourceIdentitySha256: context.resourceIdentitySha256,
          }
        : { present: false, bindingVersionSha256: null, resourceIdentitySha256: null };
    },
    async store() {
      throw new Error("synthetic custody failure");
    },
  };
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, { resendClient: resend, secretSink }),
    ),
    ProductionBootstrapAmbiguousError,
  );
  assert.equal(deleteCount, 1);
  assert.equal(keyPresent, false);
});

test("a newly-created Resend webhook is removed when protected custody fails", async () => {
  const value = capsule();
  value.bootstrap.targets.resend.webhook.id = null;
  rebindCapsule(value);
  let webhookPresent = false;
  let deleteCount = 0;
  const secret = ["whsec", "synthetic", "orphan", "secret", "value"].join("_");
  const resend = {
    async request(input) {
      if (input.path === "/domains/" + domainId) {
        return existingResendClient().request(input);
      }
      if (input.path === "/domains") {
        return response({ data: [{
          id: domainId,
          name: "notify.freshtowels.gr",
          status: "verified",
          capabilities: { sending: "enabled", receiving: "disabled" },
        }] });
      }
      if (input.path === "/webhooks" && input.method === "GET") {
        return response({
          data: webhookPresent
            ? [{ id: webhookId, endpoint: value.bootstrap.targets.resend.webhook.endpoint, events: value.bootstrap.targets.resend.webhook.events, status: "enabled" }]
            : [],
        });
      }
      if (input.path === "/webhooks" && input.method === "POST") {
        webhookPresent = true;
        return response({ id: webhookId, signing_secret: secret });
      }
      if (input.path === "/webhooks/" + webhookId && input.method === "GET") {
        return response({
          id: webhookId,
          endpoint: value.bootstrap.targets.resend.webhook.endpoint,
          events: value.bootstrap.targets.resend.webhook.events,
          status: "enabled",
          signing_secret: secret,
        });
      }
      if (input.path === "/webhooks/" + webhookId && input.method === "DELETE") {
        deleteCount += 1;
        webhookPresent = false;
        return response({ id: webhookId, deleted: true });
      }
      throw new Error("Unexpected request " + input.method + " " + input.path);
    },
  };
  const secretSink = {
    async inspect() {
      return { present: false, bindingVersionSha256: null, resourceIdentitySha256: null };
    },
    async store() {
      throw new Error("synthetic custody failure");
    },
  };
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, { resendClient: resend, secretSink }),
    ),
    ProductionBootstrapAmbiguousError,
  );
  assert.equal(deleteCount, 1);
  assert.equal(webhookPresent, false);
});

test("ambiguous D1 create is reconciled once and never blindly retried", async () => {
  const value = capsule();
  value.bootstrap.targets.cloudflare.d1.primary.id = null;
  rebindCapsule(value);
  let creates = 0;
  const cloudflare = existingCloudflareClient();
  const original = cloudflare.request;
  cloudflare.request = async (input) => {
    if (input.path.endsWith("/d1/database") && input.method === "GET") return response([]);
    if (input.path.endsWith("/d1/database") && input.method === "POST") {
      creates += 1;
      throw new ProviderTransportAmbiguousError("timeout");
    }
    return original(input);
  };
  await assert.rejects(
    executeProductionProviderBootstrap(executionInput(value, { cloudflareClient: cloudflare })),
    ProductionBootstrapAmbiguousError,
  );
  assert.equal(creates, 1);
});

test("existing one-time provider resource without secret custody fails closed", async () => {
  const value = capsule();
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        secretSink: {
          async inspect() {
            return {
              present: false,
              bindingVersionSha256: null,
              resourceIdentitySha256: null,
            };
          },
          async store() {
            throw new Error("must not rotate");
          },
        },
      }),
    ),
    ProductionBootstrapAmbiguousError,
  );
});

test("a stored Resend secret bound to another provider resource is rejected", async () => {
  const value = capsule();
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        secretSink: {
          async inspect() {
            return {
              present: true,
              bindingVersionSha256: "c".repeat(64),
              resourceIdentitySha256: "d".repeat(64),
            };
          },
          async store() {
            throw new Error("must not overwrite mismatched custody");
          },
        },
      }),
    ),
    ProductionBootstrapAmbiguousError,
  );
});

test("terminal success requires encrypted custody and a confirmed decrypt proof", async () => {
  const value = capsule();
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        privateReceiptSink: {
          async store({ receiptSha256 }) {
            return {
              ...encryptedReceiptCustody("private-custody", receiptSha256),
              decryptVerified: false,
            };
          },
        },
      }),
    ),
    /custody was not confirmed/,
  );
});

test("protected execution provenance binds the exact dispatcher request", async () => {
  const value = capsule();
  await assert.rejects(
    executeProductionProviderBootstrap(
      executionInput(value, {
        protectedExecution: {
          brokerRequestId: "66666666-6666-4666-8666-666666666666",
          capsuleRequestSha256: value.bootstrap.requestId,
          runId: "40000000001",
        },
      }),
    ),
    /provenance/,
  );
});
