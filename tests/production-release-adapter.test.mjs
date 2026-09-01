import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import { productionDeploymentPlaceholders } from "../scripts/production-capsule.mjs";
import {
  executeProductionReleaseAdapter,
  hydrateProductionConfiguration,
  validateProductionInfrastructureReceipt,
} from "../scripts/production-release-adapter.mjs";

const digest = (value) => sha256(Buffer.from(value));
const canonicalDigest = (value) =>
  sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
const d = (character) => character.repeat(64);
const appSha = "a".repeat(40);
const controllerSha = "b".repeat(40);
const primaryId = "11111111-1111-4111-8111-111111111111";
const recoveryId = "22222222-2222-4222-8222-222222222222";
const workerVersionId = "33333333-3333-4333-8333-333333333333";
const adminEmail = "owner-admin@example.net";
const expectedSchemaSha256 = d("9");

function exactTemplate(receiptSha256) {
  return {
    name: "fresh-towels-production",
    account_id: productionDeploymentPlaceholders.accountId,
    main: "./worker/index.js",
    compatibility_date: "2026-08-28",
    compatibility_flags: ["nodejs_compat"],
    vars: {
      CLOUDFLARE_ACCESS_AUD: productionDeploymentPlaceholders.accessAudience,
      CLOUDFLARE_ACCESS_TEAM_DOMAIN: productionDeploymentPlaceholders.accessTeamDomain,
      PRODUCTION_INFRASTRUCTURE_RECEIPT_SHA256: receiptSha256,
      PRODUCTION_VERSION_PREVIEW_URL_SUFFIX: productionDeploymentPlaceholders.previewSuffix,
    },
    d1_databases: [
      {
        binding: "LEADS_DB",
        database_id: productionDeploymentPlaceholders.databaseId,
      },
    ],
    assets: {
      directory: "./assets",
      run_worker_first: ["/api/leads"],
    },
  };
}

function runtimeSecretRecord(binding, value, seed) {
  const bytes = Buffer.from(value, "utf8");
  return {
    bindingVersionSha256: d(seed),
    bytes,
    custodySha256: d(String((Number(seed) + 1) % 10)),
    payloadKind: "secret",
    plaintextSha256: sha256(bytes),
    resourceIdentitySha256: d(String((Number(seed) + 2) % 10)),
  };
}

function runtimeSecrets() {
  return {
    DASHBOARD_AUTHORIZED_EMAILS: runtimeSecretRecord(
      "DASHBOARD_AUTHORIZED_EMAILS",
      adminEmail,
      "1",
    ),
    LEAD_RATE_LIMIT_SECRET: runtimeSecretRecord(
      "LEAD_RATE_LIMIT_SECRET",
      "T8s!R2q#P9m$V4x@N7c%K6z&H3w*D5j+",
      "2",
    ),
    RESEND_API_KEY: runtimeSecretRecord(
      "RESEND_API_KEY",
      ["re", "1234567890abcdefghijklmno"].join("_"),
      "3",
    ),
    RESEND_WEBHOOK_SECRET: runtimeSecretRecord(
      "RESEND_WEBHOOK_SECRET",
      ["whsec", "MTIzNDU2Nzg5MGFiY2RlZg"].join("_"),
      "4",
    ),
  };
}

function custodyMetadata(secrets) {
  const metadata = {};
  for (const [binding, value] of Object.entries(secrets)) {
    metadata[binding] = {
      binding,
      bindingVersionSha256: value.bindingVersionSha256,
      resourceIdentitySha256: value.resourceIdentitySha256,
    };
  }
  return {
    dashboardAuthorizedEmails: metadata.DASHBOARD_AUTHORIZED_EMAILS,
    leadRateLimitSecret: metadata.LEAD_RATE_LIMIT_SECRET,
    resendApiKey: metadata.RESEND_API_KEY,
    resendWebhookSecret: metadata.RESEND_WEBHOOK_SECRET,
  };
}

function receipt(secrets, overrides = {}) {
  const issuedAt = "2026-09-01T08:00:00.000Z";
  const base = {
    schemaVersion: 1,
    receiptType: "fresh-towels-production-infrastructure-bootstrap",
    environment: "production",
    issuedAt,
    validUntil: "2026-09-02T08:00:00.000Z",
    application: {
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1350923567",
      commitSha: appSha,
    },
    controller: {
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      commitSha: controllerSha,
    },
    providerCanary: {
      requestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      receiptSha256: d("a"),
      runId: "33524593667",
    },
    protectedExecution: {
      brokerRequestId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      capsuleRequestSha256: d("b"),
      runId: "33524593668",
    },
    verifiedState: {
      cloudflareTargetVerified: true,
      cloudflareZoneActive: true,
      d1TargetsVerified: true,
      accessConfigurationVerified: true,
      resendDomainVerified: true,
      resendWebhookVerified: true,
    },
    stableEvidence: {
      redirectCandidateEvidenceSha256: d("c"),
      privacyOperationsEvidenceSha256: d("d"),
      legacyWordPressRecoveryEvidenceSha256: d("e"),
    },
    cloudflare: {
      accountId: "1".repeat(32),
      zoneId: "2".repeat(32),
      zoneName: "freshtowels.gr",
      zoneStatus: "active",
      nameServers: ["anna.ns.cloudflare.com", "nick.ns.cloudflare.com"],
      zoneSettings: { always_use_https: "on", min_tls_version: "1.2", ssl: "strict" },
      dnsInventoryCount: 0,
      dnsInventorySha256: d("0"),
      workerName: "fresh-towels-production",
      workersDevSubdomain: "fresh-towels-account",
      d1: {
        jurisdiction: "eu",
        primary: { databaseName: "fresh-towels-leads-prod", databaseId: primaryId },
        recovery: {
          databaseName: "fresh-towels-leads-prod-recovery",
          databaseId: recoveryId,
        },
      },
      access: {
        identityProviderId: "44444444-4444-4444-8444-444444444444",
        identityProviderType: "onetimepin",
        applicationId: "55555555-5555-4555-8555-555555555555",
        applicationDomain: "freshtowels.gr/internal/leads",
        policyId: "66666666-6666-4666-8666-666666666666",
        aud: "ABCDEFGHIJKLMNOPQRSTUVWX",
        destinations: [
          { type: "public", uri: "freshtowels.gr/api/internal/*" },
          { type: "public", uri: "freshtowels.gr/internal/leads" },
          { type: "public", uri: "freshtowels.gr/internal/leads/*" },
        ],
        allowedIdentityProviderIds: ["44444444-4444-4444-8444-444444444444"],
        adminIdentitySha256: digest(adminEmail),
        policyDecision: "allow",
        policyPrecedence: 1,
        extraPolicyCount: 0,
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
        teamDomain: "https://fresh-towels.cloudflareaccess.com",
        organizationSessionDuration: "8h",
        applicationSessionDuration: "8h",
      },
    },
    resend: {
      domain: "notify.freshtowels.gr",
      domainId: "resend-domain-id",
      domainStatus: "verified",
      sendingCapability: "enabled",
      senderAddress: "notifications@notify.freshtowels.gr",
      webhookId: "resend-webhook-id",
      webhookEndpointSha256: digest("https://freshtowels.gr/api/webhooks/resend"),
      webhookEvents: ["email.bounced", "email.complained", "email.delivered", "email.delivery_delayed", "email.failed", "email.sent", "email.suppressed"],
      webhookStatus: "enabled",
      sendingKeyId: "resend-sending-key-id",
      sendingKeyName: "Fresh Towels Production Worker",
      sendingKeyLeastPrivilegeProbeSha256: d("f"),
    },
    runtimeSecrets: custodyMetadata(secrets),
  };
  return Object.assign(base, overrides);
}

function materialized(root, receiptSha256) {
  return {
    root,
    release: {
      releaseId: d("7"),
      applicationCommitSha: appSha,
      controllerCommitSha: controllerSha,
      buildArtifactSha256: d("1"),
      uploadArtifactSha256: d("2"),
      productionInfrastructureReceiptSha256: receiptSha256,
    },
    manifest: {
      databasePayloadTreeSha256: d("3"),
      workerModuleSha256: d("a"),
      staticAssetsTreeSha256: d("b"),
    },
    database: { currentLeadSchemaVersion: 2 },
    configurationTemplate: {
      workerName: "fresh-towels-production",
      databaseName: "fresh-towels-leads-prod",
      productionInfrastructureReceiptSha256: receiptSha256,
      template: exactTemplate(receiptSha256),
    },
    files: [
      { path: "migrations/0001_leads.sql", bytes: 10, sha256: d("4") },
      { path: "migrations/0002_status.sql", bytes: 20, sha256: d("5") },
      { path: "assets/index.html", bytes: 30, sha256: d("6") },
    ],
  };
}

function databaseState(database, appliedMigrations = [], schemaSha256 = d("0")) {
  return {
    databaseId: database.databaseId,
    databaseName: database.databaseName,
    jurisdiction: "eu",
    appliedMigrations,
    schemaVersion: appliedMigrations.length,
    schemaSha256,
    leadCount: 0,
  };
}

function fakeAdapter(infrastructure, options = {}) {
  const calls = [];
  const migrations = [
    { version: 1, name: "0001_leads.sql" },
    { version: 2, name: "0002_status.sql" },
  ];
  let primary = databaseState(
    infrastructure.receipt.cloudflare.d1.primary,
    options.primaryHistory ?? [],
    options.primaryHistory?.length ? expectedSchemaSha256 : d("0"),
  );
  let recovery = databaseState(
    infrastructure.receipt.cloudflare.d1.recovery,
    [],
    d("0"),
  );
  let workerVersion = options.workerVersion ?? null;
  let deployment = options.previousDeployment ?? null;
  let triggers = options.previousTriggers ?? { crons: [], routes: [], stateSha256: d("8") };
  let providerInspection = 0;
  const providerBody = {
    cloudflare: structuredClone(infrastructure.receipt.cloudflare),
    resend: structuredClone(infrastructure.receipt.resend),
  };
  const providerState = {
    ...providerBody,
    stateSha256: sha256(Buffer.from(canonicalJson(providerBody) + "\n")),
  };
  const adapter = {
    calls,
    async verifyProviderState() {
      calls.push("verify-provider");
      providerInspection += 1;
      if (providerInspection === 2 && options.providerDrift) {
        return {
          ...providerState,
          resend: { ...providerState.resend, domainStatus: "pending" },
        };
      }
      return structuredClone(providerState);
    },
    async inspectDatabase({ kind }) {
      calls.push("inspect-" + kind);
      return structuredClone(kind === "primary" ? primary : recovery);
    },
    async applyOrderedMigrations() {
      calls.push("apply-migrations");
      if (options.migrationFailure) throw new Error("synthetic migration failure");
      primary = databaseState(
        infrastructure.receipt.cloudflare.d1.primary,
        migrations,
        expectedSchemaSha256,
      );
    },
    async createEncryptedRecoveryProof() {
      calls.push("recovery-proof");
      recovery = databaseState(
        infrastructure.receipt.cloudflare.d1.recovery,
        migrations,
        options.recoverySchemaDrift ? d("8") : expectedSchemaSha256,
      );
      return {
        primaryDatabaseIdSha256: digest(primaryId),
        recoveryDatabaseIdSha256: digest(recoveryId),
        plaintextBackupSha256: d("1"),
        encryptedBackupSha256: d("2"),
        encryptionKeySha256: d("3"),
        decryptionProofSha256: d("4"),
        encryptedCustodyBindingVersionSha256: d("6"),
        encryptedCustodyCiphertextSha256: d("7"),
        encryptedCustodySha256: d("8"),
        encryptedCustodyDecryptionProofSha256: d("9"),
        primarySchemaSha256: expectedSchemaSha256,
        recoverySchemaSha256: options.recoveryProofDrift ? d("8") : expectedSchemaSha256,
        timeTravelBookmarkSha256: d("5"),
        recoveryLeadCount: 0,
        plaintextRetained: false,
      };
    },
    async inspectWorkerVersion(expected, exactVersionId = null) {
      calls.push("inspect-version");
      if (exactVersionId === null) {
        if (options.preexistingWorker && !workerVersion) {
          return { versionId: workerVersionId, workerName: expected.workerName };
        }
        if (workerVersion) throw new Error("pre-existing Worker/version blocks initial release");
        return null;
      }
      if (!workerVersion) return null;
      return options.workerSubstitution
        ? { ...workerVersion, uploadArtifactSha256: d("8") }
        : structuredClone(workerVersion);
    },
    async uploadWorkerVersion({ expected, runtimeSecrets: suppliedSecrets }) {
      calls.push("upload-version");
      if (options.uploadPrecheckFailure) {
        throw new Error("synthetic pre-upload absence check failed");
      }
      assert.equal(suppliedSecrets, options.expectedSecrets);
      workerVersion = {
        versionId: workerVersionId,
        ...expected,
        stateSha256: d("6"),
      };
      return structuredClone(workerVersion);
    },
    async inspectDeployment() {
      calls.push("inspect-deployment");
      return deployment && structuredClone(deployment);
    },
    async deployWorkerVersion({ versionId }) {
      calls.push("deploy-version");
      if (options.deployFailure) throw new Error("synthetic deploy failure");
      deployment = { versionId, percentage: 100, stateSha256: d("7") };
    },
    async rollbackWorkerDeployment() {
      calls.push("rollback");
      if (options.rollbackFailure) throw new Error("synthetic rollback failure");
      workerVersion = null;
      deployment = null;
      triggers = { crons: [], routes: [], stateSha256: d("8") };
    },
    async inspectTriggers() {
      calls.push("inspect-triggers");
      return triggers && structuredClone(triggers);
    },
    async deployTriggers({ crons, routes }) {
      calls.push("deploy-triggers");
      triggers = { crons, routes, stateSha256: d("8") };
    },
    async executeCandidateVerification(input) {
      calls.push("candidate-verification");
      if (options.candidateFailure) {
        throw new Error("synthetic candidate verification failure");
      }
      const custody = {
        bindingVersionSha256: d("1"),
        ciphertextSha256: d("2"),
        custodySha256: d("3"),
        decryptionProofSha256: d("4"),
        privateReceiptSha256: d("5"),
      };
      return {
        candidateEvidenceSha256: d("6"),
        candidateRoutesPreCutoverStateSha256: d("7"),
        completedAt: input.now().toISOString(),
        custodyBindingVersionSha256: custody.bindingVersionSha256,
        custodyCiphertextSha256: custody.ciphertextSha256,
        custodyDecryptionProofSha256: custody.decryptionProofSha256,
        custodyProofSha256: canonicalDigest(custody),
        custodySha256: custody.custodySha256,
        leadArchivedStateSha256: d("8"),
        privateReceiptSha256: custody.privateReceiptSha256,
        productionReleaseStateSha256: input.productionReleaseStateSha256,
        resendDeliveryStateSha256: d("9"),
      };
    },
  };
  return adapter;
}

async function fixture(options = {}) {
  const root = await mkdtemp(join(tmpdir(), "production-release-adapter-"));
  const secrets = runtimeSecrets();
  const rawReceipt = receipt(secrets, options.receiptOverrides);
  const bytes = Buffer.from(JSON.stringify(rawReceipt) + "\n", "utf8");
  const receiptSha256 = sha256(bytes);
  const payload = materialized(root, receiptSha256);
  const infrastructure = validateProductionInfrastructureReceipt({
    bytes,
    expectedSha256: receiptSha256,
    materialized: payload,
    now: new Date("2026-09-01T09:00:00.000Z"),
  });
  return { root, secrets, payload, infrastructure };
}

function allZero(secrets) {
  return Object.values(secrets).every(({ bytes }) => bytes.every((value) => value === 0));
}

test("exact release performs ordered D1 recovery, immutable Worker deployment, and emits hash-only evidence", async () => {
  const context = await fixture();
  try {
    const adapter = fakeAdapter(context.infrastructure, { expectedSecrets: context.secrets });
    const evidence = await executeProductionReleaseAdapter({
      adapter,
      infrastructure: context.infrastructure,
      materialized: context.payload,
      runtimeSecrets: context.secrets,
      protectedExecutionRunId: "33524599999",
      now: () => new Date("2026-09-01T09:02:00.000Z"),
    });
    assert.equal(evidence.result, "verified");
    assert.match(evidence.receiptSha256, /^[a-f0-9]{64}$/);
    assert.equal(adapter.calls.filter((value) => value === "verify-provider").length, 2);
    assert.deepEqual(
      adapter.calls.filter((value) => value.startsWith("apply-")),
      ["apply-migrations"],
    );
    assert.equal(adapter.calls.includes("recovery-proof"), true);
    assert.equal(adapter.calls.includes("upload-version"), true);
    assert.equal(adapter.calls.includes("deploy-version"), true);
    assert.equal(adapter.calls.includes("deploy-triggers"), true);
    assert.equal(adapter.calls.includes("candidate-verification"), true);
    const publicBytes = JSON.stringify(evidence);
    assert.equal(publicBytes.includes(adminEmail), false);
    assert.equal(publicBytes.includes(primaryId), false);
    assert.equal(publicBytes.includes(recoveryId), false);
    assert.equal(publicBytes.includes(["re", "123456"].join("_")), false);
    assert.equal(allZero(context.secrets), true);
  } finally {
    await rm(context.root, { recursive: true, force: true });
  }
});

test("missing or semantically changed runtime custody fails before every provider call and zeroes available bytes", async () => {
  for (const mutate of [
    (secrets) => delete secrets.LEAD_RATE_LIMIT_SECRET,
    (secrets) => {
      secrets.DASHBOARD_AUTHORIZED_EMAILS.bytes = Buffer.from("other@example.net");
      secrets.DASHBOARD_AUTHORIZED_EMAILS.plaintextSha256 = sha256(
        secrets.DASHBOARD_AUTHORIZED_EMAILS.bytes,
      );
    },
    (secrets) => {
      secrets.RESEND_API_KEY.bindingVersionSha256 = d("8");
    },
  ]) {
    const context = await fixture();
    try {
      mutate(context.secrets);
      const adapter = fakeAdapter(context.infrastructure, { expectedSecrets: context.secrets });
      await assert.rejects(
        executeProductionReleaseAdapter({
          adapter,
          infrastructure: context.infrastructure,
          materialized: context.payload,
          runtimeSecrets: context.secrets,
          protectedExecutionRunId: "33524599999",
        }),
        /materialized runtime secret|runtime secrets|semantics/,
      );
      assert.deepEqual(adapter.calls, []);
      assert.equal(allZero(context.secrets), true);
    } finally {
      await rm(context.root, { recursive: true, force: true });
    }
  }
});

test("provider drift after D1 recovery fails before Worker upload", async () => {
  const context = await fixture();
  try {
    const adapter = fakeAdapter(context.infrastructure, {
      expectedSecrets: context.secrets,
      providerDrift: true,
    });
    await assert.rejects(
      executeProductionReleaseAdapter({
        adapter,
        infrastructure: context.infrastructure,
        materialized: context.payload,
        runtimeSecrets: context.secrets,
        protectedExecutionRunId: "33524599999",
      }),
      /provider (?:state changed|revalidation is invalid)/,
    );
    assert.equal(adapter.calls.includes("upload-version"), false);
    assert.equal(allZero(context.secrets), true);
  } finally {
    await rm(context.root, { recursive: true, force: true });
  }
});

test("migration-history substitution and recovery-schema substitution fail before upload", async () => {
  for (const options of [
    { primaryHistory: [{ version: 2, name: "0002_status.sql" }] },
    { recoverySchemaDrift: true },
    { recoveryProofDrift: true },
  ]) {
    const context = await fixture();
    try {
      const adapter = fakeAdapter(context.infrastructure, {
        ...options,
        expectedSecrets: context.secrets,
      });
      await assert.rejects(
        executeProductionReleaseAdapter({
          adapter,
          infrastructure: context.infrastructure,
          materialized: context.payload,
          runtimeSecrets: context.secrets,
          protectedExecutionRunId: "33524599999",
        }),
        /migration history|recovery proof|recovery D1|reproduce/,
      );
      assert.equal(adapter.calls.includes("upload-version"), false);
      assert.equal(allZero(context.secrets), true);
    } finally {
      await rm(context.root, { recursive: true, force: true });
    }
  }
});

test("Worker substitution, active route, and deployment failure remain fail-closed and rollback-aware", async () => {
  for (const options of [
    { preexistingWorker: true },
    { workerSubstitution: true },
    { previousTriggers: { crons: [], routes: ["freshtowels.gr/*"], stateSha256: d("8") } },
    { deployFailure: true },
  ]) {
    const context = await fixture();
    try {
      const adapter = fakeAdapter(context.infrastructure, {
        ...options,
        expectedSecrets: context.secrets,
      });
      await assert.rejects(
        executeProductionReleaseAdapter({
          adapter,
          infrastructure: context.infrastructure,
          materialized: context.payload,
          runtimeSecrets: context.secrets,
          protectedExecutionRunId: "33524599999",
        }),
        /(?:pre-existing Worker|Worker (?:version|release tag)|active route|synthetic deploy failure)/,
      );
      if (options.deployFailure) assert.equal(adapter.calls.includes("rollback"), true);
      assert.equal(allZero(context.secrets), true);
    } finally {
      await rm(context.root, { recursive: true, force: true });
    }
  }
});

test("an ambiguous rollback replaces the provider error with a terminal ambiguity", async () => {
  const context = await fixture();
  try {
    const adapter = fakeAdapter(context.infrastructure, {
      expectedSecrets: context.secrets,
      deployFailure: true,
      rollbackFailure: true,
    });
    await assert.rejects(
      executeProductionReleaseAdapter({
        adapter,
        infrastructure: context.infrastructure,
        materialized: context.payload,
        runtimeSecrets: context.secrets,
        protectedExecutionRunId: "33524599999",
      }),
      /rollback is ambiguous/,
    );
    assert.equal(allZero(context.secrets), true);
  } finally {
    await rm(context.root, { recursive: true, force: true });
  }
});

test("candidate or private-custody failure rolls back the just-created Worker", async () => {
  const context = await fixture();
  try {
    const adapter = fakeAdapter(context.infrastructure, {
      candidateFailure: true,
      expectedSecrets: context.secrets,
    });
    await assert.rejects(
      executeProductionReleaseAdapter({
        adapter,
        infrastructure: context.infrastructure,
        materialized: context.payload,
        runtimeSecrets: context.secrets,
        protectedExecutionRunId: "33524599999",
      }),
      /candidate verification failure/,
    );
    assert.equal(adapter.calls.includes("candidate-verification"), true);
    assert.equal(adapter.calls.includes("rollback"), true);
    assert.equal(allZero(context.secrets), true);
  } finally {
    await rm(context.root, { recursive: true, force: true });
  }
});

test("a failed second absence check cannot delete a Worker not created by this invocation", async () => {
  const context = await fixture();
  try {
    const adapter = fakeAdapter(context.infrastructure, {
      expectedSecrets: context.secrets,
      uploadPrecheckFailure: true,
    });
    await assert.rejects(
      executeProductionReleaseAdapter({
        adapter,
        infrastructure: context.infrastructure,
        materialized: context.payload,
        runtimeSecrets: context.secrets,
        protectedExecutionRunId: "33524599999",
      }),
      /pre-upload absence check failed/,
    );
    assert.equal(adapter.calls.includes("rollback"), false);
    assert.equal(allZero(context.secrets), true);
  } finally {
    await rm(context.root, { recursive: true, force: true });
  }
});

test("receipt bytes, 24-hour validity, Access security fields, and release identities are exact", async () => {
  const root = await mkdtemp(join(tmpdir(), "production-release-receipt-"));
  try {
    for (const mutate of [
      (value) => {
        value.validUntil = "2026-09-01T10:00:00.000Z";
      },
      (value) => {
        value.cloudflare.access.sameSiteCookieAttribute = "lax";
      },
      (value) => {
        value.application.commitSha = "c".repeat(40);
      },
      (value) => {
        value.verifiedState.resendDomainVerified = false;
      },
    ]) {
      const secrets = runtimeSecrets();
      const value = receipt(secrets);
      mutate(value);
      const bytes = Buffer.from(JSON.stringify(value) + "\n");
      const expectedSha256 = sha256(bytes);
      await assert.rejects(
        async () =>
          validateProductionInfrastructureReceipt({
            bytes,
            expectedSha256,
            materialized: materialized(root, expectedSha256),
            now: new Date("2026-09-01T09:00:00.000Z"),
          }),
      );
    }
    const pendingSecrets = runtimeSecrets();
    const pending = receipt(pendingSecrets);
    pending.cloudflare.zoneStatus = "pending";
    pending.verifiedState.cloudflareZoneActive = false;
    const pendingBytes = Buffer.from(JSON.stringify(pending) + "\n");
    const pendingSha256 = sha256(pendingBytes);
    assert.equal(
      validateProductionInfrastructureReceipt({
        bytes: pendingBytes,
        expectedSha256: pendingSha256,
        materialized: materialized(root, pendingSha256),
        now: new Date("2026-09-01T09:00:00.000Z"),
      }).receipt.cloudflare.zoneStatus,
      "pending",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("hydration rejects missing, duplicated, and pre-existing final configuration", async () => {
  for (const mutate of [
    (template) => {
      template.account_id = "1".repeat(32);
    },
    (template) => {
      template.extra = productionDeploymentPlaceholders.accountId;
    },
  ]) {
    const context = await fixture();
    try {
      mutate(context.payload.configurationTemplate.template);
      await assert.rejects(
        hydrateProductionConfiguration({
          materialized: context.payload,
          infrastructure: context.infrastructure,
        }),
        /placeholder cardinality/,
      );
    } finally {
      await rm(context.root, { recursive: true, force: true });
    }
  }
});
