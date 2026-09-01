import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  executeProductionCutoverAdapter,
  productionCandidateRoutes,
  productionCutoverConstants,
  productionPreCutoverRoutes,
  productionFullRoutes,
  validateProductionCutoverInput,
} from "../scripts/production-cutover-adapter.mjs";

const d = (value) => String(value).repeat(64).slice(0, 64);
const appSha = "a".repeat(40);
const controllerSha = "b".repeat(40);
const workerVersionId = "11111111-1111-4111-8111-111111111111";
const accessApplicationId = "22222222-2222-4222-8222-222222222222";
const accountId = "3".repeat(32);
const zoneId = "4".repeat(32);

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
}

function withState(value) {
  return { ...value, stateSha256: digest(value) };
}

function routeState(patterns) {
  return withState({
    workerName: "fresh-towels-production",
    patterns: [...patterns],
    inventoryStateSha256: digest(patterns),
  });
}

function workerState() {
  return withState({
    workerName: "fresh-towels-production",
    versionId: workerVersionId,
    percentage: 100,
    versionStateSha256: d("1"),
    deploymentStateSha256: d("2"),
  });
}

function providerState() {
  const cloudflare = {
    account: withState({ accountId }),
    zone: withState({ zoneId, name: "freshtowels.gr", status: "active" }),
    dns: withState({ recordCount: 17, inventorySha256: d("3") }),
    d1: withState({
      databaseIdSha256: d("4"),
      databaseName: "fresh-towels-leads-prod",
      jurisdiction: "eu",
      schemaVersion: 9,
      schemaSha256: d("6"),
    }),
    access: withState({
      applicationId: accessApplicationId,
      applicationDomain: "freshtowels.gr/internal/leads",
      status: "active",
      adminIdentitySha256: d("5"),
      policyDecision: "allow",
      extraPolicyCount: 0,
    }),
  };
  const resend = withState({
    domain: "notify.freshtowels.gr",
    status: "verified",
    sendingEnabled: true,
    senderAddress: "notifications@notify.freshtowels.gr",
    webhookEndpointSha256: sha256(
      Buffer.from("https://freshtowels.gr/api/webhooks/resend"),
    ),
    webhookStatus: "enabled",
  });
  return withState({ cloudflare, resend });
}

function accessAudit() {
  const eventSha256 = d("8");
  return withState({
    applicationId: accessApplicationId,
    applicationDomain: "freshtowels.gr/internal/leads",
    identitySha256: d("5"),
    decision: "allow",
    eventType: "login",
    occurredAt: "2026-09-01T08:45:00.000Z",
    eventSha256,
  });
}

function smoke() {
  const criticalRoutes = productionCutoverConstants.criticalRoutes.map((path) => ({
    path,
    status: 200,
    canonical: `https://freshtowels.gr${path}`,
  }));
  return withState({
    origin: "https://freshtowels.gr",
    wwwOrigin: "https://www.freshtowels.gr",
    httpsValid: true,
    wwwRedirectStatus: 301,
    wwwRedirectLocation: "https://freshtowels.gr/",
    robotsStatus: 200,
    robotsIndexable: true,
    sitemapStatus: 200,
    productionNoindexCount: 0,
    stagingReferenceCount: 0,
    criticalRoutes,
  });
}

function fixture() {
  const provider = providerState();
  const worker = workerState();
  const routes = routeState(productionPreCutoverRoutes);
  const audit = accessAudit();
  const input = {
    schemaVersion: 1,
    operation: "production-cutover",
    environment: "production",
    issuedAt: "2026-09-01T09:00:00.000Z",
    validUntil: "2026-09-01T11:00:00.000Z",
    cutoverRequestId: "33333333-3333-4333-8333-333333333333",
    release: {
      releaseId: d("6"),
      applicationRepository: "zikosbozonis-beep/fresh-towels-website",
      applicationRepositoryId: "1350923567",
      applicationCommitSha: appSha,
      controllerRepository: "zikosbozonis-beep/fresh-towels-deployment-control",
      controllerCommitSha: controllerSha,
      buildArtifactSha256: d("7"),
      uploadArtifactSha256: d("8"),
      productionInfrastructureReceiptSha256: d("9"),
    },
    productionReleasePrerequisite: {
      requestId: "44444444-4444-4444-8444-444444444444",
      runId: "33524599990",
      receiptSha256: d("a"),
      completedAt: "2026-09-01T08:40:00.000Z",
    },
    worker: {
      name: worker.workerName,
      versionId: worker.versionId,
      versionStateSha256: worker.versionStateSha256,
      deploymentStateSha256: worker.deploymentStateSha256,
    },
    provider: {
      accountId,
      zoneId,
      zoneName: "freshtowels.gr",
      fullDnsInventorySha256: provider.cloudflare.dns.inventorySha256,
      primaryDatabaseIdSha256: provider.cloudflare.d1.databaseIdSha256,
      primaryDatabaseName: provider.cloudflare.d1.databaseName,
      primaryDatabaseJurisdiction: provider.cloudflare.d1.jurisdiction,
      primaryDatabaseSchemaVersion: provider.cloudflare.d1.schemaVersion,
      primaryDatabaseSchemaSha256: provider.cloudflare.d1.schemaSha256,
      primaryDatabaseStateSha256: provider.cloudflare.d1.stateSha256,
      accessApplicationId,
      accessApplicationDomain: provider.cloudflare.access.applicationDomain,
      accessAdminIdentitySha256: provider.cloudflare.access.adminIdentitySha256,
      accessStateSha256: provider.cloudflare.access.stateSha256,
      resendDomain: provider.resend.domain,
      resendStateSha256: provider.resend.stateSha256,
      providerStateSha256: provider.stateSha256,
    },
    candidate: {
      completedAt: "2026-09-01T08:30:00.000Z",
      routesStateSha256: routes.inventoryStateSha256,
      syntheticMarkerSha256: d("0"),
      e2eEvidenceSha256: d("0"),
      d1EvidenceSha256: d("b"),
      outboxEvidenceSha256: d("c"),
      resendDeliveryEvidenceSha256: d("d"),
      accessAuditEvidenceSha256: audit.eventSha256,
      productionReleaseStateSha256: d("e"),
      productionReleaseCandidateReceiptSha256: d("f"),
    },
  };
  input.candidate.syntheticMarkerSha256 = d("e");
  const e2eBody = {
    schema: "deployment-control/production-candidate-e2e/v1",
    receiptType: "fresh-towels-production-candidate-e2e",
    environment: "production-candidate-e2e",
    completedAt: input.candidate.completedAt,
    release: {
      applicationCommitSha: input.release.applicationCommitSha,
      artifactSha256: input.release.uploadArtifactSha256,
      controllerCommitSha: input.release.controllerCommitSha,
      executionClaimSha256: d("1"),
      executionRequestId: input.productionReleasePrerequisite.requestId,
      infrastructureReceiptSha256:
        input.release.productionInfrastructureReceiptSha256,
      productionReleaseStateSha256:
        input.candidate.productionReleaseStateSha256,
      releaseBindingSha256: d("2"),
    },
    worker: {
      stateSha256: d("3"),
      versionId: input.worker.versionId,
      workerNameSha256: sha256(Buffer.from(input.worker.name)),
    },
    routes: {
      activeStateSha256: d("4"),
      candidatePatternsSha256: digest(productionCandidateRoutes),
      preCutoverStateSha256: routes.inventoryStateSha256,
      preStateSha256: d("5"),
      rollbackVerified: true,
    },
    accessUnauthorized: {
      challengeSha256: d("6"),
      responseBodySha256: d("7"),
      status: 302,
    },
    leadFlow: {
      d1StateSha256: input.candidate.d1EvidenceSha256,
      deliveryEventIdSha256: d("8"),
      deliveryStateSha256: d("9"),
      duplicateEffectCount: 1,
      finalStatusSha256: sha256(Buffer.from("archived")),
      leadCount: 1,
      leadIdSha256: d("a"),
      outboxIdSha256: d("b"),
      outboxStateSha256: input.candidate.outboxEvidenceSha256,
      providerMessageIdSha256: d("c"),
      syntheticMarkerSha256: input.candidate.syntheticMarkerSha256,
      testRunIdSha256: d("d"),
    },
    resend: {
      deliveryStateSha256: input.candidate.resendDeliveryEvidenceSha256,
      messageIdSha256: d("e"),
      recipientSha256: sha256(Buffer.from("info@freshtowels.gr")),
      senderSha256: sha256(
        Buffer.from("notifications@notify.freshtowels.gr"),
      ),
    },
    lifecycle: {
      finalStateSha256: d("f"),
      transitionSha256s: [d("1"), d("2"), d("3")],
    },
  };
  const e2e = { ...e2eBody, receiptSha256: digest(e2eBody) };
  input.candidate.e2eEvidenceSha256 = e2e.receiptSha256;
  return { input, provider, worker, routes, audit, e2e };
}

function fakeAdapter(context, options = {}) {
  const calls = [];
  let routes = structuredClone(context.routes);
  let providerInspections = 0;
  const adapter = {
    calls,
    async inspectProviderState() {
      calls.push("inspect-provider");
      providerInspections += 1;
      if (options.providerDrift && providerInspections > 1) {
        return withState({
          cloudflare: context.provider.cloudflare,
          resend: withState({
            ...Object.fromEntries(
              Object.entries(context.provider.resend).filter(
                ([key]) => key !== "stateSha256",
              ),
            ),
            status: "pending",
          }),
        });
      }
      return structuredClone(context.provider);
    },
    async inspectWorkerState() {
      calls.push("inspect-worker");
      if (options.workerSubstitution) {
        return withState({
          ...Object.fromEntries(
            Object.entries(context.worker).filter(([key]) => key !== "stateSha256"),
          ),
          versionId: "55555555-5555-4555-8555-555555555555",
        });
      }
      return structuredClone(context.worker);
    },
    async inspectRoutes() {
      calls.push("inspect-routes");
      return structuredClone(routes);
    },
    async inspectAccessAudit() {
      calls.push("inspect-access-audit");
      const value = structuredClone(context.audit);
      if (options.accessIdentitySubstitution) {
        value.identitySha256 = d("f");
        value.stateSha256 = digest(
          Object.fromEntries(Object.entries(value).filter(([key]) => key !== "stateSha256")),
        );
      }
      if (options.staleAccessLogin) {
        value.occurredAt = "2026-09-01T08:00:00.000Z";
        value.stateSha256 = digest(
          Object.fromEntries(Object.entries(value).filter(([key]) => key !== "stateSha256")),
        );
      }
      return value;
    },
    async inspectCandidateE2e({ receiptSha256 }) {
      calls.push("inspect-e2e");
      assert.equal(receiptSha256, context.e2e.receiptSha256);
      if (options.emailNotDelivered) {
        const value = structuredClone(context.e2e);
        value.resend.deliveryStateSha256 = d("0");
        value.receiptSha256 = digest(
          Object.fromEntries(
            Object.entries(value).filter(([key]) => key !== "receiptSha256"),
          ),
        );
        return value;
      }
      return structuredClone(context.e2e);
    },
    async setExactRoutes({ expectedPreviousPatterns, desiredPatterns }) {
      calls.push(`set-routes:${desiredPatterns.join(",")}`);
      if (options.routeMutationThrows && desiredPatterns === productionFullRoutes) {
        if (options.mutationAppliedBeforeThrow) routes = routeState(productionFullRoutes);
        throw new Error("synthetic ambiguous provider response");
      }
      if (canonicalJson(routes.patterns) !== canonicalJson(expectedPreviousPatterns)) {
        throw new Error("synthetic previous route state differs");
      }
      routes = routeState(desiredPatterns);
      if (options.rollbackDrift && desiredPatterns === productionPreCutoverRoutes) {
        routes = routeState(["freshtowels.gr/unexpected/*"]);
      }
    },
    async inspectExternalSmoke() {
      calls.push("smoke");
      const value = smoke();
      if (options.noindex) {
        value.productionNoindexCount = 1;
        value.stateSha256 = digest(
          Object.fromEntries(Object.entries(value).filter(([key]) => key !== "stateSha256")),
        );
      }
      return value;
    },
  };
  return adapter;
}

test("exact candidate proof activates only the full routes and emits non-secret hash-only evidence", async () => {
  const context = fixture();
  const adapter = fakeAdapter(context);
  const evidence = await executeProductionCutoverAdapter({
    adapter,
    cutoverInput: context.input,
    protectedExecutionRunId: "33524599999",
    now: () => new Date("2026-09-01T09:30:00.000Z"),
  });
  assert.equal(evidence.result, "verified");
  assert.equal(evidence.rollbackPerformed, false);
  assert.match(evidence.receiptSha256, /^[a-f0-9]{64}$/);
  assert.equal(adapter.calls.filter((value) => value === "inspect-provider").length, 3);
  assert.equal(adapter.calls.includes(`set-routes:${productionFullRoutes.join(",")}`), true);
  const serialized = JSON.stringify(evidence);
  for (const forbidden of [accountId, zoneId, accessApplicationId]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("stale, malformed, or substituted immutable input fails before provider access", async () => {
  const mutations = [
    (input) => {
      input.validUntil = "2026-09-01T09:01:00.000Z";
    },
    (input) => {
      input.release.applicationCommitSha = "not-a-commit";
    },
    (input) => {
      input.release.controllerRepository = "attacker/public";
    },
    (input) => {
      input.unexpected = true;
    },
  ];
  for (const mutate of mutations) {
    const context = fixture();
    mutate(context.input);
    const adapter = fakeAdapter(context);
    await assert.rejects(
      executeProductionCutoverAdapter({
        adapter,
        cutoverInput: context.input,
        protectedExecutionRunId: "33524599999",
        now: () => new Date("2026-09-01T09:30:00.000Z"),
      }),
    );
    assert.deepEqual(adapter.calls, []);
  }
});

test("provider drift, Worker substitution, and non-baseline routes fail before mutation", async () => {
  for (const option of ["providerDrift", "workerSubstitution", "routeDrift"]) {
    const context = fixture();
    if (option === "routeDrift") context.routes = routeState(["freshtowels.gr/untrusted/*"]);
    const adapter = fakeAdapter(context, { [option]: true });
    await assert.rejects(
      executeProductionCutoverAdapter({
        adapter,
        cutoverInput: context.input,
        protectedExecutionRunId: "33524599999",
        now: () => new Date("2026-09-01T09:30:00.000Z"),
      }),
      /provider state|Worker differs|routes|route state/,
    );
    assert.equal(
      adapter.calls.some((value) => value.startsWith("set-routes:")),
      false,
    );
  }
});

test("only a post-candidate allowed owner login and delivered one-effect E2E marker can cut over", async () => {
  for (const option of [
    "accessIdentitySubstitution",
    "staleAccessLogin",
    "emailNotDelivered",
  ]) {
    const context = fixture();
    const adapter = fakeAdapter(context, { [option]: true });
    await assert.rejects(
      executeProductionCutoverAdapter({
        adapter,
        cutoverInput: context.input,
        protectedExecutionRunId: "33524599999",
        now: () => new Date("2026-09-01T09:30:00.000Z"),
      }),
      /Access audit|candidate E2E/,
    );
    assert.equal(
      adapter.calls.some((value) => value.startsWith("set-routes:")),
      false,
    );
  }
  const context = fixture();
  context.input.candidate.syntheticMarkerSha256 = d("f");
  const adapter = fakeAdapter(context);
  await assert.rejects(
    executeProductionCutoverAdapter({
      adapter,
      cutoverInput: context.input,
      protectedExecutionRunId: "33524599999",
      now: () => new Date("2026-09-01T09:30:00.000Z"),
    }),
    /candidate E2E/,
  );
  assert.equal(
    adapter.calls.some((value) => value.startsWith("set-routes:")),
    false,
  );
});

test("an ambiguous activation is reconciled without retry when the exact full routes landed", async () => {
  const context = fixture();
  const adapter = fakeAdapter(context, {
    routeMutationThrows: true,
    mutationAppliedBeforeThrow: true,
  });
  const evidence = await executeProductionCutoverAdapter({
    adapter,
    cutoverInput: context.input,
    protectedExecutionRunId: "33524599999",
    now: () => new Date("2026-09-01T09:30:00.000Z"),
  });
  assert.equal(evidence.result, "verified");
  assert.equal(
    adapter.calls.filter((value) => value === `set-routes:${productionFullRoutes.join(",")}`).length,
    1,
  );
});

test("material live-smoke failure restores the byte-identical protected pre-cutover route state", async () => {
  const context = fixture();
  const adapter = fakeAdapter(context, { noindex: true });
  await assert.rejects(
    executeProductionCutoverAdapter({
      adapter,
      cutoverInput: context.input,
      protectedExecutionRunId: "33524599999",
      now: () => new Date("2026-09-01T09:30:00.000Z"),
    }),
    /protected pre-cutover routes were restored/,
  );
  const finalRoutes = await adapter.inspectRoutes();
  assert.deepEqual(finalRoutes, context.routes);
  assert.equal(
    adapter.calls.includes(`set-routes:${productionPreCutoverRoutes.join(",")}`),
    true,
  );
});

test("rollback substitution is terminally ambiguous and never reported as success", async () => {
  const context = fixture();
  const adapter = fakeAdapter(context, { noindex: true, rollbackDrift: true });
  await assert.rejects(
    executeProductionCutoverAdapter({
      adapter,
      cutoverInput: context.input,
      protectedExecutionRunId: "33524599999",
      now: () => new Date("2026-09-01T09:30:00.000Z"),
    }),
    /rollback is ambiguous/,
  );
});

test("route allowlists are frozen, minimal, and exclude branch/tag or staging inputs", () => {
  assert.equal(Object.isFrozen(productionCandidateRoutes), true);
  assert.equal(Object.isFrozen(productionPreCutoverRoutes), true);
  assert.deepEqual(productionPreCutoverRoutes, [
    "freshtowels.gr/api/internal/*",
    "freshtowels.gr/internal/leads",
    "freshtowels.gr/internal/leads/*",
  ]);
  assert.equal(Object.isFrozen(productionFullRoutes), true);
  assert.deepEqual(productionFullRoutes, ["freshtowels.gr/*", "www.freshtowels.gr/*"]);
  assert.equal(
    [...productionCandidateRoutes, ...productionFullRoutes].some((value) =>
      /staging|preview|github|refs\/heads|main/i.test(value),
    ),
    false,
  );
  const context = fixture();
  assert.equal(
    validateProductionCutoverInput(context.input, {
      now: new Date("2026-09-01T09:30:00.000Z"),
    }).input,
    context.input,
  );
});
