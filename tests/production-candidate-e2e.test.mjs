import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../scripts/control-contract.mjs";
import {
  CandidateE2eError,
  executeProductionCandidateE2e,
  productionCandidateE2eConstants,
  serializeProductionCandidateE2eReceipt,
} from "../scripts/production-candidate-e2e.mjs";

const d = (value) => createHash("sha256").update(value).digest("hex");
const digest = (value) => d(Buffer.from(canonicalJson(value) + "\n", "utf8"));
const applicationCommitSha = "a".repeat(40);
const controllerCommitSha = "b".repeat(40);
const artifactSha256 = "c".repeat(64);
const workerVersionId = "11111111-1111-4111-8111-111111111111";
const databaseId = "22222222-2222-4222-8222-222222222222";
const executionRequestId = "33333333-3333-4333-8333-333333333333";
const testRunId = "44444444-4444-4444-8444-444444444444";
const leadId = `lead_${"5".repeat(32)}`;
const outboxId = `mail_${"6".repeat(32)}`;
const providerMessageId = "resend-message-123";
const routeId = (index) => String(index).repeat(32);

function expected() {
  return {
    accessTeamDomain: "https://fresh-towels-test.cloudflareaccess.com",
    applicationCommitSha,
    artifactSha256,
    controllerCommitSha,
    databaseId,
    notificationRecipient: "info@freshtowels.gr",
    notificationSender: "notifications@notify.freshtowels.gr",
    workerName: "fresh-towels-production",
    workerVersionId,
    zoneId: "d".repeat(32),
  };
}

function release(overrides = {}) {
  const identity = expected();
  return {
    applicationCommitSha,
    artifactSha256,
    controllerCommitSha,
    databaseId,
    environment: "production-candidate-e2e",
    executionClaimSha256: "e".repeat(64),
    executionRequestId,
    infrastructureReceiptSha256: "f".repeat(64),
    productionReleaseStateSha256: "0".repeat(64),
    workerName: identity.workerName,
    workerVersionId,
    zoneId: identity.zoneId,
    ...overrides,
  };
}

function response(status, body, headers = {}) {
  return { body, bodySha256: digest(body), headers, status };
}

function harness(options = {}) {
  const calls = {
    activate: [],
    d1: 0,
    markSynthetic: [],
    deactivate: [],
    http: [],
    lifecycle: [],
    resend: [],
    routesList: 0,
    sleep: [],
    worker: [],
  };
  let currentTime = Date.parse("2026-09-01T12:00:00.000Z");
  let routes = structuredClone(
    options.initialRoutes ?? [
      ...productionCandidateE2eConstants.preCutoverRoutePatterns.map(
        (pattern, index) => ({
          id: routeId(index + 5),
          pattern,
          script: "fresh-towels-production",
        }),
      ),
      {
        id: routeId(9),
        pattern: "unrelated.example.com/*",
        script: "unrelated-worker",
      },
    ],
  );
  let postCount = 0;
  let flowStatus = "new";
  let flowVersion = 1;
  let flowInspectionCount = 0;
  let syntheticMarkerSha256 = null;

  function flow(input) {
    syntheticMarkerSha256 ??= input.syntheticMarkerSha256;
    flowInspectionCount += 1;
    const pending = options.pendingOnce && flowInspectionCount === 1;
    return {
      databaseId,
      delivery: pending
        ? null
        : {
            eventIdSha256: "7".repeat(64),
            providerCreatedAt: "2026-09-01T12:00:04.000Z",
            providerMessageIdSha256: d(providerMessageId),
            receivedAt: "2026-09-01T12:00:05.000Z",
            status: options.deliveryStatus ?? "delivered",
          },
      lead: {
        id: leadId,
        sourcePath: "/epikoinonia",
        status: flowStatus,
        synthetic: true,
        syntheticMarkerSha256:
          options.wrongSyntheticMarker === true
            ? "8".repeat(64)
            : syntheticMarkerSha256,
        version: flowVersion,
      },
      outbox: {
        id: outboxId,
        providerMessageId: pending ? null : providerMessageId,
        providerMessageIdSha256: pending ? null : d(providerMessageId),
        recipientSha256:
          options.wrongRecipient === true
            ? "9".repeat(64)
            : d("info@freshtowels.gr"),
        senderSha256: d("notifications@notify.freshtowels.gr"),
        status: pending ? "processing" : (options.outboxStatus ?? "sent"),
      },
      testRunId,
    };
  }

  const adapters = {
    d1: {
      async markSynthetic(input) {
        calls.markSynthetic.push(input);
        return {
          leadId,
          stateSha256: d("synthetic-mark"),
          synthetic: options.syntheticMarkFailed !== true,
        };
      },
      async inspectFlow(input) {
        calls.d1 += 1;
        return flow(input);
      },
    },
    http: {
      async request(request) {
        calls.http.push(request);
        if (request.method === "GET") {
          return response(
            options.accessStatus ?? 302,
            {},
            options.accessStatus === 403
              ? { server: "cloudflare" }
              : {
                  location:
                    options.accessLocation ??
                    "https://fresh-towels-test.cloudflareaccess.com/cdn-cgi/access/login/freshtowels.gr?opaque=1",
                  server: "cloudflare",
                },
          );
        }
        postCount += 1;
        const duplicate = postCount > 1;
        return response(duplicate ? 200 : 201, {
          duplicate: options.duplicateMismatch && duplicate ? false : duplicate,
          id: leadId,
          notification: "pending",
          ok: true,
        });
      },
    },
    lifecycle: {
      async transition(input) {
        calls.lifecycle.push(input);
        const previousVersion = flowVersion;
        flowStatus = input.toStatus;
        flowVersion += 1;
        return {
          eventIdSha256: d(`${input.fromStatus}:${input.toStatus}`),
          fromStatus: input.fromStatus,
          leadId,
          previousVersion,
          stateSha256: d(`state:${input.toStatus}`),
          toStatus: input.toStatus,
          version: flowVersion,
        };
      },
    },
    resend: {
      async inspectEmail(input) {
        calls.resend.push(input);
        return {
          createdAt: "2026-09-01T12:00:05.000Z",
          from:
            options.resendWrongSender === true
              ? "attacker@example.com"
              : "notifications@notify.freshtowels.gr",
          id: providerMessageId,
          lastEvent: options.resendEvent ?? "delivered",
          to: [
            options.resendWrongRecipient === true
              ? "attacker@example.com"
              : "info@freshtowels.gr",
          ],
        };
      },
    },
    routes: {
      async activate(input) {
        calls.activate.push(input);
        if (options.activationNoop !== true) {
          routes.push(
            ...input.patterns.map((pattern, index) => ({
              id: routeId(index + 1),
              pattern,
              script: input.workerName,
            })),
          );
        }
        if (options.activationThrows === true) {
          throw new Error("synthetic ambiguous activation acknowledgement");
        }
        return { accepted: true, operationSha256: d("activate") };
      },
      async deactivate(input) {
        calls.deactivate.push(input);
        if (options.deactivationNoop !== true) {
          routes = routes.filter(
            (route) => !input.patterns.includes(route.pattern),
          );
        }
        if (options.deactivationThrows === true) {
          throw new Error("synthetic ambiguous deactivation acknowledgement");
        }
        return { accepted: true, operationSha256: d("deactivate") };
      },
      async list() {
        calls.routesList += 1;
        if (options.driftBeforeRollback && calls.routesList === 3) {
          routes.push({
            id: routeId(8),
            pattern: "another.example.com/*",
            script: "other-worker",
          });
        }
        return structuredClone(routes);
      },
    },
    worker: {
      async inspect(input) {
        calls.worker.push(input);
        return {
          applicationCommitSha,
          artifactSha256: options.workerArtifactSha256 ?? artifactSha256,
          stateSha256: d("worker-state"),
          trafficPercentage: 100,
          versionId: workerVersionId,
          workerName: "fresh-towels-production",
        };
      },
    },
  };
  const poll = {
    intervalMilliseconds: 100,
    now: () => new Date(currentTime),
    sleep: async (milliseconds) => {
      calls.sleep.push(milliseconds);
      currentTime += milliseconds;
    },
    timeoutMilliseconds: 2_000,
  };
  return { adapters, calls, poll };
}

test("candidate route allowlist is the exact five-route split surface", () => {
  assert.deepEqual(productionCandidateE2eConstants.candidateRoutePatterns, [
    "freshtowels.gr/api/internal/*",
    "freshtowels.gr/api/leads",
    "freshtowels.gr/api/webhooks/resend",
    "freshtowels.gr/internal/leads",
    "freshtowels.gr/internal/leads/*",
  ]);
  assert.equal(
    productionCandidateE2eConstants.candidateRoutePatterns.some((pattern) =>
      [
        "freshtowels.gr/*",
        "www.freshtowels.gr/*",
        "freshtowels.gr/api/leads*",
        "freshtowels.gr/api/webhooks/resend*",
        "freshtowels.gr/internal/leads*",
      ].includes(pattern),
    ),
    false,
  );
  assert.deepEqual(productionCandidateE2eConstants.preCutoverRoutePatterns, [
    "freshtowels.gr/api/internal/*",
    "freshtowels.gr/internal/leads",
    "freshtowels.gr/internal/leads/*",
  ]);
  assert.deepEqual(productionCandidateE2eConstants.publicCandidateRoutePatterns, [
    "freshtowels.gr/api/leads",
    "freshtowels.gr/api/webhooks/resend",
  ]);
});

test("runs the exact candidate E2E, proves delivery, archives the lead, and restores the protected baseline", async () => {
  const fixture = harness({ pendingOnce: true });
  const receipt = await executeProductionCandidateE2e({
    adapters: fixture.adapters,
    expected: expected(),
    poll: fixture.poll,
    release: release(),
    testRunId,
  });
  assert.equal(
    receipt.schema,
    "deployment-control/production-candidate-e2e/v1",
  );
  assert.equal(receipt.worker.versionId, workerVersionId);
  assert.equal(receipt.release.applicationCommitSha, applicationCommitSha);
  assert.equal(receipt.release.controllerCommitSha, controllerCommitSha);
  assert.equal(receipt.release.artifactSha256, artifactSha256);
  assert.equal(receipt.routes.rollbackVerified, true);
  assert.equal(receipt.accessUnauthorized.status, 302);
  assert.equal(fixture.calls.activate.length, 1);
  assert.equal(fixture.calls.markSynthetic.length, 1);
  assert.deepEqual(
    fixture.calls.activate[0].patterns,
    productionCandidateE2eConstants.publicCandidateRoutePatterns,
  );
  assert.equal(fixture.calls.deactivate.length, 1);
  assert.equal(
    fixture.calls.http.filter((request) => request.method === "POST").length,
    2,
  );
  assert.equal(fixture.calls.resend.length, 1);
  assert.deepEqual(
    fixture.calls.lifecycle.map((input) => [input.fromStatus, input.toStatus]),
    [
      ["new", "in_progress"],
      ["in_progress", "answered"],
      ["answered", "archived"],
    ],
  );
  const bytes = serializeProductionCandidateE2eReceipt(receipt);
  assert.equal(d(Buffer.from(JSON.stringify(receipt) + "\n")), d(bytes));
  const text = bytes.toString("utf8");
  assert.doesNotMatch(text, /info@freshtowels\.gr/);
  assert.doesNotMatch(text, /notifications@notify\.freshtowels\.gr/);
  assert.doesNotMatch(text, /210 965 2672/);
  assert.match(text, new RegExp(applicationCommitSha));
  assert.match(text, new RegExp(controllerCommitSha));
  assert.match(text, new RegExp(workerVersionId));
});

test("rejects a release identity mismatch before inspecting providers", async () => {
  const fixture = harness();
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release({ artifactSha256: "1".repeat(64) }),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "release-identity-mismatch",
  );
  assert.equal(fixture.calls.worker.length, 0);
  assert.equal(fixture.calls.routesList, 0);
});

test("rejects a substituted Worker version before route mutation", async () => {
  const fixture = harness({ workerArtifactSha256: "1".repeat(64) });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "worker-version-mismatch",
  );
  assert.equal(fixture.calls.activate.length, 0);
  assert.equal(fixture.calls.http.length, 0);
});

test("fails closed on an unexpected route that overlaps the candidate surface", async () => {
  const fixture = harness({
    initialRoutes: [
      {
        id: routeId(9),
        pattern: "freshtowels.gr/api/*",
        script: "unexpected-worker",
      },
    ],
  });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "unexpected-overlapping-route" &&
      error.doNotRetry === true,
  );
  assert.equal(fixture.calls.activate.length, 0);
  assert.equal(fixture.calls.deactivate.length, 0);
});

test("reconciles a partial public candidate activation to the protected baseline and requires a fresh run", async () => {
  const fixture = harness({
    initialRoutes: [
      ...productionCandidateE2eConstants.preCutoverRoutePatterns,
      productionCandidateE2eConstants.publicCandidateRoutePatterns[0],
    ].map((pattern, index) => ({
        id: routeId(index + 1),
        pattern,
        script: "fresh-towels-production",
      })),
  });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "partial-route-state-reconciled",
  );
  assert.equal(fixture.calls.activate.length, 0);
  assert.equal(fixture.calls.deactivate.length, 1);
  assert.equal(fixture.calls.http.length, 0);
});

test("fails closed without mutation when the protected pre-cutover baseline is missing", async () => {
  const fixture = harness({
    initialRoutes: productionCandidateE2eConstants.preCutoverRoutePatterns
      .slice(0, 2)
      .map((pattern, index) => ({
        id: routeId(index + 1),
        pattern,
        script: "fresh-towels-production",
      })),
  });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "pre-cutover-route-baseline-missing" &&
      error.doNotRetry === true,
  );
  assert.equal(fixture.calls.activate.length, 0);
  assert.equal(fixture.calls.deactivate.length, 0);
});

test("does not submit a lead when Access fails to deny an unauthenticated dashboard request", async () => {
  const fixture = harness({ accessStatus: 200 });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "access-unauthorized-not-denied" &&
      error.doNotRetry === true,
  );
  assert.equal(
    fixture.calls.http.filter((request) => request.method === "POST").length,
    0,
  );
  assert.equal(fixture.calls.deactivate.length, 1);
});

test("fails closed, archives the exact persisted lead, and restores the protected baseline when the synthetic mark acknowledgement is invalid", async () => {
  const fixture = harness({ syntheticMarkFailed: true });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "synthetic-mark-failed" &&
      error.doNotRetry === true,
  );
  assert.equal(fixture.calls.deactivate.length, 1);
  assert.deepEqual(
    fixture.calls.lifecycle.map((entry) => entry.toStatus),
    ["in_progress", "answered", "archived"],
  );
});

test("archives a persisted synthetic lead and rolls routes back when duplicate proof fails", async () => {
  const fixture = harness({ duplicateMismatch: true });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "lead-submission-proof-failed",
  );
  assert.equal(fixture.calls.lifecycle.length, 3);
  assert.equal(fixture.calls.deactivate.length, 1);
});

test("rejects D1 identity drift and still performs bounded cleanup", async () => {
  const fixture = harness({ wrongRecipient: true });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "synthetic-lead-cleanup-failed" &&
      error.doNotRetry,
  );
  assert.equal(fixture.calls.deactivate.length, 1);
  assert.equal(fixture.calls.resend.length, 0);
});

test("rejects a mismatched Resend recipient and archives the synthetic lead", async () => {
  const fixture = harness({ resendWrongRecipient: true });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "resend-delivery-mismatch",
  );
  assert.equal(fixture.calls.lifecycle.length, 3);
  assert.equal(fixture.calls.deactivate.length, 1);
});

test("fails do-not-retry when authoritative route state drifts before rollback", async () => {
  const fixture = harness({ driftBeforeRollback: true });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "candidate-route-cleanup-failed" &&
      error.doNotRetry === true,
  );
});

test("rejects an acknowledged activation whose authoritative route state did not change", async () => {
  const fixture = harness({ activationNoop: true });
  await assert.rejects(
    executeProductionCandidateE2e({
      adapters: fixture.adapters,
      expected: expected(),
      poll: fixture.poll,
      release: release(),
      testRunId,
    }),
    (error) =>
      error instanceof CandidateE2eError &&
      error.code === "route-activation-not-authoritative",
  );
  assert.equal(fixture.calls.http.length, 0);
});

test("accepts an ambiguous activation acknowledgement only after exact authoritative reconciliation", async () => {
  const fixture = harness({ activationThrows: true });
  const receipt = await executeProductionCandidateE2e({
    adapters: fixture.adapters,
    expected: expected(),
    poll: fixture.poll,
    release: release(),
    testRunId,
  });
  assert.equal(receipt.routes.rollbackVerified, true);
  assert.equal(fixture.calls.activate.length, 1);
  assert.equal(fixture.calls.deactivate.length, 1);
});

test("accepts an ambiguous rollback acknowledgement only after the protected baseline is authoritative", async () => {
  const fixture = harness({ deactivationThrows: true });
  const receipt = await executeProductionCandidateE2e({
    adapters: fixture.adapters,
    expected: expected(),
    poll: fixture.poll,
    release: release(),
    testRunId,
  });
  assert.equal(receipt.routes.rollbackVerified, true);
  assert.equal(fixture.calls.deactivate.length, 1);
});

test("rejects receipt tampering instead of serializing invented success", async () => {
  const fixture = harness();
  const receipt = await executeProductionCandidateE2e({
    adapters: fixture.adapters,
    expected: expected(),
    poll: fixture.poll,
    release: release(),
    testRunId,
  });
  assert.throws(
    () =>
      serializeProductionCandidateE2eReceipt({
        ...receipt,
        receiptSha256: "0".repeat(64),
      }),
    (error) =>
      error instanceof CandidateE2eError && error.code === "receipt-invalid",
  );
});
