import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../scripts/control-contract.mjs";
import {
  createProductionCandidateProviderAdapter,
  productionCandidateProviderAdapterConstants,
} from "../scripts/production-candidate-provider-adapter.mjs";
import { executeProductionCandidateE2e } from "../scripts/production-candidate-e2e.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const digest = (value) => sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
const accountId = "a".repeat(32);
const zoneId = "b".repeat(32);
const databaseId = "11111111-1111-4111-8111-111111111111";
const workerVersionId = "22222222-2222-4222-8222-222222222222";
const requestId = "33333333-3333-4333-8333-333333333333";
const testRunId = "44444444-4444-4444-8444-444444444444";
const applicationCommitSha = "c".repeat(40);
const controllerCommitSha = "d".repeat(40);
const artifactSha256 = "e".repeat(64);

function candidateRelease() {
  return {
    applicationCommitSha,
    artifactSha256,
    controllerCommitSha,
    databaseId,
    environment: "production-candidate-e2e",
    executionClaimSha256: "1".repeat(64),
    executionRequestId: requestId,
    infrastructureReceiptSha256: "2".repeat(64),
    productionReleaseStateSha256: "3".repeat(64),
    workerName: "fresh-towels-production",
    workerVersionId,
    zoneId,
  };
}

function candidateExpected() {
  return {
    accessTeamDomain: "https://fresh-towels.cloudflareaccess.com",
    applicationCommitSha,
    artifactSha256,
    controllerCommitSha,
    databaseId,
    notificationRecipient: "info@freshtowels.gr",
    notificationSender: "notifications@notify.freshtowels.gr",
    workerName: "fresh-towels-production",
    workerVersionId,
    zoneId,
  };
}

function harness(options = {}) {
  const release = candidateRelease();
  const releaseBindingSha256 = digest(release);
  const idempotencyKey = `candidate_${sha256(
    Buffer.from(`${releaseBindingSha256}:${testRunId}`, "utf8"),
  ).slice(0, 48)}`;
  const idempotencyHash = sha256(Buffer.from(idempotencyKey, "utf8"));
  const leadId = `lead_${idempotencyHash.slice(0, 32)}`;
  const outboxId = `mail_${idempotencyHash.slice(0, 32)}`;
  const messageId = "resend-production-candidate-1";
  const state = {
    fetches: [],
    routes: [
      "freshtowels.gr/api/internal/*",
      "freshtowels.gr/internal/leads",
      "freshtowels.gr/internal/leads/*",
    ].map((pattern, index) => ({
      id: (index + 10).toString(16).padStart(32, "0"),
      pattern,
      script: "fresh-towels-production",
    })),
    status: "new",
    version: 1,
    synthetic: 0,
    events: new Map(),
    postCount: 0,
  };
  const leadRow = () => ({
    id: leadId,
    idempotency_key_hash: idempotencyHash,
    contact_name: "Release Candidate",
    company_name: `Fresh Towels synthetic ${testRunId}`,
    phone_e164: "+302109652672",
    segment: "hair",
    towel_interest: "hair_50x90",
    service_area: "other",
    weekly_quantity: 50,
    message:
      "AUTOMATED SYNTHETIC PRODUCTION RELEASE TEST. NOT A CUSTOMER REQUEST.",
    source_path: "/epikoinonia",
    form_version: "quote-v2",
    status: state.status,
    version: state.version,
    synthetic: state.synthetic,
    relationship_status: "non_customer",
    anonymized_at: null,
  });
  const snapshot = JSON.stringify({
    from: "Fresh Towels <notifications@notify.freshtowels.gr>",
    to: [options.wrongRecipient ? "attacker@example.net" : "info@freshtowels.gr"],
    subject: "Synthetic release",
    text: "Synthetic release",
    html: "<p>Synthetic release</p>",
  });
  const cloudflareClient = {
    async request(input) {
      if (input.path === `/zones/${zoneId}/workers/routes` && input.method === "GET") {
        return { result: structuredClone(state.routes) };
      }
      if (input.path === `/zones/${zoneId}/workers/routes` && input.method === "POST") {
        state.routes.push({
          id: (state.routes.length + 1).toString(16).padStart(32, "0"),
          pattern: input.body.pattern,
          script: input.body.script,
        });
        return { result: structuredClone(state.routes.at(-1)) };
      }
      if (
        input.method === "DELETE" &&
        input.path.startsWith(`/zones/${zoneId}/workers/routes/`)
      ) {
        const id = input.path.split("/").at(-1);
        state.routes = state.routes.filter((route) => route.id !== id);
        return { result: null };
      }
      if (
        input.path ===
          `/accounts/${accountId}/d1/database/${databaseId}/query` &&
        input.method === "POST"
      ) {
        const { sql, params } = input.body;
        let results = [];
        if (sql.includes("FROM leads AS l WHERE l.id")) {
          results = [leadRow()];
        } else if (sql.includes("UPDATE leads SET synthetic = 1")) {
          state.synthetic = 1;
        } else if (sql.includes("JOIN notification_outbox AS o")) {
          results = [
            {
              ...leadRow(),
              outbox_id: outboxId,
              outbox_status: "sent",
              provider_message_id: messageId,
              provider_message_id_sha256: sha256(Buffer.from(messageId)),
              request_body: snapshot,
              request_body_sha256: sha256(Buffer.from(snapshot)),
            },
          ];
        } else if (sql.includes("FROM notification_delivery_events")) {
          results = [
            {
              id: "resend-event-delivered-1",
              provider_message_id: messageId,
              delivery_status: "delivered",
              provider_created_at: "2026-09-01T12:00:01.123456+00:00",
              received_at: "2026-09-01T12:00:02.000Z",
            },
          ];
        } else if (sql.includes("UPDATE leads") && sql.includes("SET status = ?1")) {
          state.status = params[0];
          state.version += 1;
        } else if (sql.includes("INSERT OR IGNORE INTO lead_status_events")) {
          state.events.set(params[0], {
            id: params[0],
            lead_id: leadId,
            from_status: params[1],
            to_status: params[2],
            changed_at: "2026-09-01T12:00:03.000Z",
            actor_subject: params[3],
          });
        } else if (sql.includes("FROM lead_status_events WHERE id")) {
          const event = state.events.get(params[0]);
          results = event ? [event] : [];
        } else {
          throw new Error("unexpected synthetic D1 query");
        }
        return { result: [{ success: true, results, meta: { changes: 1 } }] };
      }
      throw new Error(`unexpected Cloudflare request ${input.method} ${input.path}`);
    },
  };
  const resendAdminClient = {
    async request(input) {
      assert.equal(input.method, "GET");
      assert.equal(input.path, `/emails/${messageId}`);
      return {
        result: {
          id: messageId,
          from: "Fresh Towels <notifications@notify.freshtowels.gr>",
          to: ["info@freshtowels.gr"],
          created_at: "2026-09-01T12:00:01.123456+00:00",
          last_event: "delivered",
        },
      };
    },
  };
  const workerExpected = {
    workerName: "fresh-towels-production",
    stateSha256: "7".repeat(64),
  };
  const productionWranglerAdapter = {
    async inspectWorkerVersion(expected, versionId) {
      assert.equal(expected, workerExpected);
      assert.equal(versionId, workerVersionId);
      return { ...workerExpected, versionId };
    },
    async inspectDeployment() {
      return { versionId: workerVersionId, percentage: 100, stateSha256: "8".repeat(64) };
    },
  };
  const fetchImpl = async (url, init) => {
    state.fetches.push({ url: String(url), init });
    const pathname = new URL(url).pathname;
    if (pathname === "/internal/leads") {
      return new Response("Access denied", {
        status: 302,
        headers: {
          location:
            "https://fresh-towels.cloudflareaccess.com/cdn-cgi/access/login/freshtowels.gr?opaque=1",
          server: "cloudflare",
        },
      });
    }
    if (pathname === "/api/leads") {
      state.postCount += 1;
      return Response.json(
        {
          duplicate: state.postCount > 1,
          id: leadId,
          notification: "sent",
          ok: true,
        },
        { status: state.postCount > 1 ? 200 : 201 },
      );
    }
    throw new Error("unexpected public path");
  };
  const adapter = createProductionCandidateProviderAdapter({
    accountId,
    candidateExpected: candidateExpected(),
    cloudflareClient,
    databaseId,
    fetchImpl,
    productionWranglerAdapter,
    releaseBindingSha256,
    resendAdminClient,
    testRunId,
    workerExpected,
    zoneId,
  });
  return { adapter, leadId, release, state };
}

test("real provider adapter executes the five-route candidate path and archives the exact synthetic lead", async () => {
  const fixture = harness();
  let time = Date.parse("2026-09-01T12:00:05.000Z");
  const receipt = await executeProductionCandidateE2e({
    adapters: fixture.adapter,
    expected: candidateExpected(),
    poll: {
      intervalMilliseconds: 100,
      now: () => new Date(time),
      sleep: async (milliseconds) => {
        time += milliseconds;
      },
      timeoutMilliseconds: 2_000,
    },
    release: fixture.release,
    testRunId,
  });
  assert.equal(receipt.routes.rollbackVerified, true);
  assert.deepEqual(
    fixture.state.routes.map((route) => route.pattern).sort(),
    [...productionCandidateProviderAdapterConstants.candidatePatterns]
      .filter(
        (pattern) =>
          !productionCandidateProviderAdapterConstants.activationPatterns.includes(pattern),
      )
      .sort(),
  );
  assert.equal(fixture.state.synthetic, 1);
  assert.equal(fixture.state.status, "archived");
  assert.equal(fixture.state.version, 4);
  assert.equal(fixture.state.postCount, 2);
  assert.equal(receipt.resend.messageIdSha256, receipt.leadFlow.providerMessageIdSha256);
});

test("public HTTP boundary rejects non-candidate paths before fetch", async () => {
  const fixture = harness();
  await assert.rejects(
    fixture.adapter.http.request({
      body: null,
      headers: {},
      method: "GET",
      redirect: "manual",
      url: "https://freshtowels.gr/",
    }),
    /exact route boundary/,
  );
  assert.equal(fixture.state.fetches.length, 0);
});

test("D1 candidate mark rejects a substituted release binding before mutation", async () => {
  const fixture = harness();
  await assert.rejects(
    fixture.adapter.d1.markSynthetic({
      databaseId,
      leadId: fixture.leadId,
      releaseBindingSha256: "9".repeat(64),
      syntheticMarkerSha256: "8".repeat(64),
      testRunId,
    }),
    /identity changed/,
  );
  assert.equal(fixture.state.synthetic, 0);
});

test("D1 flow rejects a notification recipient substitution", async () => {
  const fixture = harness({ wrongRecipient: true });
  fixture.state.synthetic = 1;
  await assert.rejects(
    fixture.adapter.d1.inspectFlow({
      databaseId,
      leadId: fixture.leadId,
      syntheticMarkerSha256: "8".repeat(64),
      testRunId,
    }),
    /recipient or sender changed/,
  );
});

test("route mutation rejects stale authoritative state", async () => {
  const fixture = harness();
  await assert.rejects(
    fixture.adapter.routes.activate({
      expectedStateSha256: "0".repeat(64),
      patterns: productionCandidateProviderAdapterConstants.activationPatterns,
      releaseBindingSha256: digest(fixture.release),
      workerName: "fresh-towels-production",
      zoneId,
    }),
    /precondition changed/,
  );
  assert.equal(fixture.state.routes.length, 3);
});
