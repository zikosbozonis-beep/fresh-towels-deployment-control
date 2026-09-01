import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  productionCandidateRoutes,
  productionCutoverConstants,
  productionPreCutoverRoutes,
  productionFullRoutes,
} from "../scripts/production-cutover-adapter.mjs";
import { createProductionCutoverProviderAdapter } from "../scripts/production-cutover-provider-adapter.mjs";
import {
  createCloudflareHttpAdapter,
  ProviderTransportAmbiguousError,
} from "../scripts/provider-adapter.mjs";
import { inspectProductionCutoverWorkerState } from "../scripts/production-wrangler-adapter.mjs";

const accountId = "a".repeat(32);
const zoneId = "b".repeat(32);
const workerName = "fresh-towels-production";
const adminIdentity = "owner-admin@example.net";
const applicationId = "11111111-1111-4111-8111-111111111111";

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
}

function request(method, path, options = {}) {
  return {
    method,
    path,
    body: options.body,
    bodyBytes: options.bodyBytes,
    bodySha256: options.bodySha256,
    contentType: options.contentType,
    idempotencyKey: options.idempotencyKey ?? null,
    query: options.query,
  };
}

function cloudflareResponse(result) {
  return new Response(JSON.stringify({ success: true, result }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function dependencies(overrides = {}) {
  return {
    accountId,
    adminIdentity,
    cloudflareClient: overrides.cloudflareClient,
    fetchImpl: overrides.fetchImpl ?? (async () => new Response("")),
    inspectCandidateE2e: async (input) => ({ input, kind: "candidate" }),
    inspectProviderState: async (input) => ({ input, kind: "provider" }),
    inspectWorkerState: async (input) => ({ input, kind: "worker" }),
    now: overrides.now ?? (() => new Date("2026-09-01T10:00:00.000Z")),
    workerName,
    zoneId,
  };
}

test("Cloudflare provider allowlist permits only exact route and Access-audit calls", async () => {
  const observed = [];
  const client = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl: async (url, options) => {
      observed.push({ url: String(url), method: options.method });
      return cloudflareResponse([]);
    },
  });
  await client.request(request("GET", `/zones/${zoneId}/workers/routes`));
  const body = { pattern: productionFullRoutes[0], script: workerName };
  await client.request(
    request("POST", `/zones/${zoneId}/workers/routes`, {
      body,
      bodySha256: digest(body),
      idempotencyKey: "1".repeat(64),
    }),
  );
  await client.request(
    request("DELETE", `/zones/${zoneId}/workers/routes/${"c".repeat(32)}`, {
      idempotencyKey: "2".repeat(64),
    }),
  );
  await client.request(
    request("GET", `/accounts/${accountId}/access/logs/access_requests`, {
      query: {
        direction: "desc",
        email: adminIdentity,
        emailOp: "eq",
        limit: "100",
        since: "2026-09-01T09:00:00.000Z",
        until: "2026-09-01T10:00:00.000Z",
      },
    }),
  );
  assert.deepEqual(
    observed.map((value) => value.method),
    ["GET", "POST", "DELETE", "GET"],
  );
  await assert.rejects(
    client.request(
      request("GET", `/accounts/${accountId}/access/logs/access_requests`, {
        query: {
          direction: "desc",
          email: adminIdentity,
          limit: "100",
          since: "2026-09-01T09:00:00.000Z",
          until: "2026-09-01T10:00:00.000Z",
        },
      }),
    ),
    /query|allowlist/,
  );
  await assert.rejects(
    client.request(request("DELETE", `/zones/${zoneId}/workers/routes/not-an-id`)),
    /allowlist/,
  );
});

test("route cutover mutates only the exact Worker-owned route set", async () => {
  let serial = 10;
  let routes = productionPreCutoverRoutes.map((pattern, index) => ({
    id: (index + 1).toString(16).padStart(32, "0"),
    pattern,
    script: workerName,
  }));
  routes.push({ id: "f".repeat(32), pattern: "unrelated.example/*", script: "other" });
  const calls = [];
  const cloudflareClient = {
    async request(input) {
      calls.push({ method: input.method, path: input.path });
      if (input.method === "GET") return { result: structuredClone(routes) };
      if (input.method === "DELETE") {
        const id = input.path.split("/").at(-1);
        routes = routes.filter((route) => route.id !== id);
        return { result: { id } };
      }
      if (input.method === "POST") {
        routes.push({
          id: (serial++).toString(16).padStart(32, "0"),
          pattern: input.body.pattern,
          script: input.body.script,
        });
        return { result: routes.at(-1) };
      }
      throw new Error("unexpected method");
    },
  };
  const adapter = createProductionCutoverProviderAdapter(
    dependencies({ cloudflareClient }),
  );
  await adapter.setExactRoutes({
    desiredPatterns: productionFullRoutes,
    expectedPreviousPatterns: productionPreCutoverRoutes,
    idempotencyKey: "1".repeat(64),
    workerName,
  });
  const live = await adapter.inspectRoutes({ workerName });
  assert.deepEqual(live.patterns, productionFullRoutes);
  assert.equal(
    routes.some((route) => route.pattern === "unrelated.example/*" && route.script === "other"),
    true,
  );
  assert.equal(calls.filter((call) => call.method === "POST").length, 2);
  assert.equal(calls.filter((call) => call.method === "DELETE").length, 3);
});

test("ambiguous route transport is reconciled once without repeating a landed mutation", async () => {
  let routes = productionPreCutoverRoutes.map((pattern, index) => ({
    id: (index + 1).toString(16).padStart(32, "0"),
    pattern,
    script: workerName,
  }));
  let serial = 20;
  const mutationCounts = new Map();
  const cloudflareClient = {
    async request(input) {
      if (input.method === "GET") return { result: structuredClone(routes) };
      const key = `${input.method}:${input.body?.pattern ?? input.path.split("/").at(-1)}`;
      mutationCounts.set(key, (mutationCounts.get(key) ?? 0) + 1);
      if (input.method === "DELETE") {
        const id = input.path.split("/").at(-1);
        routes = routes.filter((route) => route.id !== id);
        return { result: { id } };
      }
      routes.push({
        id: (serial++).toString(16).padStart(32, "0"),
        pattern: input.body.pattern,
        script: workerName,
      });
      if (input.body.pattern === productionFullRoutes[0]) {
        throw new ProviderTransportAmbiguousError("synthetic-timeout");
      }
      return { result: routes.at(-1) };
    },
  };
  const adapter = createProductionCutoverProviderAdapter(
    dependencies({ cloudflareClient }),
  );
  await adapter.setExactRoutes({
    desiredPatterns: productionFullRoutes,
    expectedPreviousPatterns: productionPreCutoverRoutes,
    idempotencyKey: "2".repeat(64),
    workerName,
  });
  assert.deepEqual((await adapter.inspectRoutes({ workerName })).patterns, productionFullRoutes);
  assert.equal(mutationCounts.get(`POST:${productionFullRoutes[0]}`), 1);
});

test("foreign overlap fails before any route mutation", async () => {
  const routes = [
    ...productionCandidateRoutes.map((pattern, index) => ({
      id: (index + 1).toString(16).padStart(32, "0"),
      pattern,
      script: workerName,
    })),
    { id: "e".repeat(32), pattern: "freshtowels.gr/private/*", script: "foreign" },
  ];
  let mutations = 0;
  const adapter = createProductionCutoverProviderAdapter(
    dependencies({
      cloudflareClient: {
        async request(input) {
          if (input.method === "GET") return { result: structuredClone(routes) };
          mutations += 1;
          return { result: {} };
        },
      },
    }),
  );
  await assert.rejects(
    adapter.setExactRoutes({
      desiredPatterns: productionFullRoutes,
      expectedPreviousPatterns: productionCandidateRoutes,
      idempotencyKey: "3".repeat(64),
      workerName,
    }),
    /overlaps/,
  );
  assert.equal(mutations, 0);
});

test("Access audit proves the exact allowed owner login without returning the email or ray ID", async () => {
  let observedQuery;
  const occurredAt = "2026-09-01T09:30:00.000Z";
  const adapter = createProductionCutoverProviderAdapter(
    dependencies({
      cloudflareClient: {
        async request(input) {
          observedQuery = input.query;
          return {
            result: [
              {
                action: "login",
                allowed: true,
                app_domain: "https://freshtowels.gr/internal/leads/",
                app_uid: applicationId,
                created_at: occurredAt,
                ray_id: "1234567890abcdef",
                user_email: adminIdentity,
              },
            ],
          };
        },
      },
    }),
  );
  const evidence = await adapter.inspectAccessAudit({
    after: "2026-09-01T09:00:00.000Z",
    adminIdentitySha256: sha256(Buffer.from(adminIdentity)),
    applicationDomain: "freshtowels.gr/internal/leads",
    applicationId,
  });
  assert.equal(evidence.decision, "allow");
  assert.equal(evidence.eventType, "login");
  assert.equal(evidence.occurredAt, occurredAt);
  assert.equal(observedQuery.emailOp, "eq");
  assert.equal(observedQuery.direction, "desc");
  const serialized = JSON.stringify(evidence);
  assert.equal(serialized.includes(adminIdentity), false);
  assert.equal(serialized.includes("1234567890abcdef"), false);
});

test("external smoke inspects the real production surface contract without following www", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), redirect: options.redirect });
    const parsed = new URL(url);
    if (parsed.hostname === "www.freshtowels.gr") {
      return new Response(null, {
        status: 301,
        headers: { location: "https://freshtowels.gr/" },
      });
    }
    if (parsed.pathname === "/robots.txt") {
      return new Response("User-agent: *\nAllow: /\n", { status: 200 });
    }
    if (parsed.pathname === "/sitemap.xml") {
      return new Response("<?xml version=\"1.0\"?><urlset></urlset>", { status: 200 });
    }
    return new Response(
      `<html><head><link href="https://freshtowels.gr${parsed.pathname}" rel="canonical"></head><body>Fresh Towels</body></html>`,
      { status: 200, headers: { "content-type": "text/html" } },
    );
  };
  const adapter = createProductionCutoverProviderAdapter(
    dependencies({ cloudflareClient: { request() {} }, fetchImpl }),
  );
  const evidence = await adapter.inspectExternalSmoke({
    criticalRoutes: productionCutoverConstants.criticalRoutes,
    origin: "https://freshtowels.gr",
    wwwOrigin: "https://www.freshtowels.gr",
  });
  assert.equal(evidence.httpsValid, true);
  assert.equal(evidence.wwwRedirectStatus, 301);
  assert.equal(evidence.productionNoindexCount, 0);
  assert.equal(evidence.stagingReferenceCount, 0);
  assert.equal(evidence.robotsIndexable, true);
  assert.equal(calls[0].redirect, "manual");
});

test("cutover Worker readback recomputes the exact version and deployment digests", async () => {
  const versionId = "77777777-7777-4777-8777-777777777777";
  const version = {
    id: versionId,
    metadata: { source: "wrangler" },
    number: 1,
    resources: { script: { etag: "8".repeat(64) } },
  };
  const deployment = {
    id: "deployment-one",
    versions: [{ percentage: 100, version_id: versionId }],
  };
  const approvedWorker = {
    name: workerName,
    versionId,
    versionStateSha256: digest(version),
    deploymentStateSha256: digest(deployment),
  };
  const client = {
    async request(input) {
      if (input.path.endsWith("/versions")) {
        return {
          pagination: { complete: true },
          result: [{ id: versionId, metadata: { source: "wrangler" }, number: 1 }],
        };
      }
      if (input.path.endsWith(`/versions/${versionId}`)) return { result: version };
      if (input.path.endsWith("/deployments")) {
        return { result: { deployments: [deployment] } };
      }
      throw new Error("unexpected inspection");
    },
  };
  const state = await inspectProductionCutoverWorkerState({
    accountId,
    approvedWorker,
    cloudflareClient: client,
  });
  assert.equal(state.versionId, versionId);
  assert.equal(state.percentage, 100);
  await assert.rejects(
    inspectProductionCutoverWorkerState({
      accountId,
      approvedWorker: { ...approvedWorker, versionStateSha256: "9".repeat(64) },
      cloudflareClient: client,
    }),
    /version state changed/,
  );
});
