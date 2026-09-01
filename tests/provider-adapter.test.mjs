import assert from "node:assert/strict";
import test from "node:test";

import { sha256 } from "../scripts/control-contract.mjs";
import {
  AmbiguousProviderResultError,
  createCloudflareHttpAdapter,
  createResendHttpAdapter,
  executeReconciledProviderOperation,
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
  validateProviderReceipt,
} from "../scripts/provider-adapter.mjs";
import { finalizeProviderOperation } from "../scripts/provider-plan.mjs";

function release() {
  return {
    requestId: "11111111-1111-4111-8111-111111111111",
    releaseId: "a".repeat(64),
    applicationCommitSha: "1".repeat(40),
    controllerCommitSha: "2".repeat(40),
    artifactSha256: "b".repeat(64),
    plaintextSha256: "c".repeat(64),
    uploadArtifactSha256: "d".repeat(64),
    evidenceSha256: "e".repeat(64),
  };
}

function operation({ mutation = true } = {}) {
  return finalizeProviderOperation(release(), {
    sequence: 1,
    provider: "cloudflare",
    action: mutation ? "cloudflare.d1.database.ensure" : "cloudflare.account.verify",
    resource: {
      kind: mutation ? "d1-database" : "account",
      name: mutation ? "fresh-towels-leads-prod" : "fresh-towels-account",
      identitySha256: "f".repeat(64),
    },
    desiredStateSha256: sha256(Buffer.from("desired")),
    mutation,
  });
}

function request(path, overrides = {}) {
  return {
    method: "GET",
    path,
    body: undefined,
    bodyBytes: undefined,
    bodySha256: undefined,
    contentType: undefined,
    idempotencyKey: null,
    query: undefined,
    ...overrides,
  };
}

function jsonResponse(value, { status = 200, headers = {} } = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

test("Cloudflare and Resend HTTP adapters allow only pinned provider origins and path families", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (url.includes("cloudflare")) {
      return jsonResponse({ success: true, result: { id: "safe-id" } }, {
        headers: { "cf-ray": "abc123-ATH" },
      });
    }
    return jsonResponse({ id: "safe-id" }, { headers: { "x-request-id": "resend-123" } });
  };
  const cloudflare = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl,
  });
  const resend = createResendHttpAdapter({
    token: "synthetic-resend-token-value",
    fetchImpl,
  });
  const cfResult = await cloudflare.request(request("/accounts/" + "a".repeat(32)));
  const d1Result = await cloudflare.request(
    request("/accounts/" + "a".repeat(32) + "/d1/database", {
      query: {
        name: "ft-provider-canary-aaaaaaaaaaaa-aaaaaaa",
        page: "1",
        per_page: "10000",
      },
    }),
  );
  const resendResult = await resend.request(request("/domains/domain_123"));
  await cloudflare.request(
    request(
      "/accounts/" +
        "a".repeat(32) +
        "/access/identity_providers/11111111-1111-4111-8111-111111111111",
    ),
  );
  await cloudflare.request(
    request("/zones/" + "b".repeat(32) + "/dns_records/" + "c".repeat(32)),
  );
  assert.equal(cfResult.providerRequestId, "abc123-ATH");
  assert.equal(resendResult.providerRequestId, "resend-123");
  assert.equal(calls[0].url, "https://api.cloudflare.com/client/v4/accounts/" + "a".repeat(32));
  assert.equal(
    calls[1].url,
    "https://api.cloudflare.com/client/v4/accounts/" +
      "a".repeat(32) +
      "/d1/database?name=ft-provider-canary-aaaaaaaaaaaa-aaaaaaa&page=1&per_page=10000",
  );
  assert.equal(calls[2].url, "https://api.resend.com/domains/domain_123");
  assert.equal(
    calls[3].url,
    "https://api.cloudflare.com/client/v4/accounts/" +
      "a".repeat(32) +
      "/access/identity_providers/11111111-1111-4111-8111-111111111111",
  );
  assert.equal(
    calls[4].url,
    "https://api.cloudflare.com/client/v4/zones/" +
      "b".repeat(32) +
      "/dns_records/" +
      "c".repeat(32),
  );
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.headers.get("Authorization"), "Bearer synthetic-cloudflare-token-value");
  assert.ok(!JSON.stringify(cfResult).includes("synthetic-cloudflare-token-value"));
});

test("Cloudflare adapter allows only the exact zone and Access application detail inspections", async () => {
  const calls = [];
  const adapter = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl: async (url) => {
      calls.push(url);
      return jsonResponse({ success: true, result: { id: "safe-id" } });
    },
  });
  const account = "a".repeat(32);
  const zone = "b".repeat(32);
  const application = "11111111-1111-4111-8111-111111111111";
  await adapter.request(request(`/zones/${zone}`));
  await adapter.request(request(`/accounts/${account}/access/apps/${application}`));
  await adapter.request(request(`/zones/${zone}/settings/ssl`));
  await adapter.request(request(`/zones/${zone}/settings/ssl`, {
    method: "PATCH",
    body: { value: "strict" },
    bodySha256: undefined,
  }));
  assert.deepEqual(calls, [
    `https://api.cloudflare.com/client/v4/zones/${zone}`,
    `https://api.cloudflare.com/client/v4/accounts/${account}/access/apps/${application}`,
    `https://api.cloudflare.com/client/v4/zones/${zone}/settings/ssl`,
    `https://api.cloudflare.com/client/v4/zones/${zone}/settings/ssl`,
  ]);
  await assert.rejects(
    adapter.request(request(`/zones/${zone}/settings`)),
    /allowlist/,
  );
  await assert.rejects(
    adapter.request(request(`/zones/${zone}/settings/ssl`, {
      method: "PATCH",
      body: { value: "full" },
    })),
    /exact allowlist/,
  );
  await assert.rejects(
    adapter.request(request(`/zones/${zone}/settings/hsts`)),
    /allowlist/,
  );
});

test("HTTP adapter rejects arbitrary paths, queries, invalid bodies and unbound binary bytes pre-network", async () => {
  let calls = 0;
  const adapter = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({ success: true, result: {} });
    },
  });
  await assert.rejects(adapter.request(request("/user/tokens/verify")), /allowlist/);
  await assert.rejects(
    adapter.request(request("/accounts/" + "a".repeat(32), { method: "DELETE" })),
    /method|allowlist/,
  );
  await assert.rejects(
    adapter.request(request("/accounts/" + "a".repeat(32) + "?page=1")),
    /allowlist/,
  );
  await assert.rejects(
    adapter.request(
      request("/accounts/" + "a".repeat(32) + "/d1/database", {
        query: { page: "1" },
      }),
    ),
    /query|unexpected/,
  );
  await assert.rejects(
    adapter.request(request("/accounts/" + "a".repeat(32) + "/d1/database")),
    /page boundary/,
  );
  await assert.rejects(
    adapter.request(
      request("/accounts/" + "a".repeat(32) + "/d1/database", {
        query: { name: "ft-provider-canary-aaaa", page: "1", per_page: "100" },
      }),
    ),
    /page boundary/,
  );
  await assert.rejects(
    adapter.request(
      request("/accounts/" + "a".repeat(32) + "/d1/database", {
        method: "POST",
        body: undefined,
        bodyBytes: Buffer.from("immutable"),
        bodySha256: "0".repeat(64),
        contentType: "application/octet-stream",
        idempotencyKey: "1".repeat(64),
      }),
    ),
    /digest-bound/,
  );
  await assert.rejects(
    adapter.request({
      ...request("/accounts/" + "a".repeat(32)),
      unexpected: "command",
    }),
    /unexpected/,
  );
  assert.equal(calls, 0);
});

test("list pagination is proven complete from provider-native envelopes and otherwise fails closed", async () => {
  const account = "a".repeat(32);
  const path = `/accounts/${account}/d1/database`;
  const complete = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl: async () =>
      jsonResponse({
        success: true,
        result: [],
        result_info: { page: 1, per_page: 10000, count: 0, total_count: 0 },
      }),
  });
  const incomplete = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl: async () => jsonResponse({ success: true, result: [] }),
  });
  const boundaryFull = createCloudflareHttpAdapter({
    token: "synthetic-cloudflare-token-value",
    fetchImpl: async () =>
      jsonResponse({
        success: true,
        result: Array.from({ length: 10_000 }, () => null),
        result_info: { page: 1, per_page: 10_000, count: 10_000, total_count: 10_000 },
      }),
  });
  const resendComplete = createResendHttpAdapter({
    token: "synthetic-resend-token-value",
    fetchImpl: async () => jsonResponse({ object: "list", has_more: false, data: [] }),
  });
  const resendIncomplete = createResendHttpAdapter({
    token: "synthetic-resend-token-value",
    fetchImpl: async () => jsonResponse({ object: "list", has_more: true, data: [] }),
  });
  assert.equal(
    (await complete.request(request(path, {
      query: { name: "ft-provider-canary-aaaa", page: "1", per_page: "10000" },
    }))).pagination.complete,
    true,
  );
  assert.equal(
    (await incomplete.request(request(path, {
      query: { name: "ft-provider-canary-aaaa", page: "1", per_page: "10000" },
    }))).pagination.complete,
    false,
  );
  assert.equal(
    (await boundaryFull.request(request(path, {
      query: { name: "ft-provider-canary-aaaa", page: "1", per_page: "10000" },
    }))).pagination.complete,
    false,
  );
  assert.equal(
    (await resendComplete.request(request("/domains", { query: { limit: "100" } }))).pagination.complete,
    true,
  );
  assert.equal(
    (await resendIncomplete.request(request("/domains", { query: { limit: "100" } }))).pagination.complete,
    false,
  );
});

test("HTTP adapter sends canonical digest-bound JSON with idempotency and never returns credentials", async () => {
  const token = "synthetic-resend-token-value";
  let captured;
  const adapter = createResendHttpAdapter({
    token,
    fetchImpl: async (_url, options) => {
      captured = options;
      return jsonResponse({ id: "email_123" });
    },
  });
  const body = { z: 1, a: "value" };
  const bodyBytes = Buffer.from('{"a":"value","z":1}\n');
  const result = await adapter.request(
    request("/emails", {
      method: "POST",
      body,
      bodySha256: sha256(bodyBytes),
      idempotencyKey: "9".repeat(64),
    }),
  );
  assert.equal(Buffer.from(captured.body).toString(), bodyBytes.toString());
  assert.equal(captured.headers.get("Idempotency-Key"), "9".repeat(64));
  assert.ok(!JSON.stringify(result).includes(token));
});

test("transport uncertainty and 429/5xx fail ambiguous while deterministic 4xx rejects", async () => {
  const path = "/domains/domain_123";
  const network = createResendHttpAdapter({
    token: "synthetic-resend-token-value",
    fetchImpl: async () => {
      throw new Error("secret network detail");
    },
  });
  await assert.rejects(network.request(request(path)), ProviderTransportAmbiguousError);
  for (const status of [408, 409, 425, 429, 500, 503]) {
    const adapter = createResendHttpAdapter({
      token: "synthetic-resend-token-value",
      fetchImpl: async () => jsonResponse({ message: "private provider body" }, { status }),
    });
    await assert.rejects(adapter.request(request(path)), ProviderTransportAmbiguousError);
  }
  const rejected = createResendHttpAdapter({
    token: "synthetic-resend-token-value",
    fetchImpl: async () => jsonResponse({ message: "private provider body" }, { status: 403 }),
  });
  await assert.rejects(rejected.request(request(path)), ProviderRejectedError);
});

test("Resend rejection preserves only allowlisted error identity without provider-body leakage", async () => {
  const secretMessage = "private provider detail must not escape";
  for (const fixture of [
    {
      status: 401,
      body: { name: "restricted_api_key", message: secretMessage },
      expectedCode: "restricted_api_key",
    },
    {
      status: 403,
      body: { name: "invalid_api_key", message: secretMessage },
      expectedCode: "invalid_api_key",
    },
    {
      status: 401,
      body: { code: "restricted_api_key", message: secretMessage },
      expectedCode: "restricted_api_key",
    },
    {
      status: 401,
      body: {
        name: "restricted_api_key",
        code: "invalid_api_key",
        message: secretMessage,
      },
      expectedCode: null,
    },
    {
      status: 401,
      body: { name: "unexpected_provider_code", message: secretMessage },
      expectedCode: null,
    },
    { status: 401, body: { message: secretMessage }, expectedCode: null },
  ]) {
    const adapter = createResendHttpAdapter({
      token: "synthetic-resend-token-value",
      fetchImpl: async () => jsonResponse(fixture.body, { status: fixture.status }),
    });
    await assert.rejects(adapter.request(request("/api-keys", { query: { limit: "100" } })), (error) => {
      assert.ok(error instanceof ProviderRejectedError);
      assert.equal(error.status, fixture.status);
      assert.equal(error.providerErrorCode, fixture.expectedCode);
      assert.ok(!error.message.includes(secretMessage));
      assert.ok(!JSON.stringify(error).includes(secretMessage));
      return true;
    });
  }
});

test("reconciler returns an immutable non-secret unchanged receipt without mutation", async () => {
  let mutations = 0;
  const state = sha256(Buffer.from("desired"));
  const receipt = await executeReconciledProviderOperation({
    operation: operation(),
    release: release(),
    adapter: {
      inspect: async () => ({
        state: "desired",
        stateSha256: state,
        providerRequestId: "inspect-1",
      }),
      mutate: async () => {
        mutations += 1;
      },
    },
    now: () => new Date("2026-09-01T16:00:00.000Z"),
  });
  assert.equal(receipt.result, "unchanged");
  assert.equal(receipt.preStateSha256, state);
  assert.equal(receipt.postStateSha256, state);
  assert.equal(mutations, 0);
  assert.equal(validateProviderReceipt(receipt), true);
  assert.ok(!JSON.stringify(receipt).includes("@"));
});

test("reconciler mutates once, post-verifies desired state, and emits exact release evidence", async () => {
  let inspections = 0;
  let mutations = 0;
  const before = sha256(Buffer.from("absent"));
  const after = sha256(Buffer.from("desired"));
  const receipt = await executeReconciledProviderOperation({
    operation: operation(),
    release: release(),
    adapter: {
      inspect: async () => {
        inspections += 1;
        return {
          state: inspections === 1 ? "absent" : "desired",
          stateSha256: inspections === 1 ? before : after,
          providerRequestId: "inspect-" + inspections,
        };
      },
      mutate: async () => {
        mutations += 1;
        return { status: "accepted", result: "created", providerRequestId: "mutate-1" };
      },
    },
    now: () => new Date("2026-09-01T16:00:00.000Z"),
  });
  assert.equal(inspections, 2);
  assert.equal(mutations, 1);
  assert.equal(receipt.result, "created");
  assert.equal(receipt.sourceCommitSha, release().applicationCommitSha);
  assert.equal(receipt.controllerCommitSha, release().controllerCommitSha);
  assert.equal(receipt.artifactSha256, release().artifactSha256);
  assert.equal(validateProviderReceipt(receipt), true);
});

test("an ambiguous mutation is never blindly retried and succeeds only after authoritative convergence", async () => {
  let inspections = 0;
  let mutations = 0;
  const receipt = await executeReconciledProviderOperation({
    operation: operation(),
    release: release(),
    adapter: {
      inspect: async () => {
        inspections += 1;
        return {
          state: inspections === 1 ? "absent" : "desired",
          stateSha256: sha256(Buffer.from(inspections === 1 ? "absent" : "desired")),
          providerRequestId: "inspect-" + inspections,
        };
      },
      mutate: async () => {
        mutations += 1;
        throw new ProviderTransportAmbiguousError("timeout", {
          providerRequestId: "mutation-timeout",
        });
      },
    },
    now: () => new Date("2026-09-01T16:00:00.000Z"),
  });
  assert.equal(mutations, 1);
  assert.equal(inspections, 2);
  assert.equal(receipt.result, "verified");
  assert.equal(validateProviderReceipt(receipt), true);
});

test("unreconciled partial/ambiguous mutation fails closed with a hash-only ambiguous receipt", async () => {
  let mutations = 0;
  await assert.rejects(
    executeReconciledProviderOperation({
      operation: operation(),
      release: release(),
      adapter: {
        inspect: async () => ({
          state: "drifted",
          stateSha256: sha256(Buffer.from("drifted")),
          providerRequestId: "inspect",
        }),
        mutate: async () => {
          mutations += 1;
          throw new ProviderTransportAmbiguousError("timeout", {
            providerRequestId: "timeout",
          });
        },
      },
      now: () => new Date("2026-09-01T16:00:00.000Z"),
    }),
    (error) => {
      assert.ok(error instanceof AmbiguousProviderResultError);
      assert.equal(error.receipt.result, "ambiguous");
      assert.equal(validateProviderReceipt(error.receipt), true);
      assert.ok(!JSON.stringify(error.receipt).includes("secret"));
      return true;
    },
  );
  assert.equal(mutations, 1);
});

test("read-only operations fail closed when authoritative state is not desired", async () => {
  await assert.rejects(
    executeReconciledProviderOperation({
      operation: operation({ mutation: false }),
      release: release(),
      adapter: {
        inspect: async () => ({
          state: "drifted",
          stateSha256: sha256(Buffer.from("drifted")),
          providerRequestId: null,
        }),
      },
    }),
    ProviderRejectedError,
  );
});

test("a provider cannot label the wrong state digest as desired", async () => {
  await assert.rejects(
    executeReconciledProviderOperation({
      operation: operation(),
      release: release(),
      adapter: {
        inspect: async () => ({
          state: "desired",
          stateSha256: "0".repeat(64),
          providerRequestId: null,
        }),
        mutate: async () => undefined,
      },
      now: () => new Date("2026-09-01T16:00:00.000Z"),
    }),
    AmbiguousProviderResultError,
  );
});

test("receipt tampering and public email/name leakage are rejected", async () => {
  const receipt = await executeReconciledProviderOperation({
    operation: operation(),
    release: release(),
    adapter: {
      inspect: async () => ({
        state: "desired",
        stateSha256: sha256(Buffer.from("desired")),
        providerRequestId: null,
      }),
      mutate: async () => undefined,
    },
    now: () => new Date("2026-09-01T16:00:00.000Z"),
  });
  assert.throws(
    () => validateProviderReceipt({ ...receipt, result: "updated" }),
    /binding/,
  );
  assert.throws(
    () => validateProviderReceipt({ ...receipt, resourceName: "info@freshtowels.gr" }),
    /binding/,
  );
});
