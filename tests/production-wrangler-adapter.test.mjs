import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { sha256 } from "../scripts/control-contract.mjs";
import { ProviderRejectedError } from "../scripts/provider-adapter.mjs";
import {
  createProductionWranglerAdapter,
  parseWranglerUploadedVersionId,
} from "../scripts/production-wrangler-adapter.mjs";

const accountId = "a".repeat(32);
const zoneId = "b".repeat(32);
const databaseId = "11111111-1111-4111-8111-111111111111";
const versionId = "22222222-2222-4222-8222-222222222222";
const secretNames = [
  "DASHBOARD_AUTHORIZED_EMAILS",
  "LEAD_RATE_LIMIT_SECRET",
  "RESEND_API_KEY",
  "RESEND_WEBHOOK_SECRET",
];

function response(result, complete = true) {
  return { result, pagination: { complete } };
}

function expectedVersion() {
  return {
    tag: "release-" + "a".repeat(32),
    message: "bound immutable release",
    workerName: "fresh-towels-production",
    uploadArtifactSha256: "1".repeat(64),
    configurationSha256: "2".repeat(64),
    runtimeSecretsSha256: "3".repeat(64),
    workerModuleSha256: "4".repeat(64),
    staticAssetsTreeSha256: "5".repeat(64),
    runtimeVariables: { A: "one", B: "two" },
    compatibilityDate: "2026-08-28",
    compatibilityFlags: ["nodejs_compat"],
    assetsBindingName: null,
  };
}

function exactBindings(expected = expectedVersion()) {
  return [
    { name: "LEADS_DB", type: "d1", database_id: databaseId },
    ...secretNames.map((name) => ({ name, type: "secret_text" })),
    ...Object.entries(expected.runtimeVariables).map(([name, text]) => ({
      name,
      text,
      type: "plain_text",
    })),
  ];
}

function versionDetail(expected = expectedVersion(), overrides = {}) {
  return {
    id: versionId,
    metadata: { source: "wrangler" },
    number: 1,
    resources: {
      bindings: exactBindings(expected),
      script: { etag: expected.workerModuleSha256 },
      script_runtime: {
        compatibility_date: expected.compatibilityDate,
        compatibility_flags: expected.compatibilityFlags,
      },
    },
    ...overrides,
  };
}

function adapterFor(
  client,
  runWrangler = async () => ({ stdout: "", outputSha256: "0".repeat(64) }),
) {
  return createProductionWranglerAdapter({
    cloudflareClient: client,
    cloudflareToken: "t".repeat(32),
    infrastructure: {
      cloudflare: { accountId, zoneId, d1: { primary: { databaseId } } },
    },
    resendAdminClient: { request: async () => response([]) },
    runWrangler,
  });
}

function exactReadbackClient(expected, mutate = (value) => value) {
  return {
    async request(input) {
      if (input.path.endsWith("/versions")) {
        return response({
          items: [{ id: versionId, metadata: { source: "wrangler" }, number: 1 }],
        });
      }
      if (input.path.endsWith(`/versions/${versionId}`)) {
        return response(mutate(structuredClone(versionDetail(expected))));
      }
      throw new Error("unexpected provider request: " + input.path);
    },
  };
}

test("same-invocation UUID reconciles the sole first Worker version with exact code, runtime, and bindings", async () => {
  const expected = expectedVersion();
  const adapter = adapterFor(exactReadbackClient(expected));
  await assert.rejects(
    adapter.inspectWorkerVersion({ workerName: expected.workerName }),
    /pre-existing Worker\/version/,
  );
  const worker = await adapter.inspectWorkerVersion(expected, versionId);
  assert.equal(worker.versionId, versionId);
  assert.equal(worker.workerModuleSha256, expected.workerModuleSha256);
  assert.equal(worker.assetsBindingName, null);
  assert.match(worker.stateSha256, /^[a-f0-9]{64}$/);
});

test("incomplete Worker list envelopes fail closed", async () => {
  const client = {
    async request() {
      return { result: { items: [] }, pagination: { complete: false } };
    },
  };
  await assert.rejects(
    adapterFor(client).inspectWorkerVersion({ workerName: "fresh-towels-production" }),
    /pagination is incomplete/,
  );
});

test("extra or missing bindings and substituted code/runtime/binding values fail exact readback", async () => {
  const expected = expectedVersion();
  const mutations = [
    (value) => {
      value.resources.bindings.push({ name: "UNEXPECTED", type: "plain_text", text: "x" });
      return value;
    },
    (value) => {
      value.resources.bindings = value.resources.bindings.filter(
        (binding) => binding.name !== "RESEND_WEBHOOK_SECRET",
      );
      return value;
    },
    (value) => {
      value.resources.bindings.find((binding) => binding.name === "A").text = "changed";
      return value;
    },
    (value) => {
      value.resources.bindings.find((binding) => binding.name === "LEADS_DB").database_id =
        "99999999-9999-4999-8999-999999999999";
      return value;
    },
    (value) => {
      value.resources.bindings.push({ name: "ASSETS", type: "assets" });
      return value;
    },
    (value) => {
      value.resources.script.etag = "9".repeat(64);
      return value;
    },
    (value) => {
      value.resources.script_runtime.compatibility_date = "2026-08-29";
      return value;
    },
    (value) => {
      value.resources.script_runtime.compatibility_flags = [];
      return value;
    },
  ];
  for (const mutate of mutations) {
    await assert.rejects(
      adapterFor(exactReadbackClient(expected, mutate)).inspectWorkerVersion(expected, versionId),
      /Worker (?:upload|version)/,
    );
  }
});

test("list substitution cannot be adopted by matching annotations", async () => {
  const expected = expectedVersion();
  const client = {
    async request(input) {
      if (input.path.endsWith("/versions")) {
        return response({
          items: [
            {
              id: "33333333-3333-4333-8333-333333333333",
              metadata: {
                source: "wrangler",
                tag: expected.tag,
                message: expected.message,
              },
              number: 1,
            },
          ],
        });
      }
      throw new Error("version detail must not be read for a substituted UUID");
    },
  };
  await assert.rejects(
    adapterFor(client).inspectWorkerVersion(expected, versionId),
    /sole first Wrangler version/,
  );
});

test("Wrangler upload output parser accepts one exact ID and rejects ambiguity", () => {
  assert.equal(
    parseWranglerUploadedVersionId(
      `Uploaded fresh-towels-production (1.23 sec)\nWorker Version ID: ${versionId}\n`,
    ),
    versionId,
  );
  for (const output of [
    "Uploaded without an identity\n",
    `Worker Version ID: ${versionId}\nWorker Version ID: ${versionId}\n`,
    `Worker Version ID: ${versionId}\nother ${"33333333-3333-4333-8333-333333333333"}\n`,
    `Worker Version ID: ${"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".toUpperCase()}\n`,
  ]) {
    assert.throws(() => parseWranglerUploadedVersionId(output), /one exact Worker Version ID/);
  }
});

test("upload binds the sole new version to the ID returned by this Wrangler invocation", async () => {
  const root = await mkdtemp(join(tmpdir(), "production-worker-upload-"));
  const expected = expectedVersion();
  let exists = false;
  const calls = [];
  const client = {
    async request(input) {
      calls.push(`${input.method} ${input.path}`);
      if (input.path.endsWith("/versions")) {
        if (!exists) throw new ProviderRejectedError(404);
        return response({
          items: [{ id: versionId, metadata: { source: "wrangler" }, number: 1 }],
        });
      }
      if (input.path.endsWith(`/versions/${versionId}`)) {
        return response(versionDetail(expected));
      }
      throw new Error("unexpected provider request: " + input.path);
    },
  };
  const adapter = adapterFor(client, async (arguments_) => {
    assert.deepEqual(arguments_.slice(0, 2), ["versions", "upload"]);
    exists = true;
    return {
      stdout: `Uploaded fresh-towels-production\nWorker Version ID: ${versionId}\n`,
      outputSha256: sha256(Buffer.from("synthetic Wrangler output")),
    };
  });
  const runtimeSecrets = Object.fromEntries(
    secretNames.map((name, index) => [name, { bytes: Buffer.from(`synthetic-${index}`) }]),
  );
  try {
    const result = await adapter.uploadWorkerVersion({
      expected,
      hydratedConfiguration: { path: join(root, "wrangler.jsonc") },
      materialized: { root },
      runtimeSecrets,
    });
    assert.equal(result.versionId, versionId);
    assert.equal(calls.filter((call) => call.endsWith("/versions")).length, 2);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("additive secrets upload is refused while any Worker already exists", async () => {
  const root = await mkdtemp(join(tmpdir(), "production-worker-existing-"));
  let wranglerCalled = false;
  const expected = expectedVersion();
  const client = exactReadbackClient(expected);
  const adapter = adapterFor(client, async () => {
    wranglerCalled = true;
    throw new Error("Wrangler must not run");
  });
  const runtimeSecrets = Object.fromEntries(
    secretNames.map((name, index) => [name, { bytes: Buffer.from(`synthetic-${index}`) }]),
  );
  try {
    await assert.rejects(
      adapter.uploadWorkerVersion({
        expected,
        hydratedConfiguration: { path: join(root, "wrangler.jsonc") },
        materialized: { root },
        runtimeSecrets,
      }),
      /pre-existing Worker\/version/,
    );
    assert.equal(wranglerCalled, false);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("first-release rollback deletes the owned Worker and proves empty deployments, crons, and routes", async () => {
  let exists = true;
  const client = {
    async request(input) {
      if (input.method === "DELETE" && input.path.endsWith("/fresh-towels-production")) {
        exists = false;
        return response({});
      }
      if (input.path.endsWith("/versions")) {
        if (!exists) throw new ProviderRejectedError(404);
        return response({
          items: [{ id: versionId, metadata: { source: "wrangler" }, number: 1 }],
        });
      }
      if (input.path.endsWith("/deployments") || input.path.endsWith("/schedules")) {
        if (!exists) throw new ProviderRejectedError(404);
        return response(input.path.endsWith("/deployments") ? { deployments: [] } : { schedules: [] });
      }
      if (input.path === `/zones/${zoneId}/workers/routes`) return response([]);
      throw new Error("unexpected provider request: " + input.path);
    },
  };
  await adapterFor(client).rollbackWorkerDeployment({
    workerName: "fresh-towels-production",
    createdVersionId: versionId,
    previousDeployment: null,
    previousTriggers: { crons: [], routes: [], stateSha256: "8".repeat(64) },
  });
  assert.equal(exists, false);
});

test("first-release rollback fails when deletion is not authoritatively reconciled", async () => {
  const client = {
    async request(input) {
      if (input.method === "DELETE") return response({});
      if (input.path.endsWith("/versions")) {
        return response({
          items: [{ id: versionId, metadata: { source: "wrangler" }, number: 1 }],
        });
      }
      if (input.path.endsWith("/deployments")) return response({ deployments: [] });
      if (input.path.endsWith("/schedules")) return response({ schedules: [] });
      if (input.path === `/zones/${zoneId}/workers/routes`) return response([]);
      throw new Error("unexpected provider request: " + input.path);
    },
  };
  await assert.rejects(
    adapterFor(client).rollbackWorkerDeployment({
      workerName: "fresh-towels-production",
      createdVersionId: versionId,
      previousDeployment: null,
      previousTriggers: { crons: [], routes: [], stateSha256: "8".repeat(64) },
    }),
    /did not restore the empty baseline/,
  );
});
