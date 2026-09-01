import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  ciphertextCustodyClientBindings,
  createCiphertextCustodyBrokerClient,
  createGpgCiphertextCustodySinks,
} from "../scripts/ciphertext-custody-client.mjs";
import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";

const requestId = "11111111-1111-4111-8111-111111111111";

async function releaseRequestBase64({
  operation = "production-bootstrap",
  exactRequestId = requestId,
} = {}) {
  const publicKey = await readFile(
    new URL("../keys/release-encryption-public.asc", import.meta.url),
  );
  const now = Date.now();
  const request = {
    artifact: {
      ciphertextBlobSha1: "4".repeat(40),
      ciphertextSha256: "5".repeat(64),
      encryptionKeySha256: sha256(publicKey),
      manifestBlobSha1: "6".repeat(40),
      plaintextBytes: 100,
      plaintextSha256: "7".repeat(64),
      releaseId: "9009",
      transportCommitSha: "8".repeat(40),
      transportTag: `deployment-control/${exactRequestId}`,
    },
    controller: { commitSha: "2".repeat(40), repositoryId: "2002" },
    evidence: {
      immutableRelease: true,
      manifestSha256: "9".repeat(64),
      oidcTokenSha256: "a".repeat(64),
    },
    expiresAt: new Date(now + 10 * 60_000).toISOString(),
    issuedAt: new Date(now - 1_000).toISOString(),
    nonce: randomBytes(32).toString("base64url"),
    operation,
    requestId: exactRequestId,
    schema: "deployment-control/release-request/v1",
    source: {
      commitSha: "1".repeat(40),
      repositoryId: "1001",
      workflowRunAttempt: 1,
      workflowRunId: "8008",
    },
  };
  return Buffer.from(canonicalJson(request), "utf8").toString("base64url");
}

function oidc() {
  return `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`;
}

test("broker client binds every protected response to the exact release request", async () => {
  const encoded = await releaseRequestBase64();
  const requestDigest = sha256(Buffer.from(encoded, "base64url"));
  const calls = [];
  const client = createCiphertextCustodyBrokerClient({
    dispatcherOrigin: "https://dispatcher.example/",
    getOidcToken: async () => oidc(),
    releaseRequestBase64: encoded,
    async fetcher(url, init) {
      calls.push({ init, url: String(url) });
      const request = JSON.parse(init.body);
      assert.equal(request.releaseRequestBase64, encoded);
      assert.equal(init.redirect, "error");
      assert.match(init.headers.authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
      return Response.json(
        {
          bindingVersionSha256: "b".repeat(64),
          present: true,
          requestDigest,
          requestId,
          resourceIdentitySha256: "c".repeat(64),
        },
        { status: 202 },
      );
    },
  });
  const result = await client.inspect({
    binding: "RESEND_API_KEY",
    context: {
      applicationCommitSha: "1".repeat(40),
      brokerRequestId: requestId,
      capsuleRequestSha256: "d".repeat(64),
      resourceIdentitySha256: "c".repeat(64),
      targetSha256: "e".repeat(64),
    },
    payloadKind: "secret",
  });
  assert.equal(result.present, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://dispatcher.example/v1/custody/inspect");
});

test("broker client rejects substituted receipts and malformed OIDC before custody access", async () => {
  const encoded = await releaseRequestBase64();
  const client = createCiphertextCustodyBrokerClient({
    dispatcherOrigin: "https://dispatcher.example/",
    getOidcToken: async () => oidc(),
    releaseRequestBase64: encoded,
    async fetcher() {
      return Response.json(
        {
          bindingVersionSha256: null,
          present: false,
          requestDigest: "f".repeat(64),
          requestId,
          resourceIdentitySha256: null,
        },
        { status: 202 },
      );
    },
  });
  await assert.rejects(
    client.inspect({ binding: "RESEND_API_KEY", context: {}, payloadKind: "secret" }),
    /differs from the exact release/,
  );

  let network = false;
  const malformed = createCiphertextCustodyBrokerClient({
    dispatcherOrigin: "https://dispatcher.example/",
    getOidcToken: async () => "not-a-jwt",
    releaseRequestBase64: encoded,
    async fetcher() {
      network = true;
      return new Response();
    },
  });
  await assert.rejects(
    malformed.inspect({ binding: "RESEND_API_KEY", context: {}, payloadKind: "secret" }),
    /OIDC identity is invalid/,
  );
  assert.equal(network, false);
});

test("broker client rejects an oversized response before buffering protected ciphertext", async () => {
  const encoded = await releaseRequestBase64();
  const client = createCiphertextCustodyBrokerClient({
    dispatcherOrigin: "https://dispatcher.example/",
    getOidcToken: async () => oidc(),
    releaseRequestBase64: encoded,
    async fetcher() {
      return new Response("{}", {
        headers: { "content-length": "999999" },
        status: 202,
      });
    },
  });
  await assert.rejects(
    client.inspect({ binding: "RESEND_API_KEY", context: {}, payloadKind: "secret" }),
    /exceeds the byte boundary/,
  );
});

test("GPG sink pins the release public key and rejects plaintext digest drift before encryption", async () => {
  const encoded = await releaseRequestBase64();
  const request = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const brokerClient = {
    identity: { request },
    async store() {
      throw new Error("network must not be reached");
    },
  };
  const { materializeBinding, secretSink } = await createGpgCiphertextCustodySinks({
    brokerClient,
    decryptionEnvironment: {},
  });
  const bytes = Buffer.from("synthetic-provider-secret");
  await assert.rejects(
    secretSink.store({
      binding: "RESEND_API_KEY",
      context: {},
      secretBytes: bytes,
      secretSha256: "0".repeat(64),
    }),
    /plaintext differs from its exact digest/,
  );
  await assert.rejects(
    materializeBinding({ binding: "RESEND_API_KEY" }),
    /restricted to production release/,
  );
});

test("client exposes an exact production-release receipt sink and cutover-only materializer", async () => {
  const releaseEncoded = await releaseRequestBase64({
    operation: "production-release",
    exactRequestId: "22222222-2222-4222-8222-222222222222",
  });
  const releaseRequest = JSON.parse(Buffer.from(releaseEncoded, "base64url").toString("utf8"));
  const releaseBroker = {
    identity: { request: releaseRequest },
    async store() {
      throw new Error("network must not be reached in API-contract inspection");
    },
  };
  const releaseCustody = await createGpgCiphertextCustodySinks({
    brokerClient: releaseBroker,
    decryptionEnvironment: {},
  });
  assert.equal(typeof releaseCustody.productionReleaseReceiptSink.store, "function");
  assert.equal(
    ciphertextCustodyClientBindings.productionReleaseReceiptBinding,
    "PRODUCTION_RELEASE_CANDIDATE_RECEIPT",
  );

  const cutoverEncoded = await releaseRequestBase64({
    operation: "production-cutover",
    exactRequestId: "33333333-3333-4333-8333-333333333333",
  });
  const cutoverRequest = JSON.parse(Buffer.from(cutoverEncoded, "base64url").toString("utf8"));
  let resolvedBinding = null;
  const cutoverBroker = {
    identity: { request: cutoverRequest },
    async resolve({ binding }) {
      resolvedBinding = binding;
      return { encryptionKeySha256: "0".repeat(64) };
    },
    async store() {
      throw new Error("cutover must not store custody material");
    },
  };
  const cutoverCustody = await createGpgCiphertextCustodySinks({
    brokerClient: cutoverBroker,
    decryptionEnvironment: {},
  });
  await assert.rejects(
    cutoverCustody.materializeProductionReleaseReceipt(),
    /encryption key differs/,
  );
  assert.equal(resolvedBinding, "PRODUCTION_RELEASE_CANDIDATE_RECEIPT");
  await assert.rejects(
    cutoverCustody.materializeBinding({ binding: "RESEND_API_KEY" }),
    /exact bindings/,
  );
});
