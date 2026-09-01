import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJson, sha256 } from "../scripts/control-contract.mjs";
import {
  parseFixedEnvelope,
  validateDecryptionBindings,
  validateImportedSecretKey,
  validateTransportBindings,
  validateManifest,
  validateOperationPayload,
  protectedOperationOutputs,
  validateTransportTree,
} from "../scripts/protected-transport.mjs";

const privateKeyHeader = ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join("");
const privateKeyFooter = ["-----END OPENSSH ", "PRIVATE KEY-----"].join("");
const pgpPrivateKeyHeader = ["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"].join("");
const pgpPrivateKeyFooter = ["-----END PGP ", "PRIVATE KEY BLOCK-----"].join("");

function transportEnvironment(overrides = {}) {
  const key = `${privateKeyHeader}\nQUJDRA==\nRUZHSA==\n${privateKeyFooter}\n`;
  const gitUrl = "git@github.com:owner/private-app.git";
  return {
    PRIVATE_TRANSPORT_DEPLOY_KEY: key,
    PRIVATE_TRANSPORT_DEPLOY_KEY_SHA256: sha256(Buffer.from(key)),
    PRIVATE_TRANSPORT_GIT_URL: gitUrl,
    PRIVATE_TRANSPORT_GIT_URL_SHA256: sha256(Buffer.from(gitUrl)),
    ...overrides,
  };
}

function decryptionEnvironment(overrides = {}) {
  const privateKey = `${pgpPrivateKeyHeader}\nsynthetic-armored-material\n${pgpPrivateKeyFooter}\n`;
  const passphrase = "synthetic-passphrase-without-production-value";
  return {
    RELEASE_DECRYPTION_PASSPHRASE: passphrase,
    RELEASE_DECRYPTION_PASSPHRASE_SHA256: sha256(Buffer.from(passphrase)),
    RELEASE_DECRYPTION_PRIVATE_KEY: privateKey,
    RELEASE_DECRYPTION_PRIVATE_KEY_SHA256: sha256(Buffer.from(privateKey)),
    ...overrides,
  };
}

function secretListing(primaryFingerprint, encryptionSubkeyFingerprint) {
  const record = (type, capabilities) => {
    const fields = Array(13).fill("");
    fields[0] = type;
    fields[11] = capabilities;
    return fields.join(":");
  };
  return [
    record("sec", "c"),
    `fpr:::::::::${primaryFingerprint}:`,
    record("ssb", "e"),
    `fpr:::::::::${encryptionSubkeyFingerprint}:`,
    "",
  ].join("\n");
}

function tarOctal(value, width) {
  return `${value.toString(8).padStart(width - 1, "0")}\0`;
}

test("transport credentials are bound to exact canonical key bytes and repository URL", () => {
  const environment = transportEnvironment();
  assert.deepEqual(validateTransportBindings(environment), {
    deployKey: environment.PRIVATE_TRANSPORT_DEPLOY_KEY,
    gitUrl: environment.PRIVATE_TRANSPORT_GIT_URL,
  });
  const crlf = environment.PRIVATE_TRANSPORT_DEPLOY_KEY.replaceAll("\n", "\r\n");
  assert.equal(
    validateTransportBindings({ ...environment, PRIVATE_TRANSPORT_DEPLOY_KEY: crlf }).deployKey,
    environment.PRIVATE_TRANSPORT_DEPLOY_KEY,
  );
});

test("malformed, substituted, or repository-mismatched transport credentials fail pre-network", () => {
  const environment = transportEnvironment();
  assert.throws(
    () =>
      validateTransportBindings({
        ...environment,
        PRIVATE_TRANSPORT_DEPLOY_KEY: environment.PRIVATE_TRANSPORT_DEPLOY_KEY.replaceAll(
          "\n",
          " ",
        ),
      }),
    /material is invalid/,
  );
  assert.throws(
    () =>
      validateTransportBindings({
        ...environment,
        PRIVATE_TRANSPORT_DEPLOY_KEY_SHA256: "0".repeat(64),
      }),
    /secret binding differs/,
  );
  assert.throws(
    () =>
      validateTransportBindings({
        ...environment,
        PRIVATE_TRANSPORT_GIT_URL: "git@github.com:owner/other-private-app.git",
      }),
    /repository binding differs/,
  );
});

test("decryption secrets are canonical and bound before GPG import or passphrase use", () => {
  const environment = decryptionEnvironment();
  assert.deepEqual(validateDecryptionBindings(environment), {
    passphrase: environment.RELEASE_DECRYPTION_PASSPHRASE,
    privateKey: environment.RELEASE_DECRYPTION_PRIVATE_KEY,
  });
  const crlf = environment.RELEASE_DECRYPTION_PRIVATE_KEY.replaceAll("\n", "\r\n");
  assert.equal(
    validateDecryptionBindings({ ...environment, RELEASE_DECRYPTION_PRIVATE_KEY: crlf })
      .privateKey,
    environment.RELEASE_DECRYPTION_PRIVATE_KEY,
  );
});

test("stale private-key or passphrase material and wrong imported fingerprints fail closed", () => {
  const environment = decryptionEnvironment();
  assert.throws(
    () =>
      validateDecryptionBindings({
        ...environment,
        RELEASE_DECRYPTION_PRIVATE_KEY_SHA256: "0".repeat(64),
      }),
    /key binding differs/,
  );
  assert.throws(
    () =>
      validateDecryptionBindings({
        ...environment,
        RELEASE_DECRYPTION_PASSPHRASE: `${environment.RELEASE_DECRYPTION_PASSPHRASE}-stale`,
      }),
    /passphrase binding differs/,
  );
  const primaryFingerprint = "A".repeat(40);
  const encryptionSubkeyFingerprint = "C".repeat(40);
  const listing = secretListing(primaryFingerprint, encryptionSubkeyFingerprint);
  assert.equal(
    validateImportedSecretKey(listing, primaryFingerprint, encryptionSubkeyFingerprint),
    true,
  );
  assert.throws(
    () =>
      validateImportedSecretKey(
        listing,
        "B".repeat(40),
        encryptionSubkeyFingerprint,
      ),
    /fingerprint differs/,
  );
  assert.throws(
    () => validateImportedSecretKey(listing, primaryFingerprint, "D".repeat(40)),
    /encryption subkey differs/,
  );
  assert.throws(
    () =>
      validateImportedSecretKey(
        secretListing(primaryFingerprint, primaryFingerprint),
        primaryFingerprint,
        encryptionSubkeyFingerprint,
      ),
    /encryption subkey differs/,
  );
});

function tar(entries) {
  const chunks = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data);
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, "utf8");
    header.write(tarOctal(entry.mode ?? 0o400, 8), 100, 8, "ascii");
    header.write(tarOctal(0, 8), 108, 8, "ascii");
    header.write(tarOctal(0, 8), 116, 8, "ascii");
    header.write(tarOctal(data.length, 12), 124, 12, "ascii");
    header.write(tarOctal(0, 12), 136, 12, "ascii");
    header.fill(32, 148, 156);
    header[156] = (entry.type ?? "0").charCodeAt(0);
    header.write("ustar\0", 257, 6, "binary");
    header.write("00", 263, 2, "ascii");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    chunks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function request(manifestBytes) {
  return {
    artifact: {
      ciphertextBlobSha1: "4".repeat(40),
      ciphertextSha256: "c".repeat(64),
      encryptionKeySha256: "d".repeat(64),
      manifestBlobSha1: "5".repeat(40),
      plaintextBytes: 7,
      plaintextSha256: sha256(Buffer.from("payload")),
      releaseId: "6006",
      transportCommitSha: "3".repeat(40),
      transportTag: "deployment-control/11111111-1111-4111-8111-111111111111",
    },
    controller: { commitSha: "2".repeat(40), repositoryId: "2002" },
    evidence: {
      immutableRelease: true,
      manifestSha256: sha256(manifestBytes),
      oidcTokenSha256: "f".repeat(64),
    },
    expiresAt: "2026-09-01T10:15:00.000Z",
    issuedAt: "2026-09-01T10:00:00.000Z",
    nonce: "A".repeat(43),
    operation: "production-release",
    requestId: "11111111-1111-4111-8111-111111111111",
    schema: "deployment-control/release-request/v1",
    source: {
      commitSha: "1".repeat(40),
      repositoryId: "1001",
      workflowRunAttempt: 1,
      workflowRunId: "3003",
    },
  };
}

function manifest() {
  return {
    controller: { commitSha: "2".repeat(40), repositoryId: "2002" },
    evidence: { oidcTokenSha256: "f".repeat(64) },
    nonce: "A".repeat(43),
    payload: { bytes: 7, sha256: sha256(Buffer.from("payload")) },
    requestId: "11111111-1111-4111-8111-111111111111",
    schema: "deployment-control/private-transport-manifest/v1",
    source: {
      commitSha: "1".repeat(40),
      repositoryId: "1001",
      workflowRunAttempt: 1,
      workflowRunId: "3003",
    },
  };
}

function canaryCapsule() {
  const capsule = {
    application: {
      commitSha: "1".repeat(40),
      ref: "refs/heads/main",
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1001",
      runAttempt: 1,
      runId: "3003",
      workflowRef:
        "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
      workflowSha: "1".repeat(40),
    },
    canary: {
      canaryId: "",
      intent: "verify-protected-boundary-without-provider-mutation",
      productionCredentialsPresent: false,
      providerMutationAuthorized: false,
    },
    capsuleType: "fresh-towels-protected-executor-canary",
    controller: {
      commitSha: "2".repeat(40),
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      workflowRef: `zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@${"2".repeat(40)}`,
    },
    createdAt: "2026-09-01T09:59:00.000Z",
    operation: "canary",
    schemaVersion: 1,
    validUntil: "2026-09-01T11:59:00.000Z",
  };
  capsule.canary.canaryId = sha256(
    Buffer.from(
      [
        capsule.application.commitSha,
        capsule.controller.commitSha,
        capsule.application.runId,
        capsule.application.runAttempt,
        capsule.createdAt,
      ].join("\0"),
    ),
  );
  return capsule;
}

function productionCapsule() {
  return {
    application: {
      repository: "zikosbozonis-beep/fresh-towels-website",
      repositoryId: "1001",
      ref: "refs/heads/main",
      commitSha: "1".repeat(40),
      workflowRef:
        "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
      workflowSha: "1".repeat(40),
      runId: "3003",
      runAttempt: 1,
    },
    controller: {
      repository: "zikosbozonis-beep/fresh-towels-deployment-control",
      commitSha: "2".repeat(40),
      workflowRef: `zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@${"2".repeat(40)}`,
    },
    createdAt: "2026-09-01T09:59:00.000Z",
    operation: "production-release",
    payload: {
      encoding: "base64-per-file",
      rawBytes: 1,
      fileCount: 1,
      entries: [{ path: "synthetic", bytes: 1 }],
    },
    releaseId: "6".repeat(64),
    releaseIntegrity: {
      buildArtifactSha256: "a".repeat(64),
      databaseSchemaSha256: "b".repeat(64),
      releaseApprovalManifestSha256: "c".repeat(64),
      configurationTemplateSha256: "d".repeat(64),
      uploadArtifactSha256: "e".repeat(64),
      capsuleTreeSha256: "f".repeat(64),
      productionInfrastructureReceiptSha256: "7".repeat(64),
    },
    schemaVersion: 2,
    capsuleType: "fresh-towels-private-release-capsule",
    validUntil: "2026-09-01T11:59:00.000Z",
  };
}

function productionBootstrapCapsule(adminIdentity = "owner-admin@example.net") {
  const application = {
    repository: "zikosbozonis-beep/fresh-towels-website",
    repositoryId: "1350923567",
    ref: "refs/heads/main",
    commitSha: "1".repeat(40),
    workflowRef:
      "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
    workflowSha: "1".repeat(40),
    runId: "3003",
    runAttempt: 1,
  };
  const controller = {
    repository: "zikosbozonis-beep/fresh-towels-deployment-control",
    commitSha: "2".repeat(40),
    workflowRef: `zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@${"2".repeat(40)}`,
  };
  const providerCanary = {
    requestId: "77777777-7777-4777-8777-777777777777",
    receiptSha256: "8".repeat(64),
    runId: "33524593667",
  };
  const stableEvidence = {
    redirectCandidateEvidenceSha256: "9".repeat(64),
    privacyOperationsEvidenceSha256: "a".repeat(64),
    legacyWordPressRecoveryEvidenceSha256: "b".repeat(64),
  };
  const targets = {
    cloudflare: {
      accountId: "c".repeat(32),
      zone: { id: null, name: "freshtowels.gr", type: "full" },
      workerName: "fresh-towels-production",
      workersDevSubdomain: null,
      d1: {
        jurisdiction: "eu",
        primary: { id: null, name: "fresh-towels-leads-prod" },
        recovery: { id: null, name: "fresh-towels-leads-prod-recovery" },
      },
      access: {
        organization: { name: "Fresh Towels", teamDomain: null, sessionDuration: "8h" },
        identityProvider: {
          id: null,
          name: "Fresh Towels owner OTP",
          type: "onetimepin",
        },
        application: {
          id: null,
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
          id: null,
          name: "Fresh Towels owner access",
          decision: "allow",
          precedence: 1,
          adminIdentitySha256: sha256(Buffer.from(adminIdentity)),
        },
      },
    },
    resend: {
      domain: { id: "c63fd375-20ce-406a-a13a-85b0a85db733", name: "notify.freshtowels.gr", region: "eu-west-1" },
      senderAddress: "notifications@notify.freshtowels.gr",
      webhook: {
        id: null,
        endpoint: "https://freshtowels.gr/api/webhooks/resend",
        events: ["email.sent", "email.delivered", "email.bounced", "email.complained", "email.delivery_delayed", "email.failed", "email.suppressed"],
        secretBinding: "RESEND_WEBHOOK_SECRET",
      },
      sendingKey: {
        id: null,
        name: "Fresh Towels Production Worker",
        permission: "sending_access",
        secretBinding: "RESEND_API_KEY",
      },
    },
  };
  const createdAt = "2026-09-01T09:59:00.000Z";
  const bootstrap = {
    requestId: "",
    intent: "provision-production-identities-and-issue-credential-free-receipt",
    dnsStage: providerCanary,
    stableEvidence,
    targets,
    safeguards: {
      credentialsPresent: false,
      applicationBuildAuthorized: false,
      applicationArtifactPresent: false,
      productionTrafficMutationAuthorized: false,
      productionDnsMutationAuthorized: false,
      providerBootstrapMutationAuthorized: true,
    },
  };
  bootstrap.requestId = sha256(
    Buffer.from(
      `${canonicalJson({ application, controller, createdAt, dnsStage: providerCanary, stableEvidence, targets })}\n`,
    ),
  );
  return {
    application,
    bootstrap,
    capsuleType: "fresh-towels-production-bootstrap-capsule",
    controller,
    createdAt,
    operation: "production-bootstrap",
    schemaVersion: 1,
    validUntil: "2026-09-01T11:59:00.000Z",
  };
}

function productionBootstrapRequest(bytes) {
  const value = request(Buffer.from("x"));
  value.operation = "production-bootstrap";
  value.source.repositoryId = "1350923567";
  value.artifact.plaintextBytes = bytes.byteLength;
  value.artifact.plaintextSha256 = sha256(bytes);
  return value;
}

function productionCutoverCapsule() {
  const application = {
    repository: "zikosbozonis-beep/fresh-towels-website",
    repositoryId: "1001",
    ref: "refs/heads/main",
    commitSha: "1".repeat(40),
    workflowRef:
      "zikosbozonis-beep/fresh-towels-website/.github/workflows/release-handoff.yml@refs/heads/main",
    workflowSha: "1".repeat(40),
    runId: "3003",
    runAttempt: 1,
  };
  const controller = {
    repository: "zikosbozonis-beep/fresh-towels-deployment-control",
    commitSha: "2".repeat(40),
    workflowRef: `zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@${"2".repeat(40)}`,
  };
  const createdAt = "2026-09-01T09:59:00.000Z";
  const prerequisite = {
    requestId: "88888888-8888-4888-8888-888888888888",
    runId: "33524599999",
    receiptSha256: "9".repeat(64),
    completedAt: "2026-09-01T09:58:00.000Z",
  };
  const safeguards = {
    exactPrerequisiteRequired: true,
    accessOwnerLoginRequired: true,
    candidateEmailDeliveryRequired: true,
    rollbackToPreCutoverRoutesRequired: true,
    legacyWordPressPreserved: true,
    productionTrafficMutationAuthorized: true,
  };
  const targets = {
    zone: "freshtowels.gr",
    worker: "fresh-towels-production",
    candidateRoutes: [
      "freshtowels.gr/api/internal/*",
      "freshtowels.gr/api/leads",
      "freshtowels.gr/api/webhooks/resend",
      "freshtowels.gr/internal/leads",
      "freshtowels.gr/internal/leads/*",
    ],
    preCutoverRoutes: [
      "freshtowels.gr/api/internal/*",
      "freshtowels.gr/internal/leads",
      "freshtowels.gr/internal/leads/*",
    ],
    liveRoutes: ["freshtowels.gr/*", "www.freshtowels.gr/*"],
  };
  const cutover = {
    cutoverId: "",
    intent: "activate-exact-qualified-release-with-automatic-route-rollback",
    prerequisite,
    safeguards,
    targets,
  };
  cutover.cutoverId = sha256(
    Buffer.from(canonicalJson({ application, controller, createdAt, prerequisite, safeguards, targets })),
  );
  return {
    application,
    capsuleType: "fresh-towels-production-cutover-capsule",
    controller,
    createdAt,
    cutover,
    operation: "production-cutover",
    schemaVersion: 1,
    validUntil: "2026-09-01T11:59:00.000Z",
  };
}

function productionCutoverRequest(bytes) {
  const value = request(Buffer.from("x"));
  value.operation = "production-cutover";
  value.artifact.plaintextBytes = bytes.byteLength;
  value.artifact.plaintextSha256 = sha256(bytes);
  return value;
}

test("transport tree permits only two exact regular non-executable blobs", () => {
  const value = request(Buffer.from("x"));
  const valid = [
    { mode: "100644", name: "manifest.json", sha: "5".repeat(40), type: "blob" },
    { mode: "100644", name: "release.gpg", sha: "4".repeat(40), type: "blob" },
  ];
  assert.equal(validateTransportTree(valid, value), true);
  for (const changed of [
    [...valid, { mode: "100644", name: "extra", sha: "6".repeat(40), type: "blob" }],
    [{ ...valid[0], mode: "120000" }, valid[1]],
    [{ ...valid[0], mode: "160000", type: "commit" }, valid[1]],
    [{ ...valid[0], sha: "9".repeat(40) }, valid[1]],
  ])
    assert.throws(() => validateTransportTree(changed, value), /tree/);
});

test("fixed envelope rejects traversal, links, executable entries, extras and trailing data", () => {
  const good = tar([
    { data: `${canonicalJson(manifest())}\n`, name: "manifest.json" },
    { data: "payload", name: "payload.bin" },
  ]);
  const files = parseFixedEnvelope(good);
  assert.equal(Buffer.from(files.get("payload.bin")).toString(), "payload");
  for (const changed of [
    tar([
      { data: "x", name: "../manifest.json" },
      { data: "payload", name: "payload.bin" },
    ]),
    tar([
      { data: "x", name: "manifest.json", type: "2" },
      { data: "payload", name: "payload.bin" },
    ]),
    tar([
      { data: "x", mode: 0o700, name: "manifest.json" },
      { data: "payload", name: "payload.bin" },
    ]),
    tar([
      { data: "x", name: "manifest.json" },
      { data: "payload", name: "payload.bin" },
      { data: "x", name: "extra" },
    ]),
    Buffer.concat([good, Buffer.from("nonzero")]),
  ])
    assert.throws(() => parseFixedEnvelope(changed), /Tar|envelope/);
});

test("canonical encrypted manifest must match every approved identity and digest", () => {
  const bytes = Buffer.from(`${canonicalJson(manifest())}\n`);
  const value = request(bytes);
  assert.equal(validateManifest(bytes, value).requestId, value.requestId);
  const changed = structuredClone(manifest());
  changed.source.commitSha = "9".repeat(40);
  assert.throws(
    () => validateManifest(Buffer.from(`${canonicalJson(changed)}\n`), value),
    /differs|digest/,
  );
});

test("decrypted operation payload is type-separated and identity-bound", () => {
  const canaryRequest = { ...request(Buffer.from("x")), operation: "canary" };
  const canary = canaryCapsule();
  const bytes = Buffer.from(`${canonicalJson(canary)}\n`);
  assert.equal(validateOperationPayload(bytes, canaryRequest).operation, "canary");

  const mutations = [
    (value) => {
      value.application.commitSha = "9".repeat(40);
    },
    (value) => {
      value.application.runAttempt = 2;
    },
    (value) => {
      value.controller.commitSha = "9".repeat(40);
    },
    (value) => {
      value.createdAt = "2026-09-01T08:00:00.000Z";
      value.validUntil = "2026-09-01T10:00:00.000Z";
    },
    (value) => {
      value.canary.canaryId = "0".repeat(64);
    },
    (value) => {
      value.unexpected = true;
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(canary);
    mutate(changed);
    assert.throws(
      () => validateOperationPayload(Buffer.from(`${canonicalJson(changed)}\n`), canaryRequest),
      /capsule|canary/,
    );
  }

  assert.throws(
    () =>
      validateOperationPayload(
        Buffer.from(`${JSON.stringify({ validUntil: canary.validUntil, ...canary })}\n`),
        canaryRequest,
      ),
    /canonical/,
  );
  assert.throws(
    () => validateOperationPayload(bytes, request(Buffer.from("x"))),
    /production capsule/,
  );
  assert.throws(
    () =>
      validateOperationPayload(
        Buffer.from(`${JSON.stringify(productionCapsule())}\n`),
        canaryRequest,
      ),
    /canary capsule/,
  );
  assert.throws(
    () =>
      validateOperationPayload(
        Buffer.from(`${JSON.stringify(productionCapsule())}\n`),
        request(Buffer.from("x")),
      ),
    /entry|payload|capsule/,
  );
});

test("production Bootstrap transport validates exact capsule, administrator hash, and prerequisite outputs", () => {
  const adminIdentity = "owner-admin@example.net";
  const capsule = productionBootstrapCapsule(adminIdentity);
  const bytes = Buffer.from(`${canonicalJson(capsule)}\n`);
  const bootstrapRequest = productionBootstrapRequest(bytes);
  const validated = validateOperationPayload(bytes, bootstrapRequest, {
    adminIdentity,
    now: new Date("2026-09-01T10:00:00.000Z"),
  });
  assert.equal(validated.operation, "production-bootstrap");
  assert.deepEqual(protectedOperationOutputs(validated, bootstrapRequest), {
    capsule_request_sha256: capsule.bootstrap.requestId,
    prerequisite_receipt_sha256: capsule.bootstrap.dnsStage.receiptSha256,
    prerequisite_request_id: capsule.bootstrap.dnsStage.requestId,
    prerequisite_run_id: capsule.bootstrap.dnsStage.runId,
  });
  assert.throws(
    () =>
      validateOperationPayload(bytes, bootstrapRequest, {
        adminIdentity: "different@example.net",
        now: new Date("2026-09-01T10:00:00.000Z"),
      }),
    /Access policy target|administrator identity|production bootstrap/,
  );
});

test("production Bootstrap prerequisite tampering and cross-operation substitution fail closed", () => {
  const adminIdentity = "owner-admin@example.net";
  const capsule = productionBootstrapCapsule(adminIdentity);
  capsule.bootstrap.dnsStage.runId = "33524593668";
  const bytes = Buffer.from(`${canonicalJson(capsule)}\n`);
  const bootstrapRequest = productionBootstrapRequest(bytes);
  assert.throws(
    () =>
      validateOperationPayload(bytes, bootstrapRequest, {
        adminIdentity,
        now: new Date("2026-09-01T10:00:00.000Z"),
      }),
    /request identity|bootstrap/,
  );
  assert.throws(
    () => validateOperationPayload(bytes, { ...bootstrapRequest, operation: "provider-canary" }),
    /provider canary capsule/,
  );
});

test("production Cutover transport is exact, canonical, and emits only prerequisite hashes", () => {
  const capsule = productionCutoverCapsule();
  const bytes = Buffer.from(`${canonicalJson(capsule)}\n`);
  const cutoverRequest = productionCutoverRequest(bytes);
  const validated = validateOperationPayload(bytes, cutoverRequest);
  assert.equal(validated.operation, "production-cutover");
  assert.deepEqual(protectedOperationOutputs(validated, cutoverRequest), {
    capsule_request_sha256: capsule.cutover.cutoverId,
    prerequisite_receipt_sha256: capsule.cutover.prerequisite.receiptSha256,
    prerequisite_request_id: capsule.cutover.prerequisite.requestId,
    prerequisite_run_id: capsule.cutover.prerequisite.runId,
  });
});

test("production Cutover prerequisite, route, identity, and operation substitution fail closed", () => {
  const original = productionCutoverCapsule();
  for (const mutate of [
    (value) => {
      value.cutover.prerequisite.receiptSha256 = "0".repeat(64);
    },
    (value) => {
      value.cutover.targets.liveRoutes.reverse();
    },
    (value) => {
      value.cutover.targets.preCutoverRoutes = [];
    },
    (value) => {
      value.application.commitSha = "3".repeat(40);
    },
    (value) => {
      value.cutover.safeguards.accessOwnerLoginRequired = false;
    },
  ]) {
    const capsule = structuredClone(original);
    mutate(capsule);
    const bytes = Buffer.from(`${canonicalJson(capsule)}\n`);
    assert.throws(
      () => validateOperationPayload(bytes, productionCutoverRequest(bytes)),
      /cutover|capsule/,
    );
  }
  const bytes = Buffer.from(`${canonicalJson(original)}\n`);
  assert.throws(
    () => validateOperationPayload(bytes, { ...productionCutoverRequest(bytes), operation: "production-release" }),
    /production capsule/,
  );
});
