const digestPattern = /^[a-f0-9]{64}$/;
const shaPattern = /^[a-f0-9]{40}$/;
const uuidV4Pattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const maximumPlaintextBytes = 65_536;
const maximumCiphertextBytes = 65_536;

const secretBindings = new Set([
  "DASHBOARD_AUTHORIZED_EMAILS",
  "LEAD_RATE_LIMIT_SECRET",
  "RESEND_API_KEY",
  "RESEND_WEBHOOK_SECRET",
]);
const privateReceiptBindings = new Set([
  "PRODUCTION_D1_INITIAL_RECOVERY",
  "PRODUCTION_DNS_STAGE_RECEIPT",
  "PRODUCTION_INFRASTRUCTURE_RECEIPT",
  "PRODUCTION_RELEASE_CANDIDATE_RECEIPT",
]);
const productionReleaseCandidateReceiptBinding = "PRODUCTION_RELEASE_CANDIDATE_RECEIPT";
const productionInfrastructureReceiptBinding = "PRODUCTION_INFRASTRUCTURE_RECEIPT";
const productionDnsStageReceiptBinding = "PRODUCTION_DNS_STAGE_RECEIPT";
const productionReleaseWritableReceiptBindings = new Set([
  "PRODUCTION_D1_INITIAL_RECOVERY",
  productionReleaseCandidateReceiptBinding,
]);

export const ciphertextCustodyPaths = Object.freeze({
  confirm: "/v1/custody/confirm",
  inspect: "/v1/custody/inspect",
  read: "/v1/custody/read",
  resolve: "/v1/custody/resolve",
  revoke: "/v1/custody/revoke",
  store: "/v1/custody/store",
});

const pathActions = new Map(Object.entries(ciphertextCustodyPaths).map(([key, value]) => [value, key]));

function exactObject(value, keys, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(label + " is not an object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(label + " fields differ");
  }
}

function exactString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(label + " is invalid");
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function decodeBase64Url(value) {
  if (typeof value !== "string" || value.length < 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("custody ciphertext encoding is invalid");
  }
  const padded = `${value.replaceAll("-", "+").replaceAll("_", "/")}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new Error("custody ciphertext is not canonical");
  return bytes;
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function database(environment) {
  if (!environment.DISPATCH_STATE || typeof environment.DISPATCH_STATE.prepare !== "function") {
    throw new Error("dispatch state binding is unavailable");
  }
  return environment.DISPATCH_STATE;
}

async function first(environment, sql, values) {
  const statement = database(environment).prepare(sql).bind(...values);
  if (typeof statement.first !== "function") throw new Error("dispatch state query is unavailable");
  return statement.first();
}

async function run(environment, sql, values) {
  const statement = database(environment).prepare(sql).bind(...values);
  const result = await statement.run();
  if (result?.success !== true) throw new Error("dispatch state mutation failed");
  return result;
}

function changed(result) {
  return Number(result?.meta?.changes ?? 0);
}

function validateBinding(payloadKind, binding) {
  exactString(binding, /^[A-Z][A-Z0-9_]{2,63}$/, "custody binding");
  if (
    (payloadKind === "secret" && !secretBindings.has(binding)) ||
    (payloadKind === "private_receipt" && !privateReceiptBindings.has(binding))
  ) {
    throw new Error("custody binding is outside the exact allowlist");
  }
}

function isProductionReleaseWritableReceipt(request, payloadKind, binding) {
  return (
    request.operation === "production-release" &&
    payloadKind === "private_receipt" &&
    productionReleaseWritableReceiptBindings.has(binding)
  );
}

function requireCustodyWriteScope(request, payloadKind, binding, action) {
  const dnsStageWritable =
    request.operation === "production-dns-stage" &&
    payloadKind === "private_receipt" &&
    binding === productionDnsStageReceiptBinding;
  const bootstrapWritable =
    request.operation === "production-bootstrap" &&
    (payloadKind === "secret" || binding === productionInfrastructureReceiptBinding);
  if (
    !dnsStageWritable &&
    !bootstrapWritable &&
    !isProductionReleaseWritableReceipt(request, payloadKind, binding)
  ) {
    throw new Error(
      `custody ${action} is restricted to production bootstrap or the exact production recovery receipt or candidate receipt`,
    );
  }
}

function validateContext(payloadKind, context, request) {
  const keys =
    payloadKind === "secret"
      ? [
          "applicationCommitSha",
          "brokerRequestId",
          "capsuleRequestSha256",
          "resourceIdentitySha256",
          "targetSha256",
        ]
      : [
          "applicationCommitSha",
          "brokerRequestId",
          "capsuleRequestSha256",
          "controllerCommitSha",
        ];
  exactObject(context, keys, "custody context");
  exactString(context.brokerRequestId, uuidV4Pattern, "custody broker request ID");
  exactString(context.capsuleRequestSha256, digestPattern, "custody capsule request digest");
  exactString(context.applicationCommitSha, shaPattern, "custody application SHA");
  if (
    context.brokerRequestId !== request.requestId ||
    context.applicationCommitSha !== request.source.commitSha
  ) {
    throw new Error("custody context differs from the exact execution");
  }
  if (payloadKind === "secret") {
    exactString(context.targetSha256, digestPattern, "custody target digest");
    exactString(context.resourceIdentitySha256, digestPattern, "custody resource identity");
    return Object.freeze({
      capsuleRequestSha256: context.capsuleRequestSha256,
      resourceIdentitySha256: context.resourceIdentitySha256,
      targetSha256: context.targetSha256,
    });
  }
  exactString(context.controllerCommitSha, shaPattern, "custody controller SHA");
  if (context.controllerCommitSha !== request.controller.commitSha) {
    throw new Error("custody controller SHA differs from the exact execution");
  }
  return Object.freeze({
    capsuleRequestSha256: context.capsuleRequestSha256,
    resourceIdentitySha256: null,
    targetSha256: null,
  });
}

async function exactExecution(request, claims, requestDigest, environment) {
  const row = await first(
    environment,
    `SELECT operation, state, source_commit_sha, controller_commit_sha,
            controller_workflow_run_id, controller_workflow_run_attempt,
            prerequisite_request_id, prerequisite_receipt_sha256
       FROM dispatch_consumptions
      WHERE request_id = ? AND request_sha256 = ?`,
    [request.requestId, requestDigest],
  );
  if (
    !row ||
    row.state !== "executing" ||
    row.operation !== request.operation ||
    row.source_commit_sha !== request.source.commitSha ||
    row.controller_commit_sha !== request.controller.commitSha ||
    String(row.controller_workflow_run_id) !== String(claims.run_id) ||
    Number(row.controller_workflow_run_attempt) !== Number(claims.run_attempt) ||
    !uuidV4Pattern.test(row.prerequisite_request_id ?? "") ||
    !digestPattern.test(row.prerequisite_receipt_sha256 ?? "")
  ) {
    throw new Error("custody execution is not exact or its prerequisite is absent");
  }
  return row;
}

function bindingVersion(row) {
  return sha256Hex(
    new TextEncoder().encode(
      canonicalJson({
        binding: row.binding,
        ciphertextSha256: row.ciphertext_sha256,
        custodyId: row.custody_id,
        decryptionProofSha256: row.decryption_proof_sha256,
        encryptionKeySha256: row.encryption_key_sha256,
        plaintextSha256: row.plaintext_sha256,
        resourceIdentitySha256: row.resource_identity_sha256,
      }),
    ),
  );
}

async function grant(environment, request, binding, custodyId, context, now) {
  await run(
    environment,
    `INSERT OR IGNORE INTO ciphertext_custody_grants (
       request_id, binding, custody_id, capsule_request_sha256,
       target_sha256, application_commit_sha, controller_commit_sha, granted_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      request.requestId,
      binding,
      custodyId,
      context.capsuleRequestSha256,
      context.targetSha256,
      request.source.commitSha,
      request.controller.commitSha,
      now,
    ],
  );
  const row = await first(
    environment,
    `SELECT custody_id, capsule_request_sha256, target_sha256,
            application_commit_sha, controller_commit_sha
       FROM ciphertext_custody_grants
      WHERE request_id = ? AND binding = ?`,
    [request.requestId, binding],
  );
  if (
    !row ||
    row.custody_id !== custodyId ||
    row.capsule_request_sha256 !== context.capsuleRequestSha256 ||
    (row.target_sha256 ?? null) !== context.targetSha256 ||
    row.application_commit_sha !== request.source.commitSha ||
    row.controller_commit_sha !== request.controller.commitSha
  ) {
    throw new Error("custody grant conflicts with an existing exact-release binding");
  }
}

async function activeObject(environment, payloadKind, binding, resourceIdentitySha256) {
  return first(
    environment,
    `SELECT custody_id, payload_kind, binding, resource_identity_sha256,
            plaintext_sha256, plaintext_bytes, encryption_key_sha256,
            ciphertext_sha256, ciphertext_bytes, ciphertext_base64url,
            state, decryption_proof_sha256, created_by_request_id
       FROM ciphertext_custody_objects
      WHERE payload_kind = ? AND binding = ? AND resource_identity_sha256 = ?
        AND state = 'active'`,
    [payloadKind, binding, resourceIdentitySha256],
  );
}

async function inspectCustody(body, request, claims, requestDigest, environment, now) {
  exactObject(body, ["binding", "context", "payloadKind", "releaseRequestBase64"], "custody inspection");
  if (request.operation !== "production-bootstrap") {
    throw new Error("custody inspection is restricted to production bootstrap");
  }
  await exactExecution(request, claims, requestDigest, environment);
  if (body.payloadKind !== "secret") throw new Error("custody inspection kind is unsupported");
  validateBinding(body.payloadKind, body.binding);
  const context = validateContext(body.payloadKind, body.context, request);
  const row = await activeObject(
    environment,
    body.payloadKind,
    body.binding,
    context.resourceIdentitySha256,
  );
  if (!row || row.encryption_key_sha256 !== request.artifact.encryptionKeySha256) {
    return Object.freeze({
      bindingVersionSha256: null,
      present: false,
      resourceIdentitySha256: null,
    });
  }
  await grant(environment, request, body.binding, row.custody_id, context, now);
  return Object.freeze({
    bindingVersionSha256: await bindingVersion(row),
    present: true,
    resourceIdentitySha256: row.resource_identity_sha256,
  });
}

async function storeCustody(body, request, claims, requestDigest, environment, now) {
  exactObject(
    body,
    [
      "binding",
      "ciphertextBase64Url",
      "ciphertextSha256",
      "context",
      "encryptionKeySha256",
      "payloadKind",
      "plaintextBytes",
      "plaintextSha256",
      "releaseRequestBase64",
    ],
    "custody store",
  );
  if (!['secret', 'private_receipt'].includes(body.payloadKind)) {
    throw new Error("custody payload kind is unsupported");
  }
  validateBinding(body.payloadKind, body.binding);
  requireCustodyWriteScope(request, body.payloadKind, body.binding, "store");
  await exactExecution(request, claims, requestDigest, environment);
  const context = validateContext(body.payloadKind, body.context, request);
  exactString(body.plaintextSha256, digestPattern, "custody plaintext digest");
  exactString(body.ciphertextSha256, digestPattern, "custody ciphertext digest");
  exactString(body.encryptionKeySha256, digestPattern, "custody encryption-key digest");
  if (body.encryptionKeySha256 !== request.artifact.encryptionKeySha256) {
    throw new Error("custody encryption key differs from the approved release");
  }
  if (
    !Number.isSafeInteger(body.plaintextBytes) ||
    body.plaintextBytes < 1 ||
    body.plaintextBytes > maximumPlaintextBytes
  ) {
    throw new Error("custody plaintext size is invalid");
  }
  const ciphertext = decodeBase64Url(body.ciphertextBase64Url);
  if (ciphertext.byteLength < 1 || ciphertext.byteLength > maximumCiphertextBytes) {
    throw new Error("custody ciphertext size is invalid");
  }
  if ((await sha256Hex(ciphertext)) !== body.ciphertextSha256) {
    throw new Error("custody ciphertext digest differs");
  }
  const resourceIdentitySha256 =
    body.payloadKind === "private_receipt"
      ? body.plaintextSha256
      : context.resourceIdentitySha256;
  const objectIdentity = {
    binding: body.binding,
    ciphertextSha256: body.ciphertextSha256,
    encryptionKeySha256: body.encryptionKeySha256,
    payloadKind: body.payloadKind,
    plaintextBytes: body.plaintextBytes,
    plaintextSha256: body.plaintextSha256,
    resourceIdentitySha256,
    schema: "deployment-control/ciphertext-custody-object/v1",
  };
  const custodyId = await sha256Hex(new TextEncoder().encode(canonicalJson(objectIdentity)));
  await run(
    environment,
    `INSERT OR IGNORE INTO ciphertext_custody_objects (
       custody_id, payload_kind, binding, resource_identity_sha256,
       plaintext_sha256, plaintext_bytes, encryption_key_sha256,
       ciphertext_sha256, ciphertext_bytes, ciphertext_base64url,
       state, decryption_proof_sha256, created_by_request_id,
       created_at, confirmed_at, revoked_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, ?, NULL, NULL)`,
    [
      custodyId,
      body.payloadKind,
      body.binding,
      resourceIdentitySha256,
      body.plaintextSha256,
      body.plaintextBytes,
      body.encryptionKeySha256,
      body.ciphertextSha256,
      ciphertext.byteLength,
      body.ciphertextBase64Url,
      request.requestId,
      now,
    ],
  );
  const row = await first(
    environment,
    `SELECT custody_id, payload_kind, binding, resource_identity_sha256,
            plaintext_sha256, plaintext_bytes, encryption_key_sha256,
            ciphertext_sha256, ciphertext_bytes, ciphertext_base64url,
            state, decryption_proof_sha256, created_by_request_id
       FROM ciphertext_custody_objects
      WHERE payload_kind = ? AND binding = ? AND resource_identity_sha256 = ?`,
    [body.payloadKind, body.binding, resourceIdentitySha256],
  );
  if (
    !row ||
    row.custody_id !== custodyId ||
    row.plaintext_sha256 !== body.plaintextSha256 ||
    Number(row.plaintext_bytes) !== body.plaintextBytes ||
    row.encryption_key_sha256 !== body.encryptionKeySha256 ||
    row.ciphertext_sha256 !== body.ciphertextSha256 ||
    Number(row.ciphertext_bytes) !== ciphertext.byteLength ||
    row.ciphertext_base64url !== body.ciphertextBase64Url ||
    !["pending", "active"].includes(row.state)
  ) {
    throw new Error("custody object conflicts with existing protected state");
  }
  if (row.state === "pending" && row.created_by_request_id !== request.requestId) {
    throw new Error("custody object is pending in another protected execution");
  }
  await grant(environment, request, body.binding, row.custody_id, context, now);
  return Object.freeze({
    binding: body.binding,
    ciphertextSha256: row.ciphertext_sha256,
    custodySha256: row.custody_id,
    plaintextSha256: row.plaintext_sha256,
    resourceIdentitySha256: row.resource_identity_sha256,
    state: row.state,
  });
}

async function grantedObject(environment, request, execution, binding) {
  const grantRequestId =
    request.operation === "production-bootstrap" && binding === productionDnsStageReceiptBinding
      ? execution.prerequisite_request_id
      :
    request.operation === "production-release" &&
    !productionReleaseWritableReceiptBindings.has(binding)
      ? execution.prerequisite_request_id
      : request.operation === "production-cutover"
        ? execution.prerequisite_request_id
      : request.requestId;
  return first(
    environment,
    `SELECT object.custody_id, object.payload_kind, object.binding,
            object.resource_identity_sha256, object.plaintext_sha256,
            object.plaintext_bytes, object.encryption_key_sha256,
            object.ciphertext_sha256, object.ciphertext_bytes,
            object.ciphertext_base64url, object.state,
            object.decryption_proof_sha256, object.created_by_request_id
       FROM ciphertext_custody_grants AS grant_record
       JOIN ciphertext_custody_objects AS object
         ON object.custody_id = grant_record.custody_id
      WHERE grant_record.request_id = ? AND grant_record.binding = ?`,
    [grantRequestId, binding],
  );
}

async function exactProductionReleaseCandidate(
  environment,
  request,
  execution,
  binding,
  now,
) {
  if (
    request.operation !== "production-cutover" ||
    binding !== productionReleaseCandidateReceiptBinding
  ) {
    throw new Error("custody cutover access is restricted to the exact production-release candidate receipt");
  }
  const earliestAccepted = now - 24 * 60 * 60 * 1000;
  return first(
    environment,
    `SELECT object.custody_id, object.payload_kind, object.binding,
            object.resource_identity_sha256, object.plaintext_sha256,
            object.plaintext_bytes, object.encryption_key_sha256,
            object.ciphertext_sha256, object.ciphertext_bytes,
            object.ciphertext_base64url, object.state,
            object.decryption_proof_sha256, object.created_by_request_id
       FROM dispatch_consumptions AS prerequisite
       JOIN ciphertext_custody_grants AS grant_record
         ON grant_record.request_id = prerequisite.request_id
       JOIN ciphertext_custody_objects AS object
         ON object.custody_id = grant_record.custody_id
      WHERE prerequisite.request_id = ?
        AND prerequisite.operation = 'production-release'
        AND prerequisite.state = 'executed'
        AND prerequisite.source_repository_id = ?
        AND prerequisite.source_commit_sha = ?
        AND prerequisite.controller_commit_sha = ?
        AND prerequisite.execution_receipt_sha256 = ?
        AND prerequisite.updated_at >= ?
        AND grant_record.binding = ?
        AND grant_record.application_commit_sha = ?
        AND grant_record.controller_commit_sha = ?
        AND object.payload_kind = 'private_receipt'
        AND object.binding = ?
        AND object.state = 'active'`,
    [
      execution.prerequisite_request_id,
      request.source.repositoryId,
      request.source.commitSha,
      request.controller.commitSha,
      execution.prerequisite_receipt_sha256,
      earliestAccepted,
      productionReleaseCandidateReceiptBinding,
      request.source.commitSha,
      request.controller.commitSha,
      productionReleaseCandidateReceiptBinding,
    ],
  );
}

async function readableObject(environment, request, execution, binding, now) {
  if (request.operation === "production-cutover") {
    return exactProductionReleaseCandidate(environment, request, execution, binding, now);
  }
  return grantedObject(environment, request, execution, binding);
}

async function readCustody(body, request, claims, requestDigest, environment, now) {
  exactObject(
    body,
    [
      "binding",
      "expectedCiphertextSha256",
      "expectedPlaintextSha256",
      "releaseRequestBase64",
    ],
    "custody read",
  );
  if (!["production-dns-stage", "production-bootstrap", "production-release", "production-cutover"].includes(request.operation)) {
    throw new Error("custody read is outside the protected operation allowlist");
  }
  const execution = await exactExecution(request, claims, requestDigest, environment);
  exactString(body.expectedCiphertextSha256, digestPattern, "expected custody ciphertext digest");
  exactString(body.expectedPlaintextSha256, digestPattern, "expected custody plaintext digest");
  exactString(body.binding, /^[A-Z][A-Z0-9_]{2,63}$/, "custody binding");
  const row = await readableObject(environment, request, execution, body.binding, now);
  const readable =
    row &&
    row.encryption_key_sha256 === request.artifact.encryptionKeySha256 &&
    (row.state === "active" ||
      ((request.operation === "production-dns-stage" ||
        request.operation === "production-bootstrap" ||
        isProductionReleaseWritableReceipt(request, row.payload_kind, row.binding)) &&
        row.state === "pending" &&
        row.created_by_request_id === request.requestId));
  if (
    !readable ||
    row.ciphertext_sha256 !== body.expectedCiphertextSha256 ||
    row.plaintext_sha256 !== body.expectedPlaintextSha256 ||
    typeof row.ciphertext_base64url !== "string"
  ) {
    throw new Error("custody read is not bound to the exact approved object");
  }
  const ciphertext = decodeBase64Url(row.ciphertext_base64url);
  if (
    ciphertext.byteLength !== Number(row.ciphertext_bytes) ||
    (await sha256Hex(ciphertext)) !== row.ciphertext_sha256
  ) {
    throw new Error("stored custody ciphertext integrity differs");
  }
  return Object.freeze({
    binding: row.binding,
    ciphertextBase64Url: row.ciphertext_base64url,
    ciphertextSha256: row.ciphertext_sha256,
    custodySha256: row.custody_id,
    encryptionKeySha256: row.encryption_key_sha256,
    payloadKind: row.payload_kind,
    plaintextBytes: Number(row.plaintext_bytes),
    plaintextSha256: row.plaintext_sha256,
    resourceIdentitySha256: row.resource_identity_sha256,
    state: row.state,
  });
}

async function resolveCustody(body, request, claims, requestDigest, environment, now) {
  exactObject(body, ["binding", "releaseRequestBase64"], "custody resolution");
  if (!["production-bootstrap", "production-release", "production-cutover"].includes(request.operation)) {
    throw new Error("custody resolution is restricted to production bootstrap, release or cutover");
  }
  const execution = await exactExecution(request, claims, requestDigest, environment);
  exactString(body.binding, /^[A-Z][A-Z0-9_]{2,63}$/, "custody binding");
  if (request.operation === "production-bootstrap" && body.binding !== productionDnsStageReceiptBinding) {
    throw new Error("bootstrap custody resolution is restricted to the exact DNS-stage receipt");
  }
  if (
    request.operation === "production-release" &&
    productionReleaseWritableReceiptBindings.has(body.binding)
  ) {
    throw new Error("custody resolution is restricted to bootstrap-issued bindings");
  }
  const row = await readableObject(environment, request, execution, body.binding, now);
  if (
    !row ||
    row.state !== "active" ||
    row.encryption_key_sha256 !== request.artifact.encryptionKeySha256 ||
    typeof row.ciphertext_base64url !== "string"
  ) {
    throw new Error("custody resolution is not bound to the exact prerequisite");
  }
  return Object.freeze({
    binding: row.binding,
    bindingVersionSha256: await bindingVersion(row),
    ciphertextSha256: row.ciphertext_sha256,
    custodySha256: row.custody_id,
    encryptionKeySha256: row.encryption_key_sha256,
    payloadKind: row.payload_kind,
    plaintextBytes: Number(row.plaintext_bytes),
    plaintextSha256: row.plaintext_sha256,
    resourceIdentitySha256: row.resource_identity_sha256,
  });
}

async function confirmCustody(body, request, claims, requestDigest, environment, now) {
  exactObject(
    body,
    [
      "binding",
      "custodySha256",
      "decryptionProofSha256",
      "expectedCiphertextSha256",
      "expectedPlaintextSha256",
      "releaseRequestBase64",
    ],
    "custody confirmation",
  );
  const execution = await exactExecution(request, claims, requestDigest, environment);
  for (const [value, label] of [
    [body.custodySha256, "custody object digest"],
    [body.decryptionProofSha256, "custody decryption proof digest"],
    [body.expectedCiphertextSha256, "expected custody ciphertext digest"],
    [body.expectedPlaintextSha256, "expected custody plaintext digest"],
  ]) {
    exactString(value, digestPattern, label);
  }
  exactString(body.binding, /^[A-Z][A-Z0-9_]{2,63}$/, "custody binding");
  const row = await grantedObject(environment, request, execution, body.binding);
  if (row) requireCustodyWriteScope(request, row.payload_kind, row.binding, "confirmation");
  if (
    !row ||
    row.custody_id !== body.custodySha256 ||
    row.ciphertext_sha256 !== body.expectedCiphertextSha256 ||
    row.plaintext_sha256 !== body.expectedPlaintextSha256
  ) {
    throw new Error("custody confirmation differs from the stored object");
  }
  if (row.state === "pending" && row.created_by_request_id === request.requestId) {
    const result = await run(
      environment,
      `UPDATE ciphertext_custody_objects
          SET state = 'active', decryption_proof_sha256 = ?, confirmed_at = ?
        WHERE custody_id = ? AND state = 'pending'
          AND created_by_request_id = ? AND ciphertext_sha256 = ?
          AND plaintext_sha256 = ?`,
      [
        body.decryptionProofSha256,
        now,
        body.custodySha256,
        request.requestId,
        body.expectedCiphertextSha256,
        body.expectedPlaintextSha256,
      ],
    );
    if (changed(result) !== 1) throw new Error("custody confirmation was not recorded");
  } else if (
    row.state !== "active" ||
    row.decryption_proof_sha256 !== body.decryptionProofSha256
  ) {
    throw new Error("custody confirmation conflicts with protected state");
  }
  const confirmed = await activeObject(
    environment,
    row.payload_kind,
    row.binding,
    row.resource_identity_sha256,
  );
  if (!confirmed || confirmed.decryption_proof_sha256 !== body.decryptionProofSha256) {
    throw new Error("custody confirmation readback failed");
  }
  return Object.freeze({
    bindingVersionSha256: await bindingVersion(confirmed),
    custodySha256: confirmed.custody_id,
    decryptionProofSha256: confirmed.decryption_proof_sha256,
    resourceIdentitySha256: confirmed.resource_identity_sha256,
    stored: true,
  });
}

async function revokeCustody(body, request, claims, requestDigest, environment, now) {
  exactObject(
    body,
    [
      "binding",
      "custodySha256",
      "expectedCiphertextSha256",
      "expectedPlaintextSha256",
      "releaseRequestBase64",
    ],
    "custody revocation",
  );
  const execution = await exactExecution(request, claims, requestDigest, environment);
  for (const [value, label] of [
    [body.custodySha256, "custody object digest"],
    [body.expectedCiphertextSha256, "expected custody ciphertext digest"],
    [body.expectedPlaintextSha256, "expected custody plaintext digest"],
  ]) {
    exactString(value, digestPattern, label);
  }
  exactString(body.binding, /^[A-Z][A-Z0-9_]{2,63}$/, "custody binding");
  const row = await grantedObject(environment, request, execution, body.binding);
  if (row) requireCustodyWriteScope(request, row.payload_kind, row.binding, "revocation");
  if (
    !row ||
    row.custody_id !== body.custodySha256 ||
    row.ciphertext_sha256 !== body.expectedCiphertextSha256 ||
    row.plaintext_sha256 !== body.expectedPlaintextSha256 ||
    !["pending", "active"].includes(row.state)
  ) {
    throw new Error("custody revocation differs from the exact granted object");
  }
  const result = await run(
    environment,
    `UPDATE ciphertext_custody_objects
        SET state = 'revoked', ciphertext_base64url = NULL, revoked_at = ?
      WHERE custody_id = ? AND state IN ('pending', 'active')
        AND ciphertext_sha256 = ? AND plaintext_sha256 = ?`,
    [now, body.custodySha256, body.expectedCiphertextSha256, body.expectedPlaintextSha256],
  );
  if (changed(result) !== 1) throw new Error("custody revocation was not recorded");
  return Object.freeze({ custodySha256: body.custodySha256, revoked: true });
}

export function ciphertextCustodyBodyKeys(path) {
  const action = pathActions.get(path);
  if (!action) return null;
  return {
    confirm: [
      "binding",
      "custodySha256",
      "decryptionProofSha256",
      "expectedCiphertextSha256",
      "expectedPlaintextSha256",
      "releaseRequestBase64",
    ],
    inspect: ["binding", "context", "payloadKind", "releaseRequestBase64"],
    read: [
      "binding",
      "expectedCiphertextSha256",
      "expectedPlaintextSha256",
      "releaseRequestBase64",
    ],
    resolve: ["binding", "releaseRequestBase64"],
    revoke: [
      "binding",
      "custodySha256",
      "expectedCiphertextSha256",
      "expectedPlaintextSha256",
      "releaseRequestBase64",
    ],
    store: [
      "binding",
      "ciphertextBase64Url",
      "ciphertextSha256",
      "context",
      "encryptionKeySha256",
      "payloadKind",
      "plaintextBytes",
      "plaintextSha256",
      "releaseRequestBase64",
    ],
  }[action];
}

export async function handleCiphertextCustody({
  body,
  claims,
  environment,
  now,
  path,
  request,
  requestDigest,
}) {
  const action = pathActions.get(path);
  if (!action) throw new Error("custody action is not allowlisted");
  return {
    confirm: confirmCustody,
    inspect: inspectCustody,
    read: readCustody,
    resolve: resolveCustody,
    revoke: revokeCustody,
    store: storeCustody,
  }[action](body, request, claims, requestDigest, environment, now);
}

export const ciphertextCustodyConstants = Object.freeze({
  maximumCiphertextBytes,
  maximumPlaintextBytes,
  privateReceiptBindings: Object.freeze([...privateReceiptBindings].sort()),
  productionReleaseCandidateReceiptBinding,
  secretBindings: Object.freeze([...secretBindings].sort()),
});
