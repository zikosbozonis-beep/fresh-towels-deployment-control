import {
  ciphertextCustodyBodyKeys,
  ciphertextCustodyPaths,
  handleCiphertextCustody,
} from "./ciphertext-custody.mjs";

const githubIssuer = "https://token.actions.githubusercontent.com";
const githubAudience = "deployment-control-packaging-v1";
const executorAudience = "deployment-control-executor-v1";

export function safeRejectionReason(error) {
  const message = error instanceof Error ? error.message : "";
  const claim = /^OIDC claim ([a-z_]+) differs$/.exec(message);
  if (claim) return `oidc_claim_${claim[1]}_differs`;
  if (message.startsWith("OIDC ")) return "oidc_verification_failed";
  if (message === "request repository identity differs") {
    return "request_repository_identity_differs";
  }
  if (message === "App installation token issuance failed") {
    return "app_token_issuance_failed";
  }
  if (message === "App token scope differs") return "app_token_scope_differs";
  if (message === "controller workflow dispatch failed") {
    return "controller_workflow_dispatch_failed";
  }
  return "request_validation_failed";
}
const githubApi = "https://api.github.com";
const digestPattern = /^[a-f0-9]{64}$/;
const shaPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;

function exactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields differ`);
  }
}

function exactString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function immutableRepositorySubject(repository, ownerId, repositoryId, context) {
  exactString(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "OIDC repository");
  exactString(ownerId, decimalPattern, "OIDC repository owner ID");
  exactString(repositoryId, decimalPattern, "OIDC repository ID");
  exactString(
    context,
    /^(?:ref:refs\/heads\/main|environment:(?:canary|production))$/,
    "OIDC context",
  );
  const [owner, name] = repository.split("/");
  return `repo:${owner}@${ownerId}/${name}@${repositoryId}:${context}`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("base64url input is invalid");
  }
  const padded = `${value.replaceAll("-", "+").replaceAll("_", "/")}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value) throw new Error("base64url input is not canonical");
  return bytes;
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function d1(environment) {
  if (!environment.DISPATCH_STATE || typeof environment.DISPATCH_STATE.prepare !== "function") {
    throw new Error("dispatch state binding is unavailable");
  }
  return environment.DISPATCH_STATE;
}

function changedExactlyOnce(result) {
  return result?.success === true && Number(result.meta?.changes) === 1;
}

export async function claimDispatch(request, claims, requestDigest, environment, now) {
  const result = await d1(environment)
    .prepare(`INSERT INTO dispatch_consumptions (
      request_id, oidc_jti_sha256, nonce_sha256, request_sha256,
      operation,
      source_repository_id, source_commit_sha, controller_commit_sha,
      source_workflow_run_id, source_workflow_run_attempt,
      state, dispatch_http_status, claimed_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', NULL, ?, ?)`)
    .bind(
      request.requestId,
      await sha256Hex(new TextEncoder().encode(claims.jti)),
      await sha256Hex(new TextEncoder().encode(request.nonce)),
      requestDigest,
      request.operation,
      request.source.repositoryId,
      request.source.commitSha,
      request.controller.commitSha,
      request.source.workflowRunId,
      request.source.workflowRunAttempt,
      now,
      now,
    )
    .run();
  if (!changedExactlyOnce(result)) throw new Error("dispatch claim was not created");
}

export async function verifyExecutionPrerequisite(
  request,
  claims,
  requestDigest,
  prerequisiteRequestId,
  prerequisiteReceiptSha256,
  prerequisiteRunId,
  environment,
  now,
) {
  const prerequisiteOperation = {
    "production-dns-stage": "provider-canary",
    "production-bootstrap": "production-dns-stage",
    "production-release": "production-bootstrap",
    "production-cutover": "production-release",
  }[request.operation];
  if (!prerequisiteOperation) throw new Error("operation has no execution prerequisite");
  exactString(
    prerequisiteRequestId,
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
    "prerequisite request ID",
  );
  exactString(
    prerequisiteReceiptSha256,
    digestPattern,
    "prerequisite receipt digest",
  );
  exactString(prerequisiteRunId, decimalPattern, "prerequisite workflow run ID");
  const earliestAccepted = now - 24 * 60 * 60 * 1000;
  const result = await d1(environment)
    .prepare(`UPDATE dispatch_consumptions
      SET prerequisite_request_id = ?, prerequisite_receipt_sha256 = ?, updated_at = ?
      WHERE request_id = ? AND request_sha256 = ? AND state = 'executing'
        AND operation = ? AND controller_workflow_run_id = ?
        AND controller_workflow_run_attempt = ?
        AND prerequisite_request_id IS NULL
        AND prerequisite_receipt_sha256 IS NULL
        AND EXISTS (
          SELECT 1 FROM dispatch_consumptions AS prerequisite
          WHERE prerequisite.request_id = ?
            AND prerequisite.operation = ?
            AND prerequisite.state = 'executed'
            AND prerequisite.source_repository_id = ?
            AND prerequisite.source_commit_sha = ?
            AND prerequisite.controller_commit_sha = ?
            AND prerequisite.controller_workflow_run_id = ?
            AND prerequisite.execution_receipt_sha256 = ?
            AND prerequisite.updated_at >= ?
        )`)
    .bind(
      prerequisiteRequestId,
      prerequisiteReceiptSha256,
      now,
      request.requestId,
      requestDigest,
      request.operation,
      claims.run_id,
      Number(claims.run_attempt),
      prerequisiteRequestId,
      prerequisiteOperation,
      request.source.repositoryId,
      request.source.commitSha,
      request.controller.commitSha,
      prerequisiteRunId,
      prerequisiteReceiptSha256,
      earliestAccepted,
    )
    .run();
  if (!changedExactlyOnce(result)) throw new Error("execution prerequisite is not proven");
}

export async function finishDispatch(requestId, state, status, environment, now) {
  if (!["dispatched", "ambiguous"].includes(state))
    throw new Error("dispatch terminal state is invalid");
  const result = await d1(environment)
    .prepare(`UPDATE dispatch_consumptions
      SET state = ?, dispatch_http_status = ?, updated_at = ?
      WHERE request_id = ? AND state = 'claimed'`)
    .bind(state, status, now, requestId)
    .run();
  if (!changedExactlyOnce(result)) throw new Error("dispatch terminal state was not recorded");
}

export async function claimExecution(request, claims, requestDigest, environment, now) {
  const result = await d1(environment)
    .prepare(`UPDATE dispatch_consumptions
      SET state = 'executing', executor_jti_sha256 = ?,
          controller_workflow_run_id = ?, controller_workflow_run_attempt = ?,
          updated_at = ?
      WHERE request_id = ? AND request_sha256 = ? AND state = 'dispatched'`)
    .bind(
      await sha256Hex(new TextEncoder().encode(claims.jti)),
      claims.run_id,
      Number(claims.run_attempt),
      now,
      request.requestId,
      requestDigest,
    )
    .run();
  if (!changedExactlyOnce(result)) throw new Error("execution claim was not created");
}

export async function finishExecution(
  request,
  claims,
  requestDigest,
  outcome,
  receiptDigest,
  environment,
  now,
) {
  const expectedOutcomes =
    request.operation === "canary"
      ? ["canary_verified", "execution_ambiguous"]
      : ["executed", "execution_ambiguous"];
  if (!expectedOutcomes.includes(outcome)) throw new Error("execution outcome is invalid");
  exactString(receiptDigest, digestPattern, "execution receipt digest");
  const result = await d1(environment)
    .prepare(`UPDATE dispatch_consumptions
      SET state = ?, execution_receipt_sha256 = ?, updated_at = ?
      WHERE request_id = ? AND request_sha256 = ? AND state = 'executing'
        AND controller_workflow_run_id = ? AND controller_workflow_run_attempt = ?`)
    .bind(
      outcome,
      receiptDigest,
      now,
      request.requestId,
      requestDigest,
      claims.run_id,
      Number(claims.run_attempt),
    )
    .run();
  if (!changedExactlyOnce(result)) throw new Error("execution outcome was not recorded");
}

export function parseCanonicalRequest(encoded, now, env) {
  if (typeof encoded !== "string" || encoded.length < 100 || encoded.length > 32_768) {
    throw new Error("release request size is invalid");
  }
  const bytes = decodeBase64Url(encoded);
  if (bytes.length > 24_576) throw new Error("release request decoded size is invalid");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const request = JSON.parse(text);
  exactObject(
    request,
    [
      "schema",
      "requestId",
      "nonce",
      "issuedAt",
      "expiresAt",
      "operation",
      "source",
      "controller",
      "artifact",
      "evidence",
    ],
    "request",
  );
  if (request.schema !== "deployment-control/release-request/v1")
    throw new Error("request schema is unsupported");
  exactString(
    request.requestId,
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
    "requestId",
  );
  exactString(request.nonce, /^[A-Za-z0-9_-]{43}$/, "nonce");
  if (
    ![
      "canary",
      "provider-canary",
      "production-dns-stage",
      "production-bootstrap",
      "production-release",
      "production-cutover",
    ].includes(request.operation)
  )
    throw new Error("operation is not allowlisted");
  exactObject(
    request.source,
    ["repositoryId", "commitSha", "workflowRunId", "workflowRunAttempt"],
    "source",
  );
  exactString(request.source.repositoryId, decimalPattern, "source repositoryId");
  exactString(request.source.commitSha, shaPattern, "source SHA");
  exactString(request.source.workflowRunId, decimalPattern, "source run ID");
  if (
    !Number.isSafeInteger(request.source.workflowRunAttempt) ||
    request.source.workflowRunAttempt < 1 ||
    request.source.workflowRunAttempt > 100
  )
    throw new Error("source run attempt is invalid");
  exactObject(request.controller, ["repositoryId", "commitSha"], "controller");
  exactString(request.controller.repositoryId, decimalPattern, "controller repositoryId");
  exactString(request.controller.commitSha, shaPattern, "controller SHA");
  exactObject(
    request.artifact,
    [
      "releaseId",
      "transportTag",
      "transportCommitSha",
      "ciphertextBlobSha1",
      "manifestBlobSha1",
      "ciphertextSha256",
      "plaintextSha256",
      "plaintextBytes",
      "encryptionKeySha256",
    ],
    "artifact",
  );
  exactString(request.artifact.releaseId, decimalPattern, "release ID");
  if (request.artifact.transportTag !== `deployment-control/${request.requestId}`)
    throw new Error("transport tag differs");
  for (const field of ["transportCommitSha", "ciphertextBlobSha1", "manifestBlobSha1"])
    exactString(request.artifact[field], shaPattern, `artifact ${field}`);
  for (const field of ["ciphertextSha256", "plaintextSha256", "encryptionKeySha256"])
    exactString(request.artifact[field], digestPattern, `artifact ${field}`);
  if (request.artifact.ciphertextBlobSha1 === request.artifact.manifestBlobSha1)
    throw new Error("transport blobs must differ");
  if (
    !Number.isSafeInteger(request.artifact.plaintextBytes) ||
    request.artifact.plaintextBytes < 1 ||
    request.artifact.plaintextBytes > 1_073_741_824
  )
    throw new Error("artifact size is invalid");
  exactObject(
    request.evidence,
    ["immutableRelease", "manifestSha256", "oidcTokenSha256"],
    "evidence",
  );
  if (request.evidence.immutableRelease !== true)
    throw new Error("immutable Release proof is absent");
  exactString(request.evidence.manifestSha256, digestPattern, "manifest digest");
  exactString(request.evidence.oidcTokenSha256, digestPattern, "OIDC digest");
  const issued = Date.parse(request.issuedAt);
  const expires = Date.parse(request.expiresAt);
  if (
    !Number.isFinite(issued) ||
    new Date(issued).toISOString() !== request.issuedAt ||
    !Number.isFinite(expires) ||
    new Date(expires).toISOString() !== request.expiresAt ||
    expires <= issued ||
    expires - issued > 30 * 60_000 ||
    issued > now + 60_000 ||
    now >= expires
  )
    throw new Error("request time window is invalid");
  if (
    request.source.repositoryId !== env.SOURCE_REPOSITORY_ID ||
    request.controller.repositoryId !== env.CONTROLLER_REPOSITORY_ID ||
    request.controller.commitSha !== env.CONTROLLER_COMMIT_SHA
  )
    throw new Error("request repository identity differs");
  if (canonicalJson(request) !== text) throw new Error("request is not canonical");
  return { request, text };
}

export async function verifyGithubOidc(token, request, env, fetcher, now) {
  if (typeof token !== "string" || token.length < 100 || token.length > 16_384)
    throw new Error("OIDC token is malformed");
  if ((await sha256Hex(new TextEncoder().encode(token))) !== request.evidence.oidcTokenSha256)
    throw new Error("OIDC token digest differs");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("OIDC token is malformed");
  const header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  if (
    header.alg !== "RS256" ||
    header.typ !== "JWT" ||
    typeof header.kid !== "string" ||
    header.kid.length > 256
  )
    throw new Error("OIDC header is unsupported");
  const discoveryResponse = await fetcher(`${githubIssuer}/.well-known/openid-configuration`);
  if (!discoveryResponse.ok) throw new Error("OIDC discovery failed");
  const discovery = await discoveryResponse.json();
  if (
    discovery.issuer !== githubIssuer ||
    discovery.jwks_uri !== `${githubIssuer}/.well-known/jwks`
  )
    throw new Error("OIDC discovery identity differs");
  const jwksResponse = await fetcher(discovery.jwks_uri);
  if (!jwksResponse.ok) throw new Error("OIDC signing keys unavailable");
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find(
    (key) =>
      key.kid === header.kid && key.kty === "RSA" && key.alg === "RS256" && key.use === "sig",
  );
  if (!jwk) throw new Error("OIDC signing key differs");
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signatureValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!signatureValid) throw new Error("OIDC signature is invalid");
  const expected = {
    aud: githubAudience,
    event_name: "workflow_dispatch",
    iss: githubIssuer,
    job_workflow_ref: `${env.CONTROLLER_REPOSITORY}/.github/workflows/package-release.yml@${request.controller.commitSha}`,
    job_workflow_sha: request.controller.commitSha,
    ref: "refs/heads/main",
    ref_type: "branch",
    repository: env.SOURCE_REPOSITORY,
    repository_id: request.source.repositoryId,
    repository_owner_id: env.SOURCE_REPOSITORY_OWNER_ID,
    repository_visibility: "private",
    run_attempt: String(request.source.workflowRunAttempt),
    run_id: request.source.workflowRunId,
    runner_environment: "github-hosted",
    sha: request.source.commitSha,
    sub: immutableRepositorySubject(
      env.SOURCE_REPOSITORY,
      env.SOURCE_REPOSITORY_OWNER_ID,
      request.source.repositoryId,
      "ref:refs/heads/main",
    ),
    workflow_ref: `${env.SOURCE_REPOSITORY}/${env.SOURCE_WORKFLOW_PATH}@refs/heads/main`,
    workflow_sha: request.source.commitSha,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (String(claims[field] ?? "") !== String(value))
      throw new Error(`OIDC claim ${field} differs`);
  }
  const seconds = Math.floor(now / 1000);
  if (
    !Number.isInteger(claims.iat) ||
    !Number.isInteger(claims.nbf) ||
    !Number.isInteger(claims.exp) ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > 10 * 60 ||
    claims.iat > seconds + 60 ||
    claims.nbf > seconds + 60 ||
    claims.exp <= seconds ||
    typeof claims.jti !== "string" ||
    claims.jti.length < 16 ||
    claims.jti.length > 256
  )
    throw new Error("OIDC token time or identity is invalid");
  return claims;
}

export async function verifyExecutorOidc(token, request, env, fetcher, now) {
  if (typeof token !== "string" || token.length < 100 || token.length > 16_384)
    throw new Error("executor OIDC token is malformed");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("executor OIDC token is malformed");
  const header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  if (
    header.alg !== "RS256" ||
    header.typ !== "JWT" ||
    typeof header.kid !== "string" ||
    header.kid.length > 256
  )
    throw new Error("executor OIDC header is unsupported");
  const discoveryResponse = await fetcher(`${githubIssuer}/.well-known/openid-configuration`);
  if (!discoveryResponse.ok) throw new Error("executor OIDC discovery failed");
  const discovery = await discoveryResponse.json();
  if (
    discovery.issuer !== githubIssuer ||
    discovery.jwks_uri !== `${githubIssuer}/.well-known/jwks`
  )
    throw new Error("executor OIDC discovery identity differs");
  const jwksResponse = await fetcher(discovery.jwks_uri);
  if (!jwksResponse.ok) throw new Error("executor OIDC signing keys unavailable");
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find(
    (key) =>
      key.kid === header.kid && key.kty === "RSA" && key.alg === "RS256" && key.use === "sig",
  );
  if (!jwk) throw new Error("executor OIDC signing key differs");
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  if (
    !(await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      decodeBase64Url(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    ))
  )
    throw new Error("executor OIDC signature is invalid");
  const protectedEnvironment = request.operation === "canary" ? "canary" : "production";
  const expected = {
    actor_id: env.REQUESTER_APP_ACTOR_ID,
    aud: executorAudience,
    environment: protectedEnvironment,
    event_name: "workflow_dispatch",
    iss: githubIssuer,
    ref: "refs/heads/main",
    ref_type: "branch",
    repository: env.CONTROLLER_REPOSITORY,
    repository_id: request.controller.repositoryId,
    repository_owner_id: env.CONTROLLER_REPOSITORY_OWNER_ID,
    repository_visibility: "public",
    run_attempt: "1",
    runner_environment: "github-hosted",
    sha: request.controller.commitSha,
    sub: immutableRepositorySubject(
      env.CONTROLLER_REPOSITORY,
      env.CONTROLLER_REPOSITORY_OWNER_ID,
      request.controller.repositoryId,
      `environment:${protectedEnvironment}`,
    ),
    workflow_ref: `${env.CONTROLLER_REPOSITORY}/.github/workflows/execute-release.yml@refs/heads/main`,
    workflow_sha: request.controller.commitSha,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (String(claims[field] ?? "") !== String(value))
      throw new Error(`executor OIDC claim ${field} differs`);
  }
  exactString(String(claims.run_id ?? ""), decimalPattern, "executor run ID");
  const seconds = Math.floor(now / 1000);
  if (
    !Number.isInteger(claims.iat) ||
    !Number.isInteger(claims.nbf) ||
    !Number.isInteger(claims.exp) ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > 10 * 60 ||
    claims.iat > seconds + 60 ||
    claims.nbf > seconds + 60 ||
    claims.exp <= seconds ||
    typeof claims.jti !== "string" ||
    claims.jti.length < 16 ||
    claims.jti.length > 256
  )
    throw new Error("executor OIDC token time or identity is invalid");
  return claims;
}

function derLength(length) {
  if (length < 128) return Uint8Array.of(length);
  const bytes = [];
  for (let value = length; value > 0; value >>>= 8) bytes.unshift(value & 255);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function derElement(tag, bytes) {
  return Uint8Array.of(tag, ...derLength(bytes.length), ...bytes);
}

function pkcs1ToPkcs8(pkcs1) {
  const algorithm = Uint8Array.of(
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
  );
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  return derElement(0x30, Uint8Array.of(...version, ...algorithm, ...derElement(0x04, pkcs1)));
}

function pemPrivateKey(pem) {
  if (typeof pem !== "string" || pem.length > 16_384)
    throw new Error("App signing key is unavailable");
  const match =
    /^-----BEGIN (RSA )?PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)\s+-----END \1PRIVATE KEY-----\s*$/.exec(
      pem.trim(),
    );
  if (!match) throw new Error("App signing key format is unsupported");
  const der = Uint8Array.from(atob(match[2].replaceAll(/\s/g, "")), (character) =>
    character.charCodeAt(0),
  );
  return match[1] ? pkcs1ToPkcs8(der) : der;
}

async function appJwt(env, now) {
  exactString(env.GITHUB_APP_ID, decimalPattern, "GitHub App ID");
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemPrivateKey(env.GITHUB_APP_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const header = encodeBase64Url(
    new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })),
  );
  const seconds = Math.floor(now / 1000);
  const payload = encodeBase64Url(
    new TextEncoder().encode(
      JSON.stringify({ exp: seconds + 540, iat: seconds - 60, iss: env.GITHUB_APP_ID }),
    ),
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  return `${header}.${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

async function dispatchWithPublicOnlyApp(encoded, env, fetcher, now) {
  exactString(env.GITHUB_APP_INSTALLATION_ID, decimalPattern, "GitHub App installation ID");
  exactString(env.CONTROLLER_REPOSITORY_ID, decimalPattern, "controller repository ID");
  exactString(
    env.CONTROLLER_REPOSITORY,
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
    "controller repository",
  );
  const jwt = await appJwt(env, now);
  const tokenResponse = await fetcher(
    `${githubApi}/app/installations/${env.GITHUB_APP_INSTALLATION_ID}/access_tokens`,
    {
      method: "POST",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${jwt}`,
        "content-type": "application/json",
        "user-agent": "deployment-control-dispatcher",
        "x-github-api-version": "2022-11-28",
      },
      body: JSON.stringify({
        permissions: { actions: "write" },
        repository_ids: [Number(env.CONTROLLER_REPOSITORY_ID)],
      }),
    },
  );
  if (!tokenResponse.ok) throw new Error("App installation token issuance failed");
  const tokenPayload = await tokenResponse.json();
  if (
    typeof tokenPayload.token !== "string" ||
    tokenPayload.token.length < 20 ||
    !Array.isArray(tokenPayload.repositories) ||
    tokenPayload.repositories.length !== 1 ||
    String(tokenPayload.repositories[0]?.id) !== env.CONTROLLER_REPOSITORY_ID
  )
    throw new Error("App token scope differs");
  const dispatchResponse = await fetcher(
    `${githubApi}/repos/${env.CONTROLLER_REPOSITORY}/actions/workflows/execute-release.yml/dispatches`,
    {
      method: "POST",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${tokenPayload.token}`,
        "content-type": "application/json",
        "user-agent": "deployment-control-dispatcher",
        "x-github-api-version": "2022-11-28",
      },
      body: JSON.stringify({ inputs: { release_request_base64: encoded }, ref: "main" }),
    },
  );
  if (dispatchResponse.status !== 204) throw new Error("controller workflow dispatch failed");
  return dispatchResponse.status;
}

export async function handleDispatch(httpRequest, env, fetcher = fetch, now = Date.now()) {
  const path = new URL(httpRequest.url).pathname;
  const custodyBodyKeys = ciphertextCustodyBodyKeys(path);
  if (
    httpRequest.method !== "POST" ||
    ![
      "/v1/dispatch",
      "/v1/execute-claim",
      "/v1/execute-finish",
      "/v1/verify-prerequisite",
      ...Object.values(ciphertextCustodyPaths),
    ].includes(path)
  )
    return new Response("Not found", { status: 404 });
  try {
    const contentType = httpRequest.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json"))
      throw new Error("content type is invalid");
    const authorization = httpRequest.headers.get("authorization") ?? "";
    if (!authorization.startsWith("Bearer ")) throw new Error("OIDC authorization is absent");
    const bodyText = await httpRequest.text();
    if (bodyText.length > (custodyBodyKeys ? 131_072 : 40_000)) {
      throw new Error("request body is too large");
    }
    const body = JSON.parse(bodyText);
    exactObject(
      body,
      custodyBodyKeys ?? (path === "/v1/execute-finish"
        ? ["releaseRequestBase64", "outcome", "providerReceiptSha256"]
        : path === "/v1/verify-prerequisite"
          ? [
              "releaseRequestBase64",
              "prerequisiteRequestId",
              "prerequisiteReceiptSha256",
              "prerequisiteRunId",
            ]
          : ["releaseRequestBase64"]),
      "dispatch body",
    );
    const verified = parseCanonicalRequest(body.releaseRequestBase64, now, env);
    const requestDigest = await sha256Hex(new TextEncoder().encode(verified.text));
    if (path !== "/v1/dispatch") {
      const claims = await verifyExecutorOidc(
        authorization.slice(7),
        verified.request,
        env,
        fetcher,
        now,
      );
      let protectedResult = null;
      if (custodyBodyKeys) {
        protectedResult = await handleCiphertextCustody({
          body,
          claims,
          environment: env,
          now,
          path,
          request: verified.request,
          requestDigest,
        });
      } else if (path === "/v1/execute-claim") {
        await claimExecution(verified.request, claims, requestDigest, env, now);
      } else if (path === "/v1/verify-prerequisite") {
        await verifyExecutionPrerequisite(
          verified.request,
          claims,
          requestDigest,
          body.prerequisiteRequestId,
          body.prerequisiteReceiptSha256,
          body.prerequisiteRunId,
          env,
          now,
        );
      } else {
        await finishExecution(
          verified.request,
          claims,
          requestDigest,
          body.outcome,
          body.providerReceiptSha256,
          env,
          now,
        );
      }
      return Response.json(
        {
          requestDigest,
          requestId: verified.request.requestId,
          ...(protectedResult ?? {}),
        },
        { status: 202, headers: { "cache-control": "no-store" } },
      );
    }
    const claims = await verifyGithubOidc(
      authorization.slice(7),
      verified.request,
      env,
      fetcher,
      now,
    );
    await claimDispatch(verified.request, claims, requestDigest, env, now);
    try {
      const dispatchStatus = await dispatchWithPublicOnlyApp(
        body.releaseRequestBase64,
        env,
        fetcher,
        now,
      );
      await finishDispatch(verified.request.requestId, "dispatched", dispatchStatus, env, now);
    } catch (error) {
      try {
        await finishDispatch(verified.request.requestId, "ambiguous", 0, env, now);
      } catch {
        // The unique claim remains consumed. Reconciliation is required; never dispatch again.
      }
      throw error;
    }
    return Response.json(
      { requestDigest, requestId: verified.request.requestId },
      { status: 202, headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    if (env.DIAGNOSTIC_LOGGING === "safe") {
      console.warn(
        JSON.stringify({
          event: "deployment_control_dispatch_rejected",
          reason: safeRejectionReason(error),
        }),
      );
    }
    return Response.json(
      { error: "dispatch_rejected" },
      { status: 401, headers: { "cache-control": "no-store" } },
    );
  }
}

export default {
  fetch(request, env) {
    return handleDispatch(request, env);
  },
};
