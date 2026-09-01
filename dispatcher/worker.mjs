const githubIssuer = 'https://token.actions.githubusercontent.com';
const githubAudience = 'deployment-control-packaging-v1';
const githubApi = 'https://api.github.com';
const digestPattern = /^[a-f0-9]{64}$/;
const shaPattern = /^[a-f0-9]{40}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;

function exactObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields differ`);
  }
}

function exactString(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('base64url input is invalid');
  }
  const padded = `${value.replaceAll('-', '+').replaceAll('_', '/')}${'='.repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, '0')).join('');
}

export function parseCanonicalRequest(encoded, now, env) {
  if (typeof encoded !== 'string' || encoded.length < 100 || encoded.length > 32_768) {
    throw new Error('release request size is invalid');
  }
  const bytes = decodeBase64Url(encoded);
  if (bytes.length > 24_576) throw new Error('release request decoded size is invalid');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const request = JSON.parse(text);
  exactObject(request, ['schema', 'requestId', 'nonce', 'issuedAt', 'expiresAt', 'operation', 'source', 'controller', 'artifact', 'evidence'], 'request');
  if (request.schema !== 'deployment-control/release-request/v1') throw new Error('request schema is unsupported');
  exactString(request.requestId, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/, 'requestId');
  exactString(request.nonce, /^[A-Za-z0-9_-]{43}$/, 'nonce');
  if (!['canary', 'production-release'].includes(request.operation)) throw new Error('operation is not allowlisted');
  exactObject(request.source, ['repositoryId', 'commitSha', 'workflowRunId', 'workflowRunAttempt'], 'source');
  exactString(request.source.repositoryId, decimalPattern, 'source repositoryId');
  exactString(request.source.commitSha, shaPattern, 'source SHA');
  exactString(request.source.workflowRunId, decimalPattern, 'source run ID');
  if (!Number.isSafeInteger(request.source.workflowRunAttempt) || request.source.workflowRunAttempt < 1 || request.source.workflowRunAttempt > 100) throw new Error('source run attempt is invalid');
  exactObject(request.controller, ['repositoryId', 'commitSha'], 'controller');
  exactString(request.controller.repositoryId, decimalPattern, 'controller repositoryId');
  exactString(request.controller.commitSha, shaPattern, 'controller SHA');
  exactObject(request.artifact, ['releaseId', 'transportTag', 'transportCommitSha', 'ciphertextBlobSha1', 'manifestBlobSha1', 'ciphertextSha256', 'plaintextSha256', 'plaintextBytes', 'encryptionKeySha256'], 'artifact');
  exactString(request.artifact.releaseId, decimalPattern, 'release ID');
  if (request.artifact.transportTag !== `deployment-control/${request.requestId}`) throw new Error('transport tag differs');
  for (const field of ['transportCommitSha', 'ciphertextBlobSha1', 'manifestBlobSha1']) exactString(request.artifact[field], shaPattern, `artifact ${field}`);
  for (const field of ['ciphertextSha256', 'plaintextSha256', 'encryptionKeySha256']) exactString(request.artifact[field], digestPattern, `artifact ${field}`);
  if (request.artifact.ciphertextBlobSha1 === request.artifact.manifestBlobSha1) throw new Error('transport blobs must differ');
  if (!Number.isSafeInteger(request.artifact.plaintextBytes) || request.artifact.plaintextBytes < 1 || request.artifact.plaintextBytes > 1_073_741_824) throw new Error('artifact size is invalid');
  exactObject(request.evidence, ['immutableRelease', 'manifestSha256', 'oidcTokenSha256'], 'evidence');
  if (request.evidence.immutableRelease !== true) throw new Error('immutable Release proof is absent');
  exactString(request.evidence.manifestSha256, digestPattern, 'manifest digest');
  exactString(request.evidence.oidcTokenSha256, digestPattern, 'OIDC digest');
  const issued = Date.parse(request.issuedAt);
  const expires = Date.parse(request.expiresAt);
  if (!Number.isFinite(issued) || new Date(issued).toISOString() !== request.issuedAt || !Number.isFinite(expires) || new Date(expires).toISOString() !== request.expiresAt || expires <= issued || expires - issued > 30 * 60_000 || issued > now + 60_000 || now >= expires) throw new Error('request time window is invalid');
  if (request.source.repositoryId !== env.SOURCE_REPOSITORY_ID || request.controller.repositoryId !== env.CONTROLLER_REPOSITORY_ID || request.controller.commitSha !== env.CONTROLLER_COMMIT_SHA) throw new Error('request repository identity differs');
  if (canonicalJson(request) !== text) throw new Error('request is not canonical');
  return { request, text };
}

export async function verifyGithubOidc(token, request, env, fetcher, now) {
  if (typeof token !== 'string' || token.length < 100 || token.length > 16_384) throw new Error('OIDC token is malformed');
  if (await sha256Hex(new TextEncoder().encode(token)) !== request.evidence.oidcTokenSha256) throw new Error('OIDC token digest differs');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('OIDC token is malformed');
  const header = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  if (header.alg !== 'RS256' || header.typ !== 'JWT' || typeof header.kid !== 'string' || header.kid.length > 256) throw new Error('OIDC header is unsupported');
  const discoveryResponse = await fetcher(`${githubIssuer}/.well-known/openid-configuration`);
  if (!discoveryResponse.ok) throw new Error('OIDC discovery failed');
  const discovery = await discoveryResponse.json();
  if (discovery.issuer !== githubIssuer || discovery.jwks_uri !== `${githubIssuer}/.well-known/jwks`) throw new Error('OIDC discovery identity differs');
  const jwksResponse = await fetcher(discovery.jwks_uri);
  if (!jwksResponse.ok) throw new Error('OIDC signing keys unavailable');
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find((key) => key.kid === header.kid && key.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig');
  if (!jwk) throw new Error('OIDC signing key differs');
  const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const signatureValid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, decodeBase64Url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!signatureValid) throw new Error('OIDC signature is invalid');
  const expected = {
    aud: githubAudience,
    event_name: 'workflow_dispatch',
    iss: githubIssuer,
    job_workflow_ref: `${env.CONTROLLER_REPOSITORY}/.github/workflows/package-release.yml@${request.controller.commitSha}`,
    job_workflow_sha: request.controller.commitSha,
    ref: 'refs/heads/main',
    ref_type: 'branch',
    repository: env.SOURCE_REPOSITORY,
    repository_id: request.source.repositoryId,
    repository_visibility: 'private',
    run_attempt: String(request.source.workflowRunAttempt),
    run_id: request.source.workflowRunId,
    runner_environment: 'github-hosted',
    sha: request.source.commitSha,
    sub: `repo:${env.SOURCE_REPOSITORY}:ref:refs/heads/main`,
    workflow_ref: `${env.SOURCE_REPOSITORY}/${env.SOURCE_WORKFLOW_PATH}@refs/heads/main`,
    workflow_sha: request.source.commitSha,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (String(claims[field] ?? '') !== String(value)) throw new Error(`OIDC claim ${field} differs`);
  }
  const seconds = Math.floor(now / 1000);
  if (!Number.isInteger(claims.iat) || !Number.isInteger(claims.nbf) || !Number.isInteger(claims.exp) || claims.exp <= claims.iat || claims.exp - claims.iat > 10 * 60 || claims.iat > seconds + 60 || claims.nbf > seconds + 60 || claims.exp <= seconds || typeof claims.jti !== 'string' || claims.jti.length < 16 || claims.jti.length > 256) throw new Error('OIDC token time or identity is invalid');
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
  const algorithm = Uint8Array.of(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00);
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  return derElement(0x30, Uint8Array.of(...version, ...algorithm, ...derElement(0x04, pkcs1)));
}

function pemPrivateKey(pem) {
  if (typeof pem !== 'string' || pem.length > 16_384) throw new Error('App signing key is unavailable');
  const match = /^-----BEGIN (RSA )?PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)\s+-----END \1PRIVATE KEY-----\s*$/.exec(pem.trim());
  if (!match) throw new Error('App signing key format is unsupported');
  const der = Uint8Array.from(atob(match[2].replaceAll(/\s/g, '')), (character) => character.charCodeAt(0));
  return match[1] ? pkcs1ToPkcs8(der) : der;
}

async function appJwt(env, now) {
  exactString(env.GITHUB_APP_ID, decimalPattern, 'GitHub App ID');
  const key = await crypto.subtle.importKey('pkcs8', pemPrivateKey(env.GITHUB_APP_PRIVATE_KEY), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const header = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const seconds = Math.floor(now / 1000);
  const payload = encodeBase64Url(new TextEncoder().encode(JSON.stringify({ exp: seconds + 540, iat: seconds - 60, iss: env.GITHUB_APP_ID })));
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${header}.${payload}`));
  return `${header}.${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

async function dispatchWithPublicOnlyApp(encoded, env, fetcher, now) {
  exactString(env.GITHUB_APP_INSTALLATION_ID, decimalPattern, 'GitHub App installation ID');
  exactString(env.CONTROLLER_REPOSITORY_ID, decimalPattern, 'controller repository ID');
  exactString(env.CONTROLLER_REPOSITORY, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, 'controller repository');
  const jwt = await appJwt(env, now);
  const tokenResponse = await fetcher(`${githubApi}/app/installations/${env.GITHUB_APP_INSTALLATION_ID}/access_tokens`, {
    method: 'POST',
    headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${jwt}`, 'content-type': 'application/json', 'user-agent': 'deployment-control-dispatcher', 'x-github-api-version': '2022-11-28' },
    body: JSON.stringify({ permissions: { actions: 'write' }, repository_ids: [Number(env.CONTROLLER_REPOSITORY_ID)] }),
  });
  if (!tokenResponse.ok) throw new Error('App installation token issuance failed');
  const tokenPayload = await tokenResponse.json();
  if (typeof tokenPayload.token !== 'string' || tokenPayload.token.length < 20 || !Array.isArray(tokenPayload.repositories) || tokenPayload.repositories.length !== 1 || String(tokenPayload.repositories[0]?.id) !== env.CONTROLLER_REPOSITORY_ID) throw new Error('App token scope differs');
  const dispatchResponse = await fetcher(`${githubApi}/repos/${env.CONTROLLER_REPOSITORY}/actions/workflows/execute-release.yml/dispatches`, {
    method: 'POST',
    headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${tokenPayload.token}`, 'content-type': 'application/json', 'user-agent': 'deployment-control-dispatcher', 'x-github-api-version': '2022-11-28' },
    body: JSON.stringify({ inputs: { release_request_base64: encoded }, ref: 'main' }),
  });
  if (dispatchResponse.status !== 204) throw new Error('controller workflow dispatch failed');
}

export async function handleDispatch(httpRequest, env, fetcher = fetch, now = Date.now()) {
  if (httpRequest.method !== 'POST' || new URL(httpRequest.url).pathname !== '/v1/dispatch') return new Response('Not found', { status: 404 });
  try {
    const contentType = httpRequest.headers.get('content-type') ?? '';
    if (!contentType.toLowerCase().startsWith('application/json')) throw new Error('content type is invalid');
    const authorization = httpRequest.headers.get('authorization') ?? '';
    if (!authorization.startsWith('Bearer ')) throw new Error('OIDC authorization is absent');
    const bodyText = await httpRequest.text();
    if (bodyText.length > 40_000) throw new Error('request body is too large');
    const body = JSON.parse(bodyText);
    exactObject(body, ['releaseRequestBase64'], 'dispatch body');
    const verified = parseCanonicalRequest(body.releaseRequestBase64, now, env);
    await verifyGithubOidc(authorization.slice(7), verified.request, env, fetcher, now);
    await dispatchWithPublicOnlyApp(body.releaseRequestBase64, env, fetcher, now);
    return Response.json({ requestDigest: await sha256Hex(new TextEncoder().encode(verified.text)), requestId: verified.request.requestId }, { status: 202, headers: { 'cache-control': 'no-store' } });
  } catch {
    return Response.json({ error: 'dispatch_rejected' }, { status: 401, headers: { 'cache-control': 'no-store' } });
  }
}

export default {
  fetch(request, env) {
    return handleDispatch(request, env);
  },
};
