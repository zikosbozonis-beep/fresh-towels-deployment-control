import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, sha256 } from "./control-contract.mjs";
import { canonicalDnsInventory } from "./dns-inventory.mjs";
import {
  createResendHttpAdapter,
  ProviderRejectedError,
  ProviderTransportAmbiguousError,
} from "./provider-adapter.mjs";
import {
  validateDecryptionBindings,
  validateImportedSecretKey,
} from "./protected-transport.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const safeIdPattern = /^[A-Za-z0-9_-]{1,200}$/;
const wranglerVersion = "4.127.1";
const expectedWebhookEvents = Object.freeze([
  "email.bounced",
  "email.complained",
  "email.delivered",
  "email.delivery_delayed",
  "email.failed",
  "email.sent",
  "email.suppressed",
]);
const expectedSecretBindings = Object.freeze([
  "DASHBOARD_AUTHORIZED_EMAILS",
  "LEAD_RATE_LIMIT_SECRET",
  "RESEND_API_KEY",
  "RESEND_WEBHOOK_SECRET",
]);
const controllerRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const gpgPrimaryFingerprintPath = resolve(
  controllerRoot,
  "keys/release-encryption-fingerprint.txt",
);
const gpgEncryptionFingerprintPath = resolve(
  controllerRoot,
  "keys/release-encryption-subkey-fingerprint.txt",
);
const gpgPublicKeyPath = resolve(controllerRoot, "keys/release-encryption-public.asc");

function exactObject(value, keys, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(label + " must be a plain object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(label + " contains missing or unexpected fields");
  }
}

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
}

function requestInput(method, path, options = {}) {
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

async function request(client, method, path, options) {
  if (!client || typeof client.request !== "function") {
    throw new Error("production provider client is unavailable");
  }
  return client.request(requestInput(method, path, options));
}

function completeList(response, label) {
  const nested = [
    response.result?.items,
    response.result?.deployments,
    response.result?.schedules,
    response.result?.data,
  ].filter(Array.isArray);
  const values = Array.isArray(response.result) ? response.result : nested[0];
  if (
    response.pagination?.complete !== true ||
    !Array.isArray(values) ||
    (!Array.isArray(response.result) && nested.length !== 1)
  ) {
    throw new Error(label + " pagination is incomplete");
  }
  return values;
}

function one(values, predicate, label) {
  const selected = values.filter(predicate);
  if (selected.length !== 1) throw new Error(label + " is absent or ambiguous");
  return selected[0];
}

function providerState(receipt, cloudflare, resend) {
  const state = { cloudflare, resend };
  return Object.freeze({ ...state, stateSha256: digest(state) });
}

function exactD1(value, expected, label) {
  if (
    value?.uuid !== expected.databaseId ||
    value?.name !== expected.databaseName ||
    value?.jurisdiction !== "eu"
  ) {
    throw new Error(label + " D1 live identity changed");
  }
  return { databaseId: value.uuid, databaseName: value.name };
}

function normalizeDestinations(value) {
  if (!Array.isArray(value)) throw new Error("Access destinations are unavailable");
  const normalized = value.map((item) => {
    exactObject(item, ["type", "uri"], "Access destination");
    return { type: item.type, uri: item.uri };
  });
  normalized.sort((left, right) => left.uri.localeCompare(right.uri));
  if (new Set(normalized.map((item) => item.uri)).size !== normalized.length) {
    throw new Error("Access destinations are duplicated");
  }
  return normalized;
}

function normalizePolicy(policy, policyCount) {
  const include = Array.isArray(policy?.include) ? policy.include : [];
  const exclude = Array.isArray(policy?.exclude) ? policy.exclude : [];
  const requireRules = Array.isArray(policy?.require) ? policy.require : [];
  const email = include.length === 1 ? include[0]?.email?.email : null;
  if (
    typeof email !== "string" ||
    Object.keys(include[0] ?? {}).length !== 1 ||
    Object.keys(include[0]?.email ?? {}).length !== 1 ||
    exclude.length !== 0 ||
    requireRules.length !== 0
  ) {
    throw new Error("Access allowlist rule changed");
  }
  return {
    policyId: policy.id,
    adminIdentitySha256: sha256(Buffer.from(email, "utf8")),
    policyDecision: policy.decision,
    policyPrecedence: policy.precedence,
    extraPolicyCount: policyCount - 1,
  };
}

async function inspectCloudflareProviderState(client, receipt) {
  const expected = receipt.cloudflare;
  const account = await request(client, "GET", `/accounts/${expected.accountId}`);
  if (account.result?.id !== expected.accountId) throw new Error("Cloudflare account changed");
  const subdomain = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/workers/subdomain`,
  );
  if (subdomain.result?.subdomain !== expected.workersDevSubdomain) {
    throw new Error("Cloudflare workers.dev identity changed");
  }
  const zone = await request(client, "GET", `/zones/${expected.zoneId}`);
  const liveNameservers = [...(zone.result?.name_servers ?? [])].sort();
  if (
    zone.result?.id !== expected.zoneId ||
    zone.result?.name !== expected.zoneName ||
    zone.result?.status !== "active" ||
    canonicalJson(liveNameservers) !== canonicalJson([...expected.nameServers].sort())
  ) {
    throw new Error("Cloudflare zone live state changed");
  }
  for (const [settingId, expectedValue] of Object.entries(expected.zoneSettings)) {
    const setting = await request(client, "GET", `/zones/${expected.zoneId}/settings/${settingId}`);
    if (setting.result?.id !== settingId || setting.result?.value !== expectedValue) {
      throw new Error("Cloudflare zone security setting changed");
    }
  }
  const dnsInventoryResponse = await request(
    client,
    "GET",
    `/zones/${expected.zoneId}/dns_records`,
    { query: { page: "1", per_page: "10000" } },
  );
  const dnsInventory = canonicalDnsInventory(
    completeList(dnsInventoryResponse, "Cloudflare DNS inventory"),
  );
  if (
    dnsInventory.length !== expected.dnsInventoryCount ||
    digest(dnsInventory) !== expected.dnsInventorySha256
  ) {
    throw new Error("Cloudflare full DNS inventory changed");
  }
  const primary = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/d1/database/${expected.d1.primary.databaseId}`,
  );
  const recovery = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/d1/database/${expected.d1.recovery.databaseId}`,
  );
  exactD1(primary.result, expected.d1.primary, "primary");
  exactD1(recovery.result, expected.d1.recovery, "recovery");

  const access = expected.access;
  const organization = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/access/organizations`,
  );
  const idp = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/access/identity_providers/${access.identityProviderId}`,
  );
  const application = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/access/apps/${access.applicationId}`,
  );
  const policyResponse = await request(
    client,
    "GET",
    `/accounts/${expected.accountId}/access/apps/${access.applicationId}/policies`,
    { query: { page: "1", per_page: "1000" } },
  );
  const policies = completeList(policyResponse, "Access policies");
  const policy = one(policies, (item) => item?.id === access.policyId, "Access policy");
  const normalizedPolicy = normalizePolicy(policy, policies.length);
  const app = application.result;
  const normalizedAccess = {
    identityProviderId: idp.result?.id,
    identityProviderType: idp.result?.type,
    applicationId: app?.id,
    applicationDomain: app?.domain,
    policyId: normalizedPolicy.policyId,
    aud: app?.aud,
    destinations: normalizeDestinations(app?.destinations),
    allowedIdentityProviderIds: Array.isArray(app?.allowed_idps) ? [...app.allowed_idps] : null,
    adminIdentitySha256: normalizedPolicy.adminIdentitySha256,
    policyDecision: normalizedPolicy.policyDecision,
    policyPrecedence: normalizedPolicy.policyPrecedence,
    extraPolicyCount: normalizedPolicy.extraPolicyCount,
    httpOnlyCookieAttribute: app?.http_only_cookie_attribute,
    sameSiteCookieAttribute: app?.same_site_cookie_attribute,
    enableBindingCookie: app?.enable_binding_cookie,
    pathCookieAttribute: app?.path_cookie_attribute,
    allowIframe: app?.allow_iframe,
    allowAuthenticateViaWarp: app?.allow_authenticate_via_warp,
    skipInterstitial: app?.skip_interstitial,
    optionsPreflightBypass: app?.options_preflight_bypass,
    appLauncherVisible: app?.app_launcher_visible,
    autoRedirectToIdentity: app?.auto_redirect_to_identity,
    teamDomain: "https://" + organization.result?.auth_domain,
    organizationSessionDuration: organization.result?.session_duration,
    applicationSessionDuration: application.result?.session_duration,
  };
  if (canonicalJson(normalizedAccess) !== canonicalJson(access)) {
    throw new Error("Cloudflare Access live state changed");
  }
  return structuredClone(expected);
}

async function proveRuntimeResendKey(resendRuntimeClient, expectedDigest) {
  try {
    await request(resendRuntimeClient, "GET", "/api-keys", { query: { limit: "100" } });
  } catch (error) {
    if (
      error instanceof ProviderRejectedError &&
      error.status === 401 &&
      error.providerErrorCode === "restricted_api_key"
    ) {
      const proof = digest({
        expectedProviderErrorCode: "restricted_api_key",
        expectedResult: "management-access-denied",
        expectedStatus: 401,
        method: "GET",
        path: "/api-keys",
        provider: "resend",
        query: { limit: "100" },
        schema: "deployment-control/resend-runtime-least-privilege-probe/v1",
      });
      if (proof !== expectedDigest) throw new Error("Resend least-privilege proof changed");
      return;
    }
    throw error;
  }
  throw new Error("Resend runtime key has management access");
}

async function inspectResendAdminProviderState({ adminClient, receipt }) {
  const expected = receipt.resend;
  const domainResponse = await request(adminClient, "GET", "/domains", {
    query: { limit: "100" },
  });
  const domain = one(
    completeList(domainResponse, "Resend domains"),
    (item) => item?.id === expected.domainId && item?.name === expected.domain,
    "Resend domain",
  );
  if (domain.status !== "verified" || domain.capabilities?.sending !== "enabled") {
    throw new Error("Resend sending domain is not ready");
  }
  const webhookResponse = await request(adminClient, "GET", "/webhooks", {
    query: { limit: "100" },
  });
  const webhook = one(
    completeList(webhookResponse, "Resend webhooks"),
    (item) => item?.id === expected.webhookId,
    "Resend webhook",
  );
  const webhookDetail = await request(adminClient, "GET", `/webhooks/${expected.webhookId}`);
  const detail = webhookDetail.result;
  const events = [...(detail?.events ?? [])].sort();
  if (
    webhook.endpoint !== detail?.endpoint ||
    webhook.status !== detail?.status ||
    detail?.id !== expected.webhookId ||
    sha256(Buffer.from(detail?.endpoint ?? "", "utf8")) !== expected.webhookEndpointSha256 ||
    canonicalJson(events) !== canonicalJson(expectedWebhookEvents) ||
    detail?.status !== "enabled" ||
    typeof detail?.signing_secret !== "string" ||
    !detail.signing_secret.startsWith("whsec_")
  ) {
    throw new Error("Resend webhook live state changed");
  }
  const signingSecretSha256 = sha256(Buffer.from(detail.signing_secret, "utf8"));
  const webhookResourceIdentitySha256 = digest({
    provider: "resend",
    resource: "webhook",
    id: detail.id,
    endpoint: detail.endpoint,
    events,
    signingSecretSha256,
  });
  const expectedWebhookIdentity =
    receipt.runtimeSecrets?.RESEND_WEBHOOK_SECRET?.resourceIdentitySha256;
  if (
    expectedWebhookIdentity !== undefined &&
    webhookResourceIdentitySha256 !== expectedWebhookIdentity
  ) {
    throw new Error("Resend webhook custody identity changed");
  }
  const keyResponse = await request(adminClient, "GET", "/api-keys", {
    query: { limit: "100" },
  });
  one(
    completeList(keyResponse, "Resend API keys"),
    (item) => item?.id === expected.sendingKeyId && item?.name === expected.sendingKeyName,
    "Resend sending key",
  );
  return structuredClone(expected);
}

async function inspectResendProviderState({ adminClient, runtimeClient, receipt }) {
  const state = await inspectResendAdminProviderState({ adminClient, receipt });
  await proveRuntimeResendKey(runtimeClient, receipt.resend.sendingKeyLeastPrivilegeProbeSha256);
  return state;
}

export async function inspectProductionCutoverProviderState({
  cloudflareClient,
  infrastructure,
  approvedState,
  resendAdminClient,
} = {}) {
  if (
    !cloudflareClient?.request ||
    !resendAdminClient?.request ||
    infrastructure === null ||
    typeof infrastructure !== "object" ||
    approvedState === null ||
    typeof approvedState !== "object"
  ) {
    throw new Error("production cutover provider inspection is unavailable");
  }
  const [cloudflare, resend] = await Promise.all([
    inspectCloudflareProviderState(cloudflareClient, infrastructure),
    inspectResendAdminProviderState({
      adminClient: resendAdminClient,
      receipt: infrastructure,
    }),
  ]);
  const state = providerState(infrastructure, cloudflare, resend);
  if (canonicalJson(state) !== canonicalJson(approvedState)) {
    throw new Error("production provider state differs from the approved private receipt");
  }
  return state;
}

export async function inspectProductionCutoverWorkerState({
  cloudflareClient,
  accountId,
  approvedWorker,
} = {}) {
  if (
    !cloudflareClient?.request ||
    !/^[a-f0-9]{32}$/.test(accountId ?? "") ||
    approvedWorker?.name !== "fresh-towels-production" ||
    !uuidPattern.test(approvedWorker?.versionId ?? "") ||
    !digestPattern.test(approvedWorker?.versionStateSha256 ?? "") ||
    !digestPattern.test(approvedWorker?.deploymentStateSha256 ?? "")
  ) {
    throw new Error("production cutover Worker inspection is unavailable");
  }
  const versionsResponse = await request(
    cloudflareClient,
    "GET",
    `/accounts/${accountId}/workers/scripts/${approvedWorker.name}/versions`,
    { query: { page: "1", per_page: "100" } },
  );
  const versions = completeList(versionsResponse, "Worker versions");
  if (
    versions.length !== 1 ||
    versions[0]?.id !== approvedWorker.versionId ||
    versions[0]?.number !== 1 ||
    versions[0]?.metadata?.source !== "wrangler"
  ) {
    throw new Error("production Worker version identity changed");
  }
  const versionResponse = await request(
    cloudflareClient,
    "GET",
    `/accounts/${accountId}/workers/scripts/${approvedWorker.name}/versions/${approvedWorker.versionId}`,
  );
  if (
    versionResponse.result?.id !== approvedWorker.versionId ||
    digest(versionResponse.result) !== approvedWorker.versionStateSha256
  ) {
    throw new Error("production Worker version state changed");
  }
  const deploymentsResponse = await request(
    cloudflareClient,
    "GET",
    `/accounts/${accountId}/workers/scripts/${approvedWorker.name}/deployments`,
  );
  const deployment = deploymentFromResult(deploymentsResponse.result);
  if (
    deployment?.versionId !== approvedWorker.versionId ||
    deployment.percentage !== 100 ||
    deployment.stateSha256 !== approvedWorker.deploymentStateSha256
  ) {
    throw new Error("production Worker deployment state changed");
  }
  const body = {
    workerName: approvedWorker.name,
    versionId: approvedWorker.versionId,
    percentage: 100,
    versionStateSha256: approvedWorker.versionStateSha256,
    deploymentStateSha256: approvedWorker.deploymentStateSha256,
  };
  return Object.freeze({ ...body, stateSha256: digest(body) });
}

function minimalWranglerEnvironment(environment, token, accountId, stateRoot) {
  if (
    typeof token !== "string" ||
    token.length < 20 ||
    token.length > 2048 ||
    /[\s\0]/.test(token) ||
    !/^[a-f0-9]{32}$/.test(accountId)
  ) {
    throw new Error("protected Cloudflare credential is invalid");
  }
  return {
    CI: "true",
    CLOUDFLARE_ACCOUNT_ID: accountId,
    CLOUDFLARE_API_TOKEN: token,
    HOME: stateRoot,
    XDG_CACHE_HOME: join(stateRoot, "cache"),
    XDG_CONFIG_HOME: join(stateRoot, "config"),
    NO_COLOR: "1",
    PATH: `${dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin`,
    WRANGLER_API_ENVIRONMENT: "production",
    WRANGLER_LOG_SANITIZE: "true",
    WRANGLER_NO_SKILLS_UPDATE_PROMPTS: "true",
    WRANGLER_SEND_ERROR_REPORTS: "false",
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_WRITE_LOGS: "false",
  };
}

export function createPinnedWranglerRunner({
  accountId,
  environment = process.env,
  spawn = spawnSync,
  token,
} = {}) {
  const executable = resolve(controllerRoot, "node_modules/wrangler/bin/wrangler.js");
  return async function runWrangler(arguments_, { cwd, mutation = true } = {}) {
    if (
      !Array.isArray(arguments_) ||
      arguments_.length < 1 ||
      arguments_.some(
        (value) =>
          typeof value !== "string" || value.length < 1 || value.length > 2048 || /[\r\n\0]/.test(value),
      )
    ) {
      throw new Error("Wrangler arguments are outside the fixed boundary");
    }
    const stateRoot = await mkdtemp(join(environment.RUNNER_TEMP ?? process.cwd(), "wrangler-state-"));
    try {
      await mkdir(join(stateRoot, "cache"), { mode: 0o700 });
      await mkdir(join(stateRoot, "config"), { mode: 0o700 });
      const result = spawn(process.execPath, [executable, ...arguments_], {
        cwd,
        encoding: "utf8",
        env: minimalWranglerEnvironment(environment, token, accountId, stateRoot),
        maxBuffer: 2 * 1024 * 1024,
        timeout: 8 * 60 * 1000,
        windowsHide: true,
      });
      const output = Buffer.from(`${result.stdout ?? ""}\n${result.stderr ?? ""}`, "utf8");
      if (result.status !== 0 || result.error) {
        const error = new Error(
          mutation
            ? "Wrangler remote outcome is ambiguous; reconcile before retry"
            : "Wrangler read-only operation failed",
        );
        error.remoteOutcomeUnknown = mutation;
        error.outputSha256 = sha256(output);
        throw error;
      }
      return Object.freeze({ stdout: String(result.stdout ?? ""), outputSha256: sha256(output) });
    } finally {
      await rm(stateRoot, { force: true, recursive: true });
    }
  };
}

function resultRows(response, label) {
  if (
    !Array.isArray(response.result) ||
    response.result.length !== 1 ||
    response.result[0]?.success !== true ||
    !Array.isArray(response.result[0].results)
  ) {
    throw new Error(label + " D1 query result is malformed");
  }
  return response.result[0].results;
}

async function d1Query(client, accountId, databaseId, sql) {
  const body = { params: [], sql };
  return resultRows(
    await request(client, "POST", `/accounts/${accountId}/d1/database/${databaseId}/query`, {
      body,
      bodySha256: digest(body),
    }),
    "production",
  );
}

async function inspectD1Database(client, accountId, database, migrations) {
  const schemaRows = await d1Query(
    client,
    accountId,
    database.databaseId,
    "SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
  );
  const names = new Set(schemaRows.map((row) => row.name));
  let appliedMigrations = [];
  let schemaVersion = 0;
  let leadCount = 0;
  if (names.has("d1_migrations")) {
    const rows = await d1Query(
      client,
      accountId,
      database.databaseId,
      "SELECT name FROM d1_migrations ORDER BY id",
    );
    appliedMigrations = rows.map((row) => {
      const match = /^(\d{4})_[a-z0-9_]+\.sql$/.exec(row.name ?? "");
      if (!match) throw new Error("D1 migration ledger contains an invalid name");
      return { version: Number(match[1]), name: row.name };
    });
  }
  if (names.has("schema_migrations")) {
    const rows = await d1Query(
      client,
      accountId,
      database.databaseId,
      "SELECT version FROM schema_migrations ORDER BY version",
    );
    if (rows.some((row, index) => row.version !== index + 1)) {
      throw new Error("application schema migration ledger is not contiguous");
    }
    schemaVersion = rows.length;
  }
  if (names.has("leads")) {
    const rows = await d1Query(client, accountId, database.databaseId, "SELECT COUNT(*) AS count FROM leads");
    if (rows.length !== 1 || !Number.isSafeInteger(rows[0].count)) {
      throw new Error("D1 lead count proof is invalid");
    }
    leadCount = rows[0].count;
  }
  if (
    appliedMigrations.some(
      (item, index) =>
        item.version !== migrations[index]?.version || item.name !== migrations[index]?.name,
    )
  ) {
    throw new Error("D1 migration content identity changed");
  }
  return Object.freeze({
    databaseId: database.databaseId,
    databaseName: database.databaseName,
    jurisdiction: "eu",
    appliedMigrations,
    schemaVersion,
    schemaSha256: digest(schemaRows),
    leadCount,
  });
}

export function parseWranglerUploadedVersionId(stdout) {
  if (
    typeof stdout !== "string" ||
    stdout.length < 1 ||
    stdout.length > 2 * 1024 * 1024 ||
    stdout.includes("\0") ||
    /\r(?!\n)/.test(stdout)
  ) {
    throw new Error("Wrangler upload output is outside the fixed boundary");
  }
  const lines = stdout.replaceAll("\r\n", "\n").split("\n");
  const matches = lines
    .map((line) => /^Worker Version ID: ([a-f0-9-]+)$/.exec(line))
    .filter(Boolean);
  const allUuids = stdout.match(
    /[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}/g,
  );
  if (
    matches.length !== 1 ||
    !uuidPattern.test(matches[0][1]) ||
    allUuids?.length !== 1 ||
    allUuids[0] !== matches[0][1]
  ) {
    throw new Error("Wrangler upload did not return one exact Worker Version ID");
  }
  return matches[0][1];
}

function deploymentFromResult(result) {
  if (result === null || result === undefined) return null;
  const nested = [result.items, result.deployments].filter(Array.isArray);
  const items = Array.isArray(result) ? result : nested[0];
  if (!Array.isArray(result) && nested.length !== 1) {
    throw new Error("Worker deployment response is ambiguous");
  }
  if (!Array.isArray(items) || items.length === 0) return null;
  const deployment = items[0];
  if (!Array.isArray(deployment.versions) || deployment.versions.length !== 1) {
    throw new Error("Worker deployment is split or ambiguous");
  }
  const version = deployment.versions[0];
  return {
    versionId: version.version_id,
    percentage: version.percentage,
    stateSha256: digest(deployment),
  };
}

function runGpg(arguments_, { environment, input } = {}) {
  const result = spawnSync("gpg", arguments_, {
    encoding: "utf8",
    env: environment,
    input,
    maxBuffer: 2 * 1024 * 1024,
    timeout: 2 * 60 * 1000,
    windowsHide: true,
  });
  if (result.status !== 0 || result.error) {
    throw new Error("offline D1 recovery cryptography failed");
  }
  return String(result.stdout ?? "");
}

async function overwriteAndRemove(path) {
  const stat = await lstat(path).catch(() => null);
  if (stat?.isFile()) {
    await writeFile(path, Buffer.alloc(stat.size), { flag: "r+", mode: 0o600 }).catch(
      () => undefined,
    );
  }
  await rm(path, { force: true });
}

async function encryptedD1RecoveryProof({
  cloudflareClient,
  environment,
  runWrangler,
  accountId,
  input,
  recoverySnapshotSink,
}) {
  const root = await mkdtemp(join(environment.RUNNER_TEMP ?? process.cwd(), "d1-recovery-"));
  const configuration = resolve(input.materializedRoot, "wrangler.jsonc");
  const plaintextPath = join(root, "primary.sql");
  const encryptedPath = join(root, "primary.sql.gpg");
  const decryptedPath = join(root, "decrypted.sql");
  const privateKeyPath = join(root, "private.asc");
  const publicKeyPath = join(root, "public.asc");
  const gpgHome = join(root, "gnupg");
  const bindings = validateDecryptionBindings(environment);
  let privateKeyBytes = Buffer.from(bindings.privateKey, "utf8");
  let passphraseBytes = Buffer.from(bindings.passphrase, "utf8");
  try {
    await mkdir(gpgHome, { mode: 0o700 });
    const [publicKeyBytes, primaryFingerprint, encryptionFingerprint] = await Promise.all([
      readFile(gpgPublicKeyPath),
      readFile(gpgPrimaryFingerprintPath, "utf8").then((value) => value.trim()),
      readFile(gpgEncryptionFingerprintPath, "utf8").then((value) => value.trim()),
    ]);
    await writeFile(publicKeyPath, publicKeyBytes, { flag: "wx", mode: 0o400 });
    await writeFile(privateKeyPath, privateKeyBytes, { flag: "wx", mode: 0o600 });
    const cleanEnvironment = {
      GNUPGHOME: gpgHome,
      HOME: root,
      PATH: environment.PATH ?? process.env.PATH,
    };
    runGpg(["--batch", "--no-tty", "--homedir", gpgHome, "--import", publicKeyPath], {
      environment: cleanEnvironment,
    });
    runGpg(["--batch", "--no-tty", "--homedir", gpgHome, "--import", privateKeyPath], {
      environment: cleanEnvironment,
    });
    const listing = runGpg(
      [
        "--batch",
        "--no-tty",
        "--homedir",
        gpgHome,
        "--with-colons",
        "--list-secret-keys",
        "--fingerprint",
        "--fingerprint",
      ],
      { environment: cleanEnvironment },
    );
    validateImportedSecretKey(listing, primaryFingerprint, encryptionFingerprint);

    await runWrangler(
      [
        "d1",
        "export",
        input.primary.databaseId,
        "--remote",
        "--skip-confirmation",
        "--output",
        plaintextPath,
        "--config",
        configuration,
      ],
      { cwd: input.materializedRoot, mutation: false },
    );
    const timeTravel = await runWrangler(
      [
        "d1",
        "time-travel",
        "info",
        input.primary.databaseId,
        "--json",
        "--config",
        configuration,
      ],
      { cwd: input.materializedRoot, mutation: false },
    );
    let timeTravelValue;
    try {
      timeTravelValue = JSON.parse(timeTravel.stdout);
    } catch {
      throw new Error("D1 Time Travel evidence is malformed");
    }
    const plaintextBytes = await readFile(plaintextPath);
    if (plaintextBytes.length < 1 || plaintextBytes.length > 60_000) {
      throw new Error("D1 export size is outside the recovery boundary");
    }
    runGpg(
      [
        "--batch",
        "--no-tty",
        "--homedir",
        gpgHome,
        "--no-auto-key-retrieve",
        "--auto-key-locate",
        "clear",
        "--trust-model",
        "always",
        "--recipient",
        `${encryptionFingerprint}!`,
        "--output",
        encryptedPath,
        "--encrypt",
        plaintextPath,
      ],
      { environment: cleanEnvironment },
    );
    runGpg(
      [
        "--batch",
        "--no-tty",
        "--homedir",
        gpgHome,
        "--no-auto-key-retrieve",
        "--auto-key-locate",
        "clear",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--output",
        decryptedPath,
        "--decrypt",
        encryptedPath,
      ],
      { environment: cleanEnvironment, input: `${bindings.passphrase}\n` },
    );
    const [encryptedBytes, decryptedBytes] = await Promise.all([
      readFile(encryptedPath),
      readFile(decryptedPath),
    ]);
    const plaintextBackupSha256 = sha256(plaintextBytes);
    const encryptedBackupSha256 = sha256(encryptedBytes);
    if (
      sha256(decryptedBytes) !== plaintextBackupSha256 ||
      encryptedBackupSha256 === plaintextBackupSha256
    ) {
      throw new Error("encrypted D1 recovery round-trip differs");
    }

    const recoveryBefore = await inspectD1Database(
      cloudflareClient,
      accountId,
      input.recovery,
      input.migrations,
    );
    if (recoveryBefore.leadCount !== 0) {
      throw new Error("isolated recovery target is not empty");
    }
    if (recoveryBefore.appliedMigrations.length === 0) {
      await runWrangler(
        [
          "d1",
          "execute",
          input.recovery.databaseId,
          "--remote",
          "--yes",
          "--file",
          decryptedPath,
          "--config",
          configuration,
        ],
        { cwd: input.materializedRoot, mutation: true },
      );
    } else if (
      recoveryBefore.appliedMigrations.length !== input.migrations.length ||
      recoveryBefore.schemaVersion !== input.expectedSchemaVersion ||
      recoveryBefore.schemaSha256 !== input.expectedSchemaSha256
    ) {
      throw new Error("existing isolated recovery target cannot be reconciled safely");
    }
    const recoveryAfter = await inspectD1Database(
      cloudflareClient,
      accountId,
      input.recovery,
      input.migrations,
    );
    if (
      recoveryAfter.schemaSha256 !== input.expectedSchemaSha256 ||
      recoveryAfter.schemaVersion !== input.expectedSchemaVersion ||
      recoveryAfter.leadCount !== 0
    ) {
      throw new Error("isolated D1 restore did not reproduce the primary schema");
    }
    if (!recoverySnapshotSink || typeof recoverySnapshotSink.store !== "function") {
      throw new Error("private encrypted D1 recovery custody is unavailable");
    }
    const custody = await recoverySnapshotSink.store({
      backupBytes: plaintextBytes,
      backupSha256: plaintextBackupSha256,
    });
    if (
      custody?.stored !== true ||
      !digestPattern.test(custody.bindingVersionSha256 ?? "") ||
      !digestPattern.test(custody.ciphertextSha256 ?? "") ||
      !digestPattern.test(custody.custodySha256 ?? "") ||
      !digestPattern.test(custody.decryptionProofSha256 ?? "")
    ) {
      throw new Error("private encrypted D1 recovery custody is unverified");
    }
    return Object.freeze({
      primaryDatabaseIdSha256: sha256(Buffer.from(input.primary.databaseId)),
      recoveryDatabaseIdSha256: sha256(Buffer.from(input.recovery.databaseId)),
      plaintextBackupSha256,
      encryptedBackupSha256,
      encryptionKeySha256: sha256(publicKeyBytes),
      decryptionProofSha256: digest({
        releaseId: input.releaseId,
        plaintextBackupSha256,
        encryptedBackupSha256,
        primaryFingerprint,
        encryptionFingerprint,
        restoredSchemaSha256: recoveryAfter.schemaSha256,
      }),
      encryptedCustodyBindingVersionSha256: custody.bindingVersionSha256,
      encryptedCustodyCiphertextSha256: custody.ciphertextSha256,
      encryptedCustodySha256: custody.custodySha256,
      encryptedCustodyDecryptionProofSha256: custody.decryptionProofSha256,
      primarySchemaSha256: input.expectedSchemaSha256,
      recoverySchemaSha256: recoveryAfter.schemaSha256,
      timeTravelBookmarkSha256: digest(timeTravelValue),
      recoveryLeadCount: recoveryAfter.leadCount,
      plaintextRetained: false,
    });
  } finally {
    privateKeyBytes.fill(0);
    passphraseBytes.fill(0);
    await overwriteAndRemove(privateKeyPath).catch(() => undefined);
    await overwriteAndRemove(plaintextPath).catch(() => undefined);
    await overwriteAndRemove(decryptedPath).catch(() => undefined);
    await overwriteAndRemove(encryptedPath).catch(() => undefined);
    await rm(root, { force: true, recursive: true });
  }
}

export function createProductionWranglerAdapter({
  cloudflareClient,
  cloudflareToken,
  environment = process.env,
  infrastructure,
  recoverySnapshotSink,
  resendAdminClient,
  runWrangler = createPinnedWranglerRunner({
    accountId: infrastructure.cloudflare.accountId,
    environment,
    token: cloudflareToken,
  }),
} = {}) {
  if (!cloudflareClient?.request || !resendAdminClient?.request || typeof runWrangler !== "function") {
    throw new Error("production Wrangler adapter dependencies are unavailable");
  }
  const accountId = infrastructure.cloudflare.accountId;
  const zoneId = infrastructure.cloudflare.zoneId;
  let configurationPath = null;
  let materializedRoot = null;

  async function listWorkerVersions(workerName) {
    const response = await request(
      cloudflareClient,
      "GET",
      `/accounts/${accountId}/workers/scripts/${workerName}/versions`,
      { query: { page: "1", per_page: "100" } },
    ).catch((error) => {
      if (error instanceof ProviderRejectedError && error.status === 404) return null;
      throw error;
    });
    if (!response) return null;
    return completeList(response, "Worker versions");
  }

  async function inspectWorkerVersion(expected, exactVersionId = null) {
    if (
      !expected ||
      typeof expected.workerName !== "string" ||
      !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(expected.workerName)
    ) {
      throw new Error("Worker inspection identity is invalid");
    }
    const versions = await listWorkerVersions(expected.workerName);
    if (exactVersionId === null) {
      if (versions === null) return null;
      throw new Error("pre-existing Worker/version blocks the initial production release");
    }
    if (!uuidPattern.test(exactVersionId ?? "")) throw new Error("Worker version ID is invalid");
    if (
      versions === null ||
      versions.length !== 1 ||
      versions[0]?.id !== exactVersionId ||
      versions[0]?.number !== 1 ||
      versions[0]?.metadata?.source !== "wrangler"
    ) {
      throw new Error("Worker upload is not the sole first Wrangler version");
    }
    const detail = await request(
      cloudflareClient,
      "GET",
      `/accounts/${accountId}/workers/scripts/${expected.workerName}/versions/${exactVersionId}`,
    );
    const value = detail.result;
    if (
      value?.id !== exactVersionId ||
      value?.number !== 1 ||
      value?.metadata?.source !== "wrangler" ||
      value?.resources?.script?.etag !== expected.workerModuleSha256 ||
      !digestPattern.test(value?.resources?.script?.etag ?? "") ||
      value?.resources?.script_runtime?.compatibility_date !== expected.compatibilityDate ||
      canonicalJson(value?.resources?.script_runtime?.compatibility_flags) !==
        canonicalJson(expected.compatibilityFlags)
    ) {
      throw new Error("Worker version code or runtime differs from the approved release");
    }
    const bindings = value?.resources?.bindings;
    if (!Array.isArray(bindings)) throw new Error("Worker version bindings are unavailable");
    const bindingMap = new Map();
    for (const binding of bindings) {
      if (typeof binding?.name !== "string" || bindingMap.has(binding.name)) {
        throw new Error("Worker version binding identity is ambiguous");
      }
      bindingMap.set(binding.name, binding);
    }
    const expectedBindingNames = new Set([
      "LEADS_DB",
      ...expectedSecretBindings,
      ...Object.keys(expected.runtimeVariables),
      ...(expected.assetsBindingName === null ? [] : [expected.assetsBindingName]),
    ]);
    if (
      bindingMap.size !== expectedBindingNames.size ||
      [...bindingMap.keys()].some((name) => !expectedBindingNames.has(name))
    ) {
      throw new Error("Worker version contains missing or unexpected bindings");
    }
    const d1Binding = bindingMap.get("LEADS_DB");
    if (
      d1Binding?.type !== "d1" ||
      d1Binding?.database_id !== infrastructure.cloudflare.d1.primary.databaseId ||
      (d1Binding.id !== undefined &&
        d1Binding.id !== infrastructure.cloudflare.d1.primary.databaseId)
    ) {
      throw new Error("Worker version D1 binding differs from the approved target");
    }
    for (const name of expectedSecretBindings) {
      if (bindingMap.get(name)?.type !== "secret_text") {
        throw new Error("Worker version secret binding is missing");
      }
    }
    for (const [name, text] of Object.entries(expected.runtimeVariables)) {
      const binding = bindingMap.get(name);
      if (binding?.type !== "plain_text" || binding.text !== text) {
        throw new Error("Worker version plain variable differs from the approved configuration");
      }
    }
    const assets = bindings.filter((binding) => binding?.type === "assets");
    if (
      (expected.assetsBindingName === null && assets.length !== 0) ||
      (expected.assetsBindingName !== null &&
        (assets.length !== 1 || assets[0].name !== expected.assetsBindingName))
    ) {
      throw new Error("Worker version assets binding differs from the approved configuration");
    }
    return {
      versionId: exactVersionId,
      ...expected,
      stateSha256: digest(value),
    };
  }

  return Object.freeze({
    async verifyProviderState({ infrastructure: receipt, runtimeSecrets }) {
      const runtimeToken = new TextDecoder("utf-8", { fatal: true }).decode(
        runtimeSecrets.RESEND_API_KEY.bytes,
      );
      const runtimeClient = createResendHttpAdapter({ token: runtimeToken });
      const cloudflare = await inspectCloudflareProviderState(cloudflareClient, receipt);
      const resend = await inspectResendProviderState({
        adminClient: resendAdminClient,
        runtimeClient,
        receipt,
      });
      return providerState(receipt, cloudflare, resend);
    },
    async inspectDatabase({ database, migrations }) {
      return inspectD1Database(cloudflareClient, accountId, database, migrations);
    },
    async applyOrderedMigrations({ database, materializedRoot: root }) {
      const config = resolve(root, "wrangler.jsonc");
      await runWrangler(
        [
          "d1",
          "migrations",
          "apply",
          database.databaseId,
          "--remote",
          "--config",
          config,
          "--no-x-provision",
          "--no-x-auto-create",
        ],
        { cwd: root, mutation: true },
      );
    },
    async createEncryptedRecoveryProof(input) {
      return encryptedD1RecoveryProof({
        cloudflareClient,
        environment,
        runWrangler,
        accountId,
        input,
        recoverySnapshotSink,
      });
    },
    inspectWorkerVersion,
    async uploadWorkerVersion({ expected, hydratedConfiguration, materialized, runtimeSecrets }) {
      configurationPath = hydratedConfiguration.path;
      materializedRoot = materialized.root;
      const secretPath = resolve(materialized.root, ".production-secrets.json");
      const values = {};
      let workerUploadAttempted = false;
      for (const binding of expectedSecretBindings) {
        values[binding] = new TextDecoder("utf-8", { fatal: true }).decode(
          runtimeSecrets[binding].bytes,
        );
      }
      const secretBytes = Buffer.from(JSON.stringify(values) + "\n", "utf8");
      try {
        // `--secrets-file` is additive for an existing Worker. The hard
        // absence invariant is therefore checked immediately before any
        // secret file is written or Wrangler mutation is attempted.
        if ((await inspectWorkerVersion({ workerName: expected.workerName })) !== null) {
          throw new Error("pre-existing Worker/version blocks secret-safe first upload");
        }
        await writeFile(secretPath, secretBytes, { flag: "wx", mode: 0o600 });
        // An ambiguous upload is terminal. A retry must use a newly reviewed
        // release ID; it may never adopt a mutable tag left by an uncertain run.
        workerUploadAttempted = true;
        const upload = await runWrangler(
          [
            "versions",
            "upload",
            resolve(materialized.root, "worker/index.js"),
            "--config",
            hydratedConfiguration.path,
            "--no-bundle",
            "--strict",
            "--secrets-file",
            secretPath,
            "--tag",
            expected.tag,
            "--message",
            expected.message,
            "--no-x-provision",
            "--no-x-auto-create",
          ],
          { cwd: materialized.root, mutation: true },
        );
        const uploadedVersionId = parseWranglerUploadedVersionId(upload.stdout);
        return await inspectWorkerVersion(expected, uploadedVersionId);
      } catch (error) {
        if (error && typeof error === "object") {
          Object.defineProperty(error, "workerUploadAttempted", {
            configurable: false,
            enumerable: false,
            value: workerUploadAttempted,
            writable: false,
          });
        }
        throw error;
      } finally {
        secretBytes.fill(0);
        for (const key of Object.keys(values)) values[key] = "";
        await writeFile(secretPath, Buffer.alloc(0), { flag: "w", mode: 0o600 }).catch(() => undefined);
        await rm(secretPath, { force: true });
      }
    },
    async inspectDeployment({ workerName }) {
      const response = await request(
        cloudflareClient,
        "GET",
        `/accounts/${accountId}/workers/scripts/${workerName}/deployments`,
      ).catch((error) => {
        if (error instanceof ProviderRejectedError && error.status === 404) return null;
        throw error;
      });
      return response ? deploymentFromResult(response.result) : null;
    },
    async deployWorkerVersion({ versionId, workerName, message }) {
      const body = {
        strategy: "percentage",
        versions: [{ percentage: 100, version_id: versionId }],
        annotations: { "workers/message": message },
      };
      try {
        await request(
          cloudflareClient,
          "POST",
          `/accounts/${accountId}/workers/scripts/${workerName}/deployments`,
          { body, bodySha256: digest(body), idempotencyKey: digest(body) },
        );
      } catch (error) {
        if (!(error instanceof ProviderTransportAmbiguousError)) throw error;
      }
    },
    async inspectTriggers({ workerName }) {
      const [scheduleResponse, routeResponse] = await Promise.all([
        request(
          cloudflareClient,
          "GET",
          `/accounts/${accountId}/workers/scripts/${workerName}/schedules`,
        ).catch((error) => {
          if (error instanceof ProviderRejectedError && error.status === 404) return null;
          throw error;
        }),
        request(cloudflareClient, "GET", `/zones/${zoneId}/workers/routes`),
      ]);
      const schedules = scheduleResponse ? completeList(scheduleResponse, "Worker schedules") : [];
      const routes = Array.isArray(routeResponse.result)
        ? routeResponse.result.filter((route) => route.script === workerName).map((route) => route.pattern)
        : null;
      if (routes === null) throw new Error("Worker routes are unavailable");
      const crons = schedules.map((item) => item.cron).sort();
      routes.sort();
      return { crons, routes, stateSha256: digest({ crons, routes }) };
    },
    async deployTriggers({ crons, routes, hydratedConfiguration }) {
      if (routes.length !== 0 || canonicalJson(crons) !== canonicalJson(["*/5 * * * *"])) {
        throw new Error("pre-cutover trigger mutation exceeds the allowlist");
      }
      const config = hydratedConfiguration?.path ?? configurationPath;
      const root = materializedRoot;
      if (!config || !root) throw new Error("hydrated trigger configuration is unavailable");
      await runWrangler(
        ["triggers", "deploy", "--config", config, "--no-x-provision", "--no-x-auto-create"],
        { cwd: root, mutation: true },
      );
    },
    async rollbackWorkerDeployment({
      workerName,
      createdVersionId,
      previousDeployment,
      previousTriggers,
    }) {
      if (
        previousDeployment !== null ||
        previousTriggers === null ||
        canonicalJson(previousTriggers.crons) !== canonicalJson([]) ||
        canonicalJson(previousTriggers.routes) !== canonicalJson([]) ||
        (createdVersionId !== null && !uuidPattern.test(createdVersionId ?? ""))
      ) {
        throw new Error("first-release rollback baseline is not authoritatively empty");
      }
      try {
        await request(
          cloudflareClient,
          "DELETE",
          `/accounts/${accountId}/workers/scripts/${workerName}`,
        );
      } catch (error) {
        if (
          !(error instanceof ProviderTransportAmbiguousError) &&
          !(error instanceof ProviderRejectedError)
        ) {
          throw error;
        }
      }
      const remainingVersions = await listWorkerVersions(workerName);
      const [currentDeployment, currentTriggers] = await Promise.all([
        this.inspectDeployment({ workerName }),
        this.inspectTriggers({ workerName }),
      ]);
      if (
        remainingVersions !== null ||
        currentDeployment !== null ||
        canonicalJson(currentTriggers?.crons) !== canonicalJson([]) ||
        canonicalJson(currentTriggers?.routes) !== canonicalJson([])
      ) {
        throw new Error("first-release Worker deletion did not restore the empty baseline");
      }
    },
  });
}

export const productionWranglerAdapterConstants = Object.freeze({
  expectedSecretBindings,
  wranglerVersion,
});
