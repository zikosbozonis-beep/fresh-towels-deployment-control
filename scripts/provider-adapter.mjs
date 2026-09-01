import { canonicalJson, sha256 } from "./control-contract.mjs";
import { providerActionContracts } from "./provider-plan.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const requestIdPattern = /^[A-Za-z0-9._:-]{1,128}$/;
const safeNamePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const maximumResponseBytes = 1024 * 1024;
const maximumRequestBytes = 16 * 1024 * 1024;
const safeProviderErrorCodes = Object.freeze({
  resend: new Set(["invalid_api_key", "restricted_api_key"]),
});

const providerConfiguration = Object.freeze({
  cloudflare: Object.freeze({
    origin: "https://api.cloudflare.com",
    prefix: "/client/v4",
    endpoints: Object.freeze([
      { pattern: /^\/accounts\/[a-f0-9]{32}$/, methods: ["GET"] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/subdomain$/, methods: ["GET"] },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/d1\/database$/,
        methods: ["GET", "POST"], list: true,
        pagination: "cloudflare-d1",
        queryShapes: [["name", "page", "per_page"]],
        requiredQueryValues: Object.freeze({ page: "1", per_page: "10000" }),
      },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/d1\/database\/[a-f0-9-]{36}$/, methods: ["GET", "DELETE"] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/d1\/database\/[a-f0-9-]{36}\/query$/, methods: ["POST"] },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/workers$/,
        methods: ["POST"],
        validateBody({ body, bodyBytes }) {
          if (bodyBytes !== undefined) {
            throw new Error("Cloudflare disposable Worker body is invalid");
          }
          exactPlainObject(
            body,
            ["name", "subdomain", "tags"],
            "Cloudflare disposable Worker body",
          );
          exactPlainObject(
            body.subdomain,
            ["enabled", "previews_enabled"],
            "Cloudflare disposable Worker subdomain",
          );
          if (
            !/^ft-provider-canary-[a-f0-9]{12}-[a-f0-9]{7}$/.test(body.name) ||
            body.subdomain.enabled !== false ||
            body.subdomain.previews_enabled !== false ||
            !Array.isArray(body.tags) ||
            body.tags.length !== 1 ||
            body.tags[0] !== "fresh-towels-provider-canary"
          ) {
            throw new Error("Cloudflare disposable Worker body is outside the exact allowlist");
          }
        },
      },
      {
        pattern:
          /^\/accounts\/[a-f0-9]{32}\/workers\/workers\/(?:[a-f0-9]{32}|ft-provider-canary-[a-f0-9]{12}-[a-f0-9]{7})$/,
        methods: ["GET", "DELETE"],
      },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/[a-z0-9-]+$/, methods: ["DELETE"] },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/[a-z0-9-]+\/versions$/,
        methods: ["GET", "POST"],
        list: true,
        pagination: "cloudflare-worker-versions",
        queryShapes: [["page", "per_page"]],
        requiredQueryValues: Object.freeze({ page: "1", per_page: "100" }),
      },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/[a-z0-9-]+\/versions\/[a-f0-9-]{36}$/, methods: ["GET"] },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/[a-z0-9-]+\/deployments$/,
        methods: ["GET", "POST"], list: true, queryShapes: [[], ["page", "per_page"]],
      },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/[a-z0-9-]+\/schedules$/,
        methods: ["GET"], list: true, queryShapes: [[], ["page", "per_page"]],
      },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/workers\/scripts\/[a-z0-9-]+\/settings$/, methods: ["GET"] },
      { pattern: /^\/zones$/, methods: ["GET", "POST"], list: true, queryShapes: [["account.id", "match", "name", "page", "per_page"]] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/access\/organizations$/, methods: ["GET", "POST"] },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/access\/identity_providers$/,
        methods: ["GET", "POST"], list: true, queryShapes: [["page", "per_page"]],
      },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/access\/identity_providers\/[a-f0-9-]{36}$/, methods: ["GET"] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/access\/apps$/, methods: ["GET", "POST"], list: true, queryShapes: [["domain", "exact", "name", "page", "per_page"]] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/access\/apps\/[a-f0-9-]{36}$/, methods: ["GET", "PUT"] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/access\/apps\/[a-f0-9-]{36}\/policies$/, methods: ["GET", "POST"], list: true, queryShapes: [["page", "per_page"]] },
      { pattern: /^\/accounts\/[a-f0-9]{32}\/access\/apps\/[a-f0-9-]{36}\/policies\/[a-f0-9-]{36}$/, methods: ["PUT"] },
      { pattern: /^\/zones\/[a-f0-9]{32}\/dns_records$/, methods: ["GET", "POST"], list: true, queryShapes: [["page", "per_page"], ["content.exact", "match", "name.exact", "page", "per_page", "type"], ["match", "name.exact", "page", "per_page", "type"]] },
      { pattern: /^\/zones\/[a-f0-9]{32}\/dns_records\/[a-f0-9]{32}$/, methods: ["GET", "PUT"] },
      {
        pattern: /^\/zones\/[a-f0-9]{32}\/settings\/(?:ssl|always_use_https|min_tls_version)$/,
        methods: ["GET", "PATCH"],
        validateBody({ method, path, body, bodyBytes }) {
          if (method === "GET") return;
          if (bodyBytes !== undefined) throw new Error("Cloudflare zone setting body is invalid");
          exactPlainObject(body, ["value"], "Cloudflare zone setting body");
          const setting = path.split("/").at(-1);
          const expected = { ssl: "strict", always_use_https: "on", min_tls_version: "1.2" };
          if (body.value !== expected[setting]) {
            throw new Error("Cloudflare zone setting value is outside the exact allowlist");
          }
        },
      },
      {
        pattern: /^\/zones\/[a-f0-9]{32}\/workers\/routes$/,
        methods: ["GET", "POST"], queryShapes: [[]],
      },
      {
        pattern: /^\/zones\/[a-f0-9]{32}\/workers\/routes\/[a-f0-9]{32}$/,
        methods: ["GET", "PUT", "DELETE"],
      },
      {
        pattern: /^\/accounts\/[a-f0-9]{32}\/access\/logs\/access_requests$/,
        methods: ["GET"],
        queryShapes: [["direction", "email", "emailOp", "limit", "since", "until"]],
        requiredQueryValues: Object.freeze({
          direction: "desc",
          emailOp: "eq",
          limit: "100",
        }),
      },
      { pattern: /^\/zones\/[a-f0-9]{32}$/, methods: ["GET"] },
    ]),
  }),
  resend: Object.freeze({
    origin: "https://api.resend.com",
    prefix: "",
    endpoints: Object.freeze([
      { pattern: /^\/domains$/, methods: ["GET"], list: true, queryShapes: [[], ["limit"]] },
      { pattern: /^\/domains\/[a-z0-9_-]+$/, methods: ["GET"] },
      { pattern: /^\/domains\/[a-z0-9_-]+\/verify$/, methods: ["POST"] },
      { pattern: /^\/webhooks$/, methods: ["GET", "POST"], list: true, queryShapes: [[], ["limit"]] },
      { pattern: /^\/webhooks\/[a-z0-9_-]+$/, methods: ["GET", "PATCH", "DELETE"] },
      { pattern: /^\/api-keys$/, methods: ["GET", "POST"], list: true, queryShapes: [[], ["limit"]] },
      { pattern: /^\/api-keys\/[a-z0-9_-]+$/, methods: ["DELETE"] },
      { pattern: /^\/emails$/, methods: ["POST"] },
      { pattern: /^\/emails\/[a-z0-9_-]+$/, methods: ["GET"] },
    ]),
  }),
});

function exactPlainObject(value, keys, label) {
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

function exactQuery(input, endpoint, provider, method) {
  if (input === undefined || input === null) {
    if (method === "GET" && endpoint.requiredQueryValues) {
      throw new Error("Provider query does not prove the required page boundary");
    }
    return "";
  }
  if (!endpoint.queryShapes) throw new Error("Provider query is outside the exact allowlist");
  exactPlainObject(input, Object.keys(input), "provider query");
  const keys = Object.keys(input).sort();
  const allowed = endpoint.queryShapes.some(
    (shape) => JSON.stringify([...shape].sort()) === JSON.stringify(keys),
  );
  if (!allowed) throw new Error("Provider query is outside the exact allowlist");
  if (
    endpoint.requiredQueryValues &&
    Object.entries(endpoint.requiredQueryValues).some(([key, value]) => input[key] !== value)
  ) {
    throw new Error("Provider query does not prove the required page boundary");
  }
  const parameters = new URLSearchParams();
  for (const key of keys) {
    const value = input[key];
    if (typeof value !== "string" || !value || /[\r\n\0]/.test(value)) {
      throw new Error("Provider query is outside the exact allowlist");
    }
    if (["page", "per_page", "limit"].includes(key) && !/^[1-9][0-9]{0,4}$/.test(value)) {
      throw new Error("Provider query is outside the exact allowlist");
    }
    if (key === "page" && value !== "1") throw new Error("Provider query must start at page one");
    if (key === "match" && value !== "all") throw new Error("Provider query match is unsafe");
    if (key === "exact" && value !== "true") throw new Error("Provider query exact flag is unsafe");
    if (provider === "resend" && key === "limit" && Number(value) > 100) {
      throw new Error("Provider query exceeds the Resend page boundary");
    }
    parameters.set(key, value);
  }
  const value = parameters.toString();
  return value ? `?${value}` : "";
}

function normalizedPagination(provider, endpoint, data) {
  if (!endpoint.list) return Object.freeze({ complete: true });
  if (provider === "resend") {
    return Object.freeze({
      complete:
        data !== null &&
        typeof data === "object" &&
        !Array.isArray(data) &&
        data.object === "list" &&
        data.has_more === false &&
        Array.isArray(data.data),
    });
  }
  const info = data?.result_info;
  const result = data?.result;
  const nestedLists = [result?.items, result?.deployments, result?.schedules].filter(Array.isArray);
  if (nestedLists.length > 1) return Object.freeze({ complete: false });
  const items = Array.isArray(result) ? result : nestedLists[0];
  if (
    info === undefined &&
    !Array.isArray(result) &&
    nestedLists.length === 1 &&
    (Array.isArray(result.deployments) || Array.isArray(result.schedules))
  ) {
    return Object.freeze({ complete: items.length <= 1000 });
  }
  if (endpoint.pagination === "cloudflare-d1") {
    return Object.freeze({
      complete:
        info !== null &&
        typeof info === "object" &&
        !Array.isArray(info) &&
        info.page === 1 &&
        info.per_page === 10_000 &&
        Number.isSafeInteger(info.count) &&
        info.count >= 0 &&
        Number.isSafeInteger(info.total_count) &&
        info.total_count >= info.count &&
        Array.isArray(items) &&
        info.count === items.length &&
        info.count < info.per_page,
    });
  }
  if (endpoint.pagination === "cloudflare-worker-versions") {
    if (info !== null && info !== undefined) {
      return Object.freeze({
        complete:
          typeof info === "object" &&
          !Array.isArray(info) &&
          info.page === 1 &&
          info.per_page === 100 &&
          Number.isSafeInteger(info.count) &&
          info.count >= 0 &&
          Number.isSafeInteger(info.total_count) &&
          info.total_count === info.count &&
          (!Object.hasOwn(info, "total_pages") || info.total_pages === 1) &&
          Array.isArray(result?.items) &&
          info.count === result.items.length &&
          info.count < info.per_page,
      });
    }
    return Object.freeze({
      complete:
        result !== null &&
        typeof result === "object" &&
        !Array.isArray(result) &&
        Array.isArray(result.items) &&
        result.items.length < 100,
    });
  }
  return Object.freeze({
    complete:
      info !== null &&
      typeof info === "object" &&
      !Array.isArray(info) &&
      info.page === 1 &&
      info.total_pages === 1 &&
      Number.isSafeInteger(info.count) &&
      Array.isArray(items) &&
      info.count === items.length,
  });
}

function safeRequestId(value) {
  return typeof value === "string" && requestIdPattern.test(value) ? value : null;
}

function providerRequestId(headers) {
  for (const name of ["cf-ray", "x-request-id", "request-id"]) {
    const value = safeRequestId(headers.get(name));
    if (value) return value;
  }
  return null;
}

function safeProviderErrorCode(provider, data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) return null;
  const identifiers = [data.name, data.code].filter((value) => typeof value === "string");
  if (identifiers.length < 1 || new Set(identifiers).size !== 1) return null;
  const [value] = identifiers;
  return safeProviderErrorCodes[provider]?.has(value) ? value : null;
}

function requestBody(input) {
  if (input.body === undefined && input.bodyBytes === undefined) {
    return { body: undefined, contentType: undefined };
  }
  if (input.body !== undefined && input.bodyBytes !== undefined) {
    throw new Error("Provider request cannot contain two body representations");
  }
  if (input.bodyBytes !== undefined) {
    if (
      !(input.bodyBytes instanceof Uint8Array) ||
      input.bodyBytes.byteLength < 1 ||
      input.bodyBytes.byteLength > maximumRequestBytes ||
      typeof input.contentType !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-\/;= ]{0,127}$/.test(input.contentType) ||
      !digestPattern.test(input.bodySha256 ?? "") ||
      sha256(input.bodyBytes) !== input.bodySha256
    ) {
      throw new Error("Provider binary request body is not digest-bound");
    }
    return { body: input.bodyBytes, contentType: input.contentType };
  }
  const serialized = canonicalJson(input.body) + "\n";
  const bytes = Buffer.from(serialized, "utf8");
  if (bytes.byteLength > maximumRequestBytes) throw new Error("Provider JSON request is too large");
  if (input.bodySha256 !== undefined && input.bodySha256 !== sha256(bytes)) {
    throw new Error("Provider JSON request body digest changed");
  }
  return { body: bytes, contentType: "application/json" };
}

export class ProviderTransportAmbiguousError extends Error {
  constructor(code, { providerRequestId: id = null } = {}) {
    super("Provider transport result is ambiguous: " + code);
    this.name = "ProviderTransportAmbiguousError";
    this.code = code;
    this.providerRequestId = safeRequestId(id);
  }
}

export class ProviderRejectedError extends Error {
  constructor(status, { providerRequestId: id = null, providerErrorCode = null } = {}) {
    super("Provider rejected the exact operation with HTTP " + status);
    this.name = "ProviderRejectedError";
    this.status = status;
    this.providerRequestId = safeRequestId(id);
    this.providerErrorCode =
      typeof providerErrorCode === "string" &&
      [...Object.values(safeProviderErrorCodes)].some((codes) => codes.has(providerErrorCode))
        ? providerErrorCode
        : null;
  }
}

export function createProviderHttpClient({
  provider,
  token,
  fetchImpl = globalThis.fetch,
  timeoutMilliseconds = 15_000,
}) {
  const configuration = providerConfiguration[provider];
  if (
    !configuration ||
    typeof token !== "string" ||
    token.length < 20 ||
    token.length > 2048 ||
    /[\r\n\0]/.test(token) ||
    typeof fetchImpl !== "function" ||
    !Number.isSafeInteger(timeoutMilliseconds) ||
    timeoutMilliseconds < 1000 ||
    timeoutMilliseconds > 60_000
  ) {
    throw new Error("Provider HTTP client configuration is invalid");
  }

  return Object.freeze({
    provider,
    async request(input) {
      exactPlainObject(
        input,
        [
          "method",
          "path",
          "body",
          "bodyBytes",
          "bodySha256",
          "contentType",
          "idempotencyKey",
          "query",
        ],
        "provider HTTP request",
      );
      if (
        !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(input.method) ||
        typeof input.path !== "string" ||
        !configuration.endpoints.some((candidate) => candidate.pattern.test(input.path)) ||
        input.path.includes("?") ||
        (input.idempotencyKey !== null && !digestPattern.test(input.idempotencyKey ?? ""))
      ) {
        throw new Error("Provider HTTP request is outside the exact allowlist");
      }
      const endpoint = configuration.endpoints.find((candidate) =>
        candidate.pattern.test(input.path),
      );
      if (!endpoint.methods.includes(input.method)) {
        throw new Error("Provider HTTP method is outside the exact allowlist");
      }
      endpoint.validateBody?.(input);
      if (
        ["GET", "DELETE"].includes(input.method) &&
        (input.body !== undefined || input.bodyBytes !== undefined)
      ) {
        throw new Error("Provider read/delete request cannot carry a body");
      }
      if (input.query !== undefined && input.query !== null && input.method !== "GET") {
        throw new Error("Provider query is outside the exact allowlist");
      }
      const query = exactQuery(input.query, endpoint, provider, input.method);
      const prepared = requestBody(input);
      const headers = new Headers({
        Accept: "application/json",
        Authorization: "Bearer " + token,
        "User-Agent": "fresh-towels-deployment-control/1",
      });
      if (prepared.contentType) headers.set("Content-Type", prepared.contentType);
      if (input.idempotencyKey) headers.set("Idempotency-Key", input.idempotencyKey);
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), timeoutMilliseconds);
      let response;
      try {
        response = await fetchImpl(configuration.origin + configuration.prefix + input.path + query, {
          method: input.method,
          headers,
          body: prepared.body,
          redirect: "error",
          signal: abort.signal,
        });
      } catch {
        throw new ProviderTransportAmbiguousError("network-or-timeout");
      } finally {
        clearTimeout(timer);
      }
      const id = providerRequestId(response.headers);
      let bytes;
      try {
        bytes = new Uint8Array(await response.arrayBuffer());
      } catch {
        throw new ProviderTransportAmbiguousError("response-read", { providerRequestId: id });
      }
      if (bytes.byteLength > maximumResponseBytes) {
        throw new ProviderTransportAmbiguousError("response-boundary", { providerRequestId: id });
      }
      let data = null;
      if (bytes.byteLength > 0) {
        try {
          data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        } catch {
          if (response.ok) {
            throw new ProviderTransportAmbiguousError("invalid-success-envelope", {
              providerRequestId: id,
            });
          }
        }
      }
      if (
        response.status >= 500 ||
        [408, 409, 425, 429].includes(response.status)
      ) {
        throw new ProviderTransportAmbiguousError("http-" + response.status, {
          providerRequestId: id,
        });
      }
      if (!response.ok) {
        throw new ProviderRejectedError(response.status, {
          providerRequestId: id,
          providerErrorCode: safeProviderErrorCode(provider, data),
        });
      }
      if (
        provider === "cloudflare" &&
        (data === null || typeof data !== "object" || Array.isArray(data) || data.success !== true)
      ) {
        throw new ProviderTransportAmbiguousError("cloudflare-success-envelope", {
          providerRequestId: id,
        });
      }
      return Object.freeze({
        provider,
        providerRequestId: id,
        status: response.status,
        result: provider === "cloudflare" ? data.result : data,
        pagination: normalizedPagination(provider, endpoint, data),
        responseSha256: sha256(bytes),
      });
    },
  });
}

export function createCloudflareHttpAdapter(options) {
  return createProviderHttpClient({ ...options, provider: "cloudflare" });
}

export function createResendHttpAdapter(options) {
  return createProviderHttpClient({ ...options, provider: "resend" });
}

function validateInspection(value, operation) {
  exactPlainObject(value, ["state", "stateSha256", "providerRequestId"], "provider inspection");
  if (
    !["desired", "absent", "drifted"].includes(value.state) ||
    !digestPattern.test(value.stateSha256) ||
    (value.state === "desired" && value.stateSha256 !== operation.desiredStateSha256) ||
    (value.providerRequestId !== null && !safeRequestId(value.providerRequestId))
  ) {
    throw new Error("provider inspection is malformed");
  }
  return value;
}

function validateMutation(value) {
  exactPlainObject(value, ["status", "result", "providerRequestId"], "provider mutation result");
  if (
    value.status !== "accepted" ||
    !["created", "updated", "deleted"].includes(value.result) ||
    (value.providerRequestId !== null && !safeRequestId(value.providerRequestId))
  ) {
    throw new Error("provider mutation result is malformed");
  }
  return value;
}

function receiptBody({
  environment,
  operation,
  release,
  preStateSha256,
  postStateSha256,
  result,
  id,
  completedAt,
}) {
  const body = {
    schema: "deployment-control/provider-operation-receipt/v1",
    environment,
    operation: operation.operationId,
    requestId: release.requestId,
    releaseId: release.releaseId,
    sourceCommitSha: release.applicationCommitSha,
    controllerCommitSha: release.controllerCommitSha,
    artifactSha256: release.artifactSha256,
    plaintextSha256: release.plaintextSha256,
    uploadArtifactSha256: release.uploadArtifactSha256,
    evidenceSha256: release.evidenceSha256,
    provider: operation.provider,
    action: operation.action,
    resourceKind: operation.resource.kind,
    resourceName: operation.resource.name,
    resourceIdentitySha256: operation.resource.identitySha256,
    preStateSha256,
    postStateSha256,
    result,
    providerRequestId: safeRequestId(id),
    completedAt,
  };
  const receiptSha256 = sha256(Buffer.from(canonicalJson(body) + "\n", "utf8"));
  return Object.freeze({ ...body, receiptSha256 });
}

export class AmbiguousProviderResultError extends Error {
  constructor(receipt) {
    super("Provider operation remains ambiguous after authoritative reconciliation");
    this.name = "AmbiguousProviderResultError";
    this.receipt = receipt;
  }
}

function completedAt(now) {
  const value = now().toISOString();
  if (new Date(value).toISOString() !== value) throw new Error("receipt time is not canonical UTC");
  return value;
}

export async function executeReconciledProviderOperation({
  environment = "production",
  operation,
  release,
  adapter,
  now = () => new Date(),
}) {
  if (
    !["canary", "production"].includes(environment) ||
    !adapter ||
    typeof adapter.inspect !== "function" ||
    (operation.mutation && typeof adapter.mutate !== "function")
  ) {
    throw new Error("Provider state adapter is incomplete");
  }
  let before;
  try {
    before = validateInspection(await adapter.inspect(operation), operation);
  } catch (error) {
    if (error instanceof ProviderRejectedError) throw error;
    throw new AmbiguousProviderResultError(
      receiptBody({
        environment,
        operation,
        release,
        preStateSha256: sha256(Buffer.from("unavailable")),
        postStateSha256: sha256(Buffer.from("unavailable")),
        result: "ambiguous",
        id: error.providerRequestId,
        completedAt: completedAt(now),
      }),
    );
  }
  if (before.state === "desired") {
    return receiptBody({
      environment,
      operation,
      release,
      preStateSha256: before.stateSha256,
      postStateSha256: before.stateSha256,
      result: operation.mutation ? "unchanged" : "verified",
      id: before.providerRequestId,
      completedAt: completedAt(now),
    });
  }
  if (!operation.mutation) {
    throw new ProviderRejectedError(412, { providerRequestId: before.providerRequestId });
  }

  let mutation;
  let ambiguousId = null;
  try {
    mutation = validateMutation(await adapter.mutate(operation));
  } catch (error) {
    if (error instanceof ProviderRejectedError) throw error;
    ambiguousId = error.providerRequestId ?? null;
  }

  let after;
  try {
    after = validateInspection(await adapter.inspect(operation), operation);
  } catch (error) {
    throw new AmbiguousProviderResultError(
      receiptBody({
        environment,
        operation,
        release,
        preStateSha256: before.stateSha256,
        postStateSha256: sha256(Buffer.from("unavailable")),
        result: "ambiguous",
        id: error.providerRequestId ?? ambiguousId ?? mutation?.providerRequestId,
        completedAt: completedAt(now),
      }),
    );
  }
  if (after.state !== "desired") {
    throw new AmbiguousProviderResultError(
      receiptBody({
        environment,
        operation,
        release,
        preStateSha256: before.stateSha256,
        postStateSha256: after.stateSha256,
        result: "ambiguous",
        id: after.providerRequestId ?? ambiguousId ?? mutation?.providerRequestId,
        completedAt: completedAt(now),
      }),
    );
  }
  return receiptBody({
    environment,
    operation,
    release,
    preStateSha256: before.stateSha256,
    postStateSha256: after.stateSha256,
    result: mutation?.result ?? "verified",
    id: after.providerRequestId ?? ambiguousId ?? mutation?.providerRequestId,
    completedAt: completedAt(now),
  });
}

export function validateProviderReceipt(receipt) {
  exactPlainObject(
    receipt,
    [
      "schema",
      "environment",
      "operation",
      "requestId",
      "releaseId",
      "sourceCommitSha",
      "controllerCommitSha",
      "artifactSha256",
      "plaintextSha256",
      "uploadArtifactSha256",
      "evidenceSha256",
      "provider",
      "action",
      "resourceKind",
      "resourceName",
      "resourceIdentitySha256",
      "preStateSha256",
      "postStateSha256",
      "result",
      "providerRequestId",
      "completedAt",
      "receiptSha256",
    ],
    "provider receipt",
  );
  const { receiptSha256, ...body } = receipt;
  const actionContract = providerActionContracts[receipt.action];
  const completedTimestamp = Date.parse(receipt.completedAt);
  if (
    receipt.schema !== "deployment-control/provider-operation-receipt/v1" ||
    !["canary", "production"].includes(receipt.environment) ||
    !digestPattern.test(receipt.operation) ||
    !uuidPattern.test(receipt.requestId) ||
    !commitPattern.test(receipt.sourceCommitSha) ||
    !commitPattern.test(receipt.controllerCommitSha) ||
    !actionContract ||
    receipt.provider !== actionContract.provider ||
    receipt.resourceKind !== actionContract.resourceKind ||
    !safeNamePattern.test(receipt.resourceName) ||
    receipt.resourceName.includes("@") ||
    (receipt.providerRequestId !== null && !safeRequestId(receipt.providerRequestId)) ||
    !Number.isFinite(completedTimestamp) ||
    new Date(completedTimestamp).toISOString() !== receipt.completedAt ||
    !["verified", "created", "updated", "deleted", "unchanged", "ambiguous"].includes(
      receipt.result,
    ) ||
    [
      receipt.releaseId,
      receipt.artifactSha256,
      receipt.plaintextSha256,
      receipt.uploadArtifactSha256,
      receipt.evidenceSha256,
      receipt.resourceIdentitySha256,
      receipt.preStateSha256,
      receipt.postStateSha256,
      receiptSha256,
    ].some((value) => !digestPattern.test(value)) ||
    sha256(Buffer.from(canonicalJson(body) + "\n", "utf8")) !== receiptSha256
  ) {
    throw new Error("provider receipt binding is invalid");
  }
  return true;
}
