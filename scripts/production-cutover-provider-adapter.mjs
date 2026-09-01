import { canonicalJson, sha256 } from "./control-contract.mjs";
import {
  productionCandidateRoutes,
  productionCutoverConstants,
  productionPreCutoverRoutes,
  productionFullRoutes,
} from "./production-cutover-adapter.mjs";
import { ProviderTransportAmbiguousError } from "./provider-adapter.mjs";

const accountPattern = /^[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const emailPattern = /^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/;
const routeIdPattern = /^[a-f0-9]{32}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const maximumDocumentBytes = 2 * 1024 * 1024;
const requestTimeoutMilliseconds = 20_000;
const allCutoverRoutes = Object.freeze(
  [...new Set([...productionCandidateRoutes, ...productionFullRoutes])].sort(),
);

function digest(value) {
  return sha256(Buffer.from(canonicalJson(value) + "\n", "utf8"));
}

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

async function providerRequest(client, method, path, options) {
  if (!client || typeof client.request !== "function") {
    throw new Error("cutover Cloudflare client is unavailable");
  }
  return client.request(requestInput(method, path, options));
}

function canonicalInstant(value, label) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error(label + " is invalid");
  return new Date(timestamp).toISOString();
}

function patternPrefix(pattern) {
  return pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
}

function overlaps(left, right) {
  const leftPrefix = patternPrefix(left);
  const rightPrefix = patternPrefix(right);
  return leftPrefix.startsWith(rightPrefix) || rightPrefix.startsWith(leftPrefix);
}

function normalizeRoutes(value) {
  if (!Array.isArray(value) || value.length > 10_000) {
    throw new Error("Cloudflare Worker route inventory is unavailable");
  }
  const routes = value.map((route) => {
    if (
      !routeIdPattern.test(route?.id ?? "") ||
      typeof route?.pattern !== "string" ||
      route.pattern.length < 1 ||
      route.pattern.length > 512 ||
      /[\r\n\0]/.test(route.pattern) ||
      (route.script !== null && route.script !== undefined &&
        (typeof route.script !== "string" || !/^[a-z0-9-]{1,63}$/.test(route.script)))
    ) {
      throw new Error("Cloudflare Worker route entry is invalid");
    }
    return Object.freeze({
      id: route.id,
      pattern: route.pattern,
      script: route.script ?? null,
    });
  });
  if (new Set(routes.map((route) => route.id)).size !== routes.length) {
    throw new Error("Cloudflare Worker route identifiers are duplicated");
  }
  routes.sort((left, right) =>
    `${left.pattern}\0${left.script ?? ""}\0${left.id}`.localeCompare(
      `${right.pattern}\0${right.script ?? ""}\0${right.id}`,
      "en",
    ),
  );
  return Object.freeze(routes);
}

function exactPatterns(value, label) {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string") ||
    canonicalJson(value) !== canonicalJson([...value].sort()) ||
    ![
      canonicalJson(productionPreCutoverRoutes),
      canonicalJson(productionCandidateRoutes),
      canonicalJson(productionFullRoutes),
    ].includes(canonicalJson(value))
  ) {
    throw new Error(label + " differs from the cutover allowlist");
  }
  return value;
}

function relevantRoutes(routes, workerName) {
  for (const route of routes) {
    if (
      route.script !== workerName &&
      allCutoverRoutes.some((pattern) => overlaps(route.pattern, pattern))
    ) {
      throw new Error("another Worker route overlaps the production cutover surface");
    }
  }
  return routes.filter((route) => route.script === workerName);
}

function routeState(routes, workerName) {
  const owned = relevantRoutes(routes, workerName);
  const patterns = owned.map((route) => route.pattern).sort();
  const body = {
    workerName,
    patterns,
    inventoryStateSha256: digest(routes),
  };
  return Object.freeze({ ...body, stateSha256: digest(body) });
}

function exactRouteState(routes, workerName, patterns) {
  const state = routeState(routes, workerName);
  if (canonicalJson(state.patterns) !== canonicalJson(patterns)) {
    throw new Error("authoritative Worker routes differ from the exact expected state");
  }
  return state;
}

function mutationKey(base, action, pattern, routeId = null) {
  return digest({ base, action, pattern, routeId });
}

async function requestWithReconciliation({ action, inspect, mutate, desired }) {
  try {
    await mutate();
  } catch (error) {
    if (!(error instanceof ProviderTransportAmbiguousError)) throw error;
    const reconciled = await inspect();
    if (!desired(reconciled)) throw error;
  }
}

async function responseBytes(response) {
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.byteLength > maximumDocumentBytes) {
    throw new Error("production smoke response exceeds its byte boundary");
  }
  return buffer;
}

async function externalRequest(fetchImpl, url, { redirect = "error" } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMilliseconds);
  try {
    return await fetchImpl(url, {
      headers: {
        accept: "text/html,application/xml,text/plain;q=0.9,*/*;q=0.1",
        "user-agent": "fresh-towels-protected-cutover-smoke/1",
      },
      method: "GET",
      redirect,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

function canonicalFromHtml(html) {
  const tags = html.match(/<link\b[^>]*>/gi) ?? [];
  const matches = [];
  for (const tag of tags) {
    const rel = /\brel\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1] ?? "";
    if (!rel.split(/\s+/).some((value) => value.toLowerCase() === "canonical")) continue;
    const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
    if (href) matches.push(href);
  }
  if (matches.length !== 1) throw new Error("production page canonical is absent or ambiguous");
  return matches[0];
}

function hasNoindex(html) {
  return (html.match(/<meta\b[^>]*>/gi) ?? []).some((tag) => {
    const name = /\bname\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1]?.toLowerCase();
    const content = /\bcontent\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1]?.toLowerCase();
    return name === "robots" && /(?:^|[,\s])noindex(?:$|[,\s])/.test(content ?? "");
  });
}

function stagingReferences(value) {
  return (value.match(/fresh-towels-staging|staging\.freshtowels\.gr/gi) ?? []).length;
}

function normalizeAccessDomain(value) {
  if (typeof value !== "string") return null;
  const withoutScheme = value.replace(/^https?:\/\//i, "").replace(/\/$/, "");
  return withoutScheme;
}

function accessEvent(event, expected) {
  const occurredAt = canonicalInstant(event?.created_at, "Access audit timestamp");
  if (
    event?.action !== "login" ||
    event?.allowed !== true ||
    event?.app_uid !== expected.applicationId ||
    normalizeAccessDomain(event?.app_domain) !== expected.applicationDomain ||
    event?.user_email !== expected.adminIdentity ||
    typeof event?.ray_id !== "string" ||
    !/^[a-f0-9]{16}$/.test(event.ray_id)
  ) {
    return null;
  }
  const eventBody = {
    action: "login",
    allowed: true,
    applicationDomain: expected.applicationDomain,
    applicationId: expected.applicationId,
    identitySha256: expected.adminIdentitySha256,
    occurredAt,
    rayIdSha256: sha256(Buffer.from(event.ray_id, "utf8")),
  };
  return Object.freeze({ ...eventBody, eventSha256: digest(eventBody) });
}

export function createProductionCutoverProviderAdapter({
  accountId,
  adminIdentity,
  cloudflareClient,
  fetchImpl = globalThis.fetch,
  inspectCandidateE2e,
  inspectProviderState,
  inspectWorkerState,
  now = () => new Date(),
  workerName = productionCutoverConstants.expectedWorkerName,
  zoneId,
} = {}) {
  if (
    !accountPattern.test(accountId ?? "") ||
    !accountPattern.test(zoneId ?? "") ||
    !emailPattern.test(adminIdentity ?? "") ||
    !cloudflareClient?.request ||
    typeof fetchImpl !== "function" ||
    typeof inspectCandidateE2e !== "function" ||
    typeof inspectProviderState !== "function" ||
    typeof inspectWorkerState !== "function" ||
    typeof now !== "function" ||
    workerName !== productionCutoverConstants.expectedWorkerName
  ) {
    throw new Error("production cutover provider dependencies are unavailable");
  }
  const adminIdentitySha256 = sha256(Buffer.from(adminIdentity, "utf8"));

  async function listRoutes() {
    const response = await providerRequest(
      cloudflareClient,
      "GET",
      `/zones/${zoneId}/workers/routes`,
    );
    return normalizeRoutes(response.result);
  }

  async function reconcileRoutesTo(patterns, idempotencyKey) {
    exactPatterns(patterns, "desired Worker routes");
    let routes = await listRoutes();
    relevantRoutes(routes, workerName);
    for (const route of routes.filter(
      (item) => item.script === workerName && !patterns.includes(item.pattern),
    )) {
      await requestWithReconciliation({
        action: "delete Worker route",
        inspect: listRoutes,
        mutate: () =>
          providerRequest(
            cloudflareClient,
            "DELETE",
            `/zones/${zoneId}/workers/routes/${route.id}`,
            {
              idempotencyKey: mutationKey(
                idempotencyKey,
                "delete",
                route.pattern,
                route.id,
              ),
            },
          ),
        desired: (current) => !current.some((item) => item.id === route.id),
      });
      routes = await listRoutes();
      relevantRoutes(routes, workerName);
    }
    for (const pattern of patterns) {
      routes = await listRoutes();
      relevantRoutes(routes, workerName);
      const exact = routes.filter(
        (route) => route.pattern === pattern && route.script === workerName,
      );
      if (exact.length === 1) continue;
      if (exact.length !== 0) throw new Error("Worker route state is duplicated");
      const body = { pattern, script: workerName };
      await requestWithReconciliation({
        action: "create Worker route",
        inspect: listRoutes,
        mutate: () =>
          providerRequest(cloudflareClient, "POST", `/zones/${zoneId}/workers/routes`, {
            body,
            bodySha256: digest(body),
            idempotencyKey: mutationKey(idempotencyKey, "create", pattern),
          }),
        desired: (current) =>
          current.filter(
            (route) => route.pattern === pattern && route.script === workerName,
          ).length === 1,
      });
    }
    return exactRouteState(await listRoutes(), workerName, patterns);
  }

  return Object.freeze({
    async inspectProviderState(input) {
      return inspectProviderState(input);
    },
    async inspectWorkerState(input) {
      return inspectWorkerState(input);
    },
    async inspectCandidateE2e(input) {
      return inspectCandidateE2e(input);
    },
    async inspectRoutes({ workerName: requestedWorkerName }) {
      if (requestedWorkerName !== workerName) throw new Error("Worker route identity changed");
      return routeState(await listRoutes(), workerName);
    },
    async setExactRoutes({
      desiredPatterns,
      expectedPreviousPatterns,
      idempotencyKey,
      workerName: requestedWorkerName,
    }) {
      if (
        requestedWorkerName !== workerName ||
        !digestPattern.test(idempotencyKey ?? "")
      ) {
        throw new Error("Worker route mutation identity changed");
      }
      exactPatterns(expectedPreviousPatterns, "previous Worker routes");
      exactPatterns(desiredPatterns, "desired Worker routes");
      const before = await listRoutes();
      exactRouteState(before, workerName, expectedPreviousPatterns);
      try {
        await reconcileRoutesTo(desiredPatterns, idempotencyKey);
      } catch (error) {
        try {
          await reconcileRoutesTo(
            expectedPreviousPatterns,
            digest({ idempotencyKey, action: "restore-previous-routes" }),
          );
        } catch {
          throw new Error("Worker route mutation failed and rollback is ambiguous");
        }
        throw error;
      }
    },
    async inspectAccessAudit({
      after,
      adminIdentitySha256: requestedIdentitySha256,
      applicationDomain,
      applicationId,
    }) {
      if (
        !uuidPattern.test(applicationId ?? "") ||
        applicationDomain !== productionCutoverConstants.expectedAccessDomain ||
        requestedIdentitySha256 !== adminIdentitySha256
      ) {
        throw new Error("Access audit identity changed");
      }
      const since = canonicalInstant(after, "Access audit lower bound");
      const until = now().toISOString();
      if (Date.parse(until) < Date.parse(since)) {
        throw new Error("Access audit window is invalid");
      }
      const response = await providerRequest(
        cloudflareClient,
        "GET",
        `/accounts/${accountId}/access/logs/access_requests`,
        {
          query: {
            direction: "desc",
            email: adminIdentity,
            emailOp: "eq",
            limit: "100",
            since,
            until,
          },
        },
      );
      if (!Array.isArray(response.result) || response.result.length > 100) {
        throw new Error("Access audit response exceeds its boundary");
      }
      const matches = response.result
        .map((event) =>
          accessEvent(event, {
            adminIdentity,
            adminIdentitySha256,
            applicationDomain,
            applicationId,
          }),
        )
        .filter(Boolean)
        .filter(
          (event) =>
            Date.parse(event.occurredAt) >= Date.parse(since) &&
            Date.parse(event.occurredAt) <= Date.parse(until),
        )
        .sort((left, right) =>
          right.occurredAt.localeCompare(left.occurredAt) ||
          left.eventSha256.localeCompare(right.eventSha256),
        );
      if (matches.length < 1) throw new Error("approved Access owner login is absent");
      const event = matches[0];
      const body = {
        applicationId,
        applicationDomain,
        identitySha256: adminIdentitySha256,
        decision: "allow",
        eventType: "login",
        occurredAt: event.occurredAt,
        eventSha256: event.eventSha256,
      };
      return Object.freeze({ ...body, stateSha256: digest(body) });
    },
    async inspectExternalSmoke({ criticalRoutes, origin, wwwOrigin }) {
      if (
        origin !== "https://freshtowels.gr" ||
        wwwOrigin !== "https://www.freshtowels.gr" ||
        canonicalJson(criticalRoutes) !==
          canonicalJson(productionCutoverConstants.criticalRoutes)
      ) {
        throw new Error("production smoke target changed");
      }
      const www = await externalRequest(fetchImpl, `${wwwOrigin}/`, {
        redirect: "manual",
      });
      const wwwRedirectLocation = www.headers.get("location");
      const pages = [];
      let productionNoindexCount = 0;
      let stagingReferenceCount = 0;
      for (const path of criticalRoutes) {
        const response = await externalRequest(fetchImpl, `${origin}${path}`);
        const bytes = await responseBytes(response);
        const html = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (hasNoindex(html)) productionNoindexCount += 1;
        stagingReferenceCount += stagingReferences(html);
        pages.push({
          path,
          status: response.status,
          canonical: canonicalFromHtml(html),
        });
      }
      const robots = await externalRequest(fetchImpl, `${origin}/robots.txt`);
      const robotsText = new TextDecoder("utf-8", { fatal: true }).decode(
        await responseBytes(robots),
      );
      const sitemap = await externalRequest(fetchImpl, `${origin}/sitemap.xml`);
      const sitemapText = new TextDecoder("utf-8", { fatal: true }).decode(
        await responseBytes(sitemap),
      );
      stagingReferenceCount += stagingReferences(robotsText) + stagingReferences(sitemapText);
      const body = {
        origin,
        wwwOrigin,
        httpsValid: pages.every((page) => page.status >= 100),
        wwwRedirectStatus: www.status,
        wwwRedirectLocation,
        robotsStatus: robots.status,
        robotsIndexable:
          !/^\s*Disallow:\s*\/\s*$/im.test(robotsText) &&
          !/\bnoindex\b/i.test(robotsText),
        sitemapStatus: sitemap.status,
        productionNoindexCount,
        stagingReferenceCount,
        criticalRoutes: pages,
      };
      return Object.freeze({ ...body, stateSha256: digest(body) });
    },
  });
}

export const productionCutoverProviderAdapterConstants = Object.freeze({
  allCutoverRoutes,
  maximumDocumentBytes,
  requestTimeoutMilliseconds,
});
