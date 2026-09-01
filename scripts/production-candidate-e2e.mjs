import { createHash } from "node:crypto";

import { canonicalJson } from "./control-contract.mjs";

const commitPattern = /^[a-f0-9]{40}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const zonePattern = /^[a-f0-9]{32}$/;
const leadIdPattern = /^lead_[a-f0-9]{32}$/;
const outboxIdPattern = /^mail_[a-f0-9]{32}$/;
const routeIdPattern = /^[a-f0-9]{32}$/;
const safeProviderIdPattern = /^[A-Za-z0-9_-]{1,256}$/;
const expectedWorkerName = "fresh-towels-production";
const expectedOrigin = "https://freshtowels.gr";
const candidateRoutePatterns = Object.freeze([
  "freshtowels.gr/api/internal/*",
  "freshtowels.gr/api/leads",
  "freshtowels.gr/api/webhooks/resend",
  "freshtowels.gr/internal/leads",
  "freshtowels.gr/internal/leads/*",
]);
const preCutoverRoutePatterns = Object.freeze([
  "freshtowels.gr/api/internal/*",
  "freshtowels.gr/internal/leads",
  "freshtowels.gr/internal/leads/*",
]);
const publicCandidateRoutePatterns = Object.freeze([
  "freshtowels.gr/api/leads",
  "freshtowels.gr/api/webhooks/resend",
]);
const leadStatuses = Object.freeze([
  "new",
  "in_progress",
  "answered",
  "archived",
]);
const outboxStatuses = Object.freeze([
  "pending",
  "processing",
  "sent",
  "failed",
  "dead",
]);
const deliveryStatuses = Object.freeze([
  "pending",
  "sent",
  "delayed",
  "delivered",
  "failed",
  "bounced",
  "suppressed",
  "complained",
]);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

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
    throw new CandidateE2eError(
      "invalid-contract",
      label + " must be a plain object",
    );
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new CandidateE2eError(
      "invalid-contract",
      label + " contains missing or unexpected fields",
    );
  }
}

function canonicalInstant(value, label) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new CandidateE2eError(
      "invalid-contract",
      label + " must be canonical UTC",
    );
  }
  return value;
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !digestPattern.test(value)) {
    throw new CandidateE2eError(
      "invalid-contract",
      label + " is not an exact SHA-256",
    );
  }
  return value;
}

function exactUuid(value, label) {
  if (typeof value !== "string" || !uuidPattern.test(value)) {
    throw new CandidateE2eError(
      "invalid-contract",
      label + " is not an exact UUID",
    );
  }
  return value;
}

function validateExpected(expected) {
  exactObject(
    expected,
    [
      "accessTeamDomain",
      "applicationCommitSha",
      "artifactSha256",
      "controllerCommitSha",
      "databaseId",
      "notificationRecipient",
      "notificationSender",
      "workerName",
      "workerVersionId",
      "zoneId",
    ],
    "candidate expected identity",
  );
  if (
    !commitPattern.test(expected.applicationCommitSha) ||
    !commitPattern.test(expected.controllerCommitSha) ||
    !digestPattern.test(expected.artifactSha256) ||
    expected.workerName !== expectedWorkerName ||
    !uuidPattern.test(expected.workerVersionId) ||
    !zonePattern.test(expected.zoneId) ||
    !uuidPattern.test(expected.databaseId) ||
    expected.notificationRecipient !== "info@freshtowels.gr" ||
    expected.notificationSender !== "notifications@notify.freshtowels.gr"
  ) {
    throw new CandidateE2eError(
      "invalid-expected-identity",
      "Candidate identity is invalid",
    );
  }
  let accessTeamDomain;
  try {
    accessTeamDomain = new URL(expected.accessTeamDomain);
  } catch {
    throw new CandidateE2eError(
      "invalid-expected-identity",
      "Access team domain is invalid",
    );
  }
  if (
    accessTeamDomain.origin !== expected.accessTeamDomain ||
    accessTeamDomain.protocol !== "https:" ||
    !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(accessTeamDomain.hostname)
  ) {
    throw new CandidateE2eError(
      "invalid-expected-identity",
      "Access team domain is invalid",
    );
  }
}

function validateRelease(release, expected) {
  exactObject(
    release,
    [
      "applicationCommitSha",
      "artifactSha256",
      "controllerCommitSha",
      "databaseId",
      "environment",
      "executionClaimSha256",
      "executionRequestId",
      "infrastructureReceiptSha256",
      "productionReleaseStateSha256",
      "workerName",
      "workerVersionId",
      "zoneId",
    ],
    "candidate release",
  );
  if (
    release.environment !== "production-candidate-e2e" ||
    release.applicationCommitSha !== expected.applicationCommitSha ||
    release.controllerCommitSha !== expected.controllerCommitSha ||
    release.artifactSha256 !== expected.artifactSha256 ||
    release.workerName !== expected.workerName ||
    release.workerVersionId !== expected.workerVersionId ||
    release.zoneId !== expected.zoneId ||
    release.databaseId !== expected.databaseId ||
    !uuidPattern.test(release.executionRequestId) ||
    [
      release.executionClaimSha256,
      release.infrastructureReceiptSha256,
      release.productionReleaseStateSha256,
    ].some((value) => !digestPattern.test(value))
  ) {
    throw new CandidateE2eError(
      "release-identity-mismatch",
      "Candidate release differs from the exact approved release",
    );
  }
  return digest(release);
}

function validateAdapters(adapters) {
  exactObject(
    adapters,
    ["d1", "http", "lifecycle", "resend", "routes", "worker"],
    "candidate adapters",
  );
  for (const [name, methods] of Object.entries({
    worker: ["inspect"],
    routes: ["list", "activate", "deactivate"],
    http: ["request"],
    d1: ["inspectFlow", "markSynthetic"],
    resend: ["inspectEmail"],
    lifecycle: ["transition"],
  })) {
    if (
      methods.some((method) => typeof adapters[name]?.[method] !== "function")
    ) {
      throw new CandidateE2eError(
        "invalid-contract",
        name + " adapter is incomplete",
      );
    }
  }
}

function validateWorkerState(value, release) {
  exactObject(
    value,
    [
      "applicationCommitSha",
      "artifactSha256",
      "stateSha256",
      "trafficPercentage",
      "versionId",
      "workerName",
    ],
    "Worker state",
  );
  if (
    value.workerName !== release.workerName ||
    value.versionId !== release.workerVersionId ||
    value.applicationCommitSha !== release.applicationCommitSha ||
    value.artifactSha256 !== release.artifactSha256 ||
    value.trafficPercentage !== 100 ||
    !digestPattern.test(value.stateSha256)
  ) {
    throw new CandidateE2eError(
      "worker-version-mismatch",
      "Candidate Worker is not the exact approved version",
    );
  }
  return value;
}

function normalizeRoutes(value) {
  if (!Array.isArray(value) || value.length > 10_000) {
    throw new CandidateE2eError(
      "route-inspection-invalid",
      "Authoritative route list is invalid",
    );
  }
  const normalized = value.map((route) => {
    exactObject(route, ["id", "pattern", "script"], "Worker route");
    if (
      !routeIdPattern.test(route.id) ||
      typeof route.pattern !== "string" ||
      route.pattern.length < 1 ||
      route.pattern.length > 512 ||
      /[\r\n\0]/.test(route.pattern) ||
      (route.script !== null &&
        (typeof route.script !== "string" ||
          !/^[a-z0-9-]{1,63}$/.test(route.script)))
    ) {
      throw new CandidateE2eError(
        "route-inspection-invalid",
        "Authoritative route entry is invalid",
      );
    }
    return Object.freeze({
      id: route.id,
      pattern: route.pattern,
      script: route.script,
    });
  });
  const ids = normalized.map((route) => route.id);
  if (new Set(ids).size !== ids.length) {
    throw new CandidateE2eError(
      "route-inspection-invalid",
      "Authoritative routes contain duplicate IDs",
    );
  }
  normalized.sort((left, right) =>
    `${left.pattern}\0${left.script ?? ""}\0${left.id}`.localeCompare(
      `${right.pattern}\0${right.script ?? ""}\0${right.id}`,
      "en",
    ),
  );
  return Object.freeze(normalized);
}

function routeState(routes) {
  const normalized = normalizeRoutes(routes);
  return Object.freeze({ routes: normalized, stateSha256: digest(normalized) });
}

function routePrefix(pattern) {
  if (pattern.endsWith("*")) return pattern.slice(0, -1);
  return pattern;
}

function routesOverlap(left, right) {
  const leftPrefix = routePrefix(left);
  const rightPrefix = routePrefix(right);
  return (
    leftPrefix.startsWith(rightPrefix) || rightPrefix.startsWith(leftPrefix)
  );
}

function candidateRoutesIn(state) {
  return state.routes.filter((route) =>
    candidateRoutePatterns.some((pattern) =>
      routesOverlap(route.pattern, pattern),
    ),
  );
}

function exactCandidateState(state, workerName) {
  const candidates = candidateRoutesIn(state);
  return (
    candidates.length === candidateRoutePatterns.length &&
    candidateRoutePatterns.every(
      (pattern) =>
        candidates.filter(
          (route) => route.pattern === pattern && route.script === workerName,
        ).length === 1,
    )
  );
}

function exactPreCutoverState(state, workerName) {
  const candidates = candidateRoutesIn(state);
  return (
    candidates.length === preCutoverRoutePatterns.length &&
    preCutoverRoutePatterns.every(
      (pattern) =>
        candidates.filter(
          (route) => route.pattern === pattern && route.script === workerName,
        ).length === 1,
    )
  );
}

function validateMutationAcknowledgement(value, action) {
  exactObject(
    value,
    ["accepted", "operationSha256"],
    action + " acknowledgement",
  );
  if (value.accepted !== true || !digestPattern.test(value.operationSha256)) {
    throw new CandidateE2eError(
      "route-mutation-ambiguous",
      action + " was not unambiguously accepted",
    );
  }
}

async function inspectRoutes(adapters, release) {
  return routeState(await adapters.routes.list({ zoneId: release.zoneId }));
}

function unrelatedRoutes(state) {
  const candidates = new Set(candidateRoutesIn(state));
  return state.routes.filter((route) => !candidates.has(route));
}

async function restorePreCutoverRoutes({
  adapters,
  release,
  releaseBindingSha256,
  state,
}) {
  const candidates = candidateRoutesIn(state);
  if (
    candidates.some(
      (route) =>
        !candidateRoutePatterns.includes(route.pattern) ||
        route.script !== release.workerName,
    )
  ) {
    throw new CandidateE2eError(
      "unexpected-overlapping-route",
      "An unexpected Worker route overlaps the candidate surface",
      { doNotRetry: true },
    );
  }
  const baselineIsIntact = preCutoverRoutePatterns.every(
    (pattern) =>
      candidates.filter(
        (route) => route.pattern === pattern && route.script === release.workerName,
      ).length === 1,
  );
  if (!baselineIsIntact) {
    throw new CandidateE2eError(
      "pre-cutover-route-baseline-missing",
      "The Access-protected pre-cutover route baseline is incomplete",
      { doNotRetry: true },
    );
  }
  const publicRoutes = candidates.filter((route) =>
    publicCandidateRoutePatterns.includes(route.pattern),
  );
  if (publicRoutes.length === 0) {
    if (!exactPreCutoverState(state, release.workerName)) {
      throw new CandidateE2eError(
        "pre-cutover-route-baseline-drift",
        "The Access-protected pre-cutover route baseline is not exact",
        { doNotRetry: true },
      );
    }
    return state;
  }

  let mutationError = null;
  try {
    const acknowledgement = await adapters.routes.deactivate({
      expectedStateSha256: state.stateSha256,
      patterns: [...new Set(publicRoutes.map((route) => route.pattern))].sort(),
      releaseBindingSha256,
      workerName: release.workerName,
      zoneId: release.zoneId,
    });
    validateMutationAcknowledgement(
      acknowledgement,
      "candidate route pre-cutover restoration",
    );
  } catch (error) {
    mutationError = error;
  }
  const restored = await inspectRoutes(adapters, release);
  if (!exactPreCutoverState(restored, release.workerName)) {
    throw new CandidateE2eError(
      "route-reconciliation-failed",
      "Candidate routes could not be restored to the Access-protected pre-cutover baseline",
      { cause: mutationError, doNotRetry: true },
    );
  }
  if (digest(unrelatedRoutes(state)) !== digest(unrelatedRoutes(restored))) {
    throw new CandidateE2eError(
      "route-reconciliation-drift",
      "Candidate reconciliation changed or observed unrelated routes",
      { cause: mutationError, doNotRetry: true },
    );
  }
  return restored;
}

async function activateCandidateRoutes({
  adapters,
  release,
  before,
  releaseBindingSha256,
}) {
  if (exactCandidateState(before, release.workerName)) {
    return Object.freeze({ state: before, resumed: true });
  }
  if (!exactPreCutoverState(before, release.workerName)) {
    const exactOwned = candidateRoutesIn(before).every(
      (route) =>
        candidateRoutePatterns.includes(route.pattern) &&
        route.script === release.workerName,
    );
    if (exactOwned) {
      await restorePreCutoverRoutes({
        adapters,
        release,
        releaseBindingSha256,
        state: before,
      });
      throw new CandidateE2eError(
        "partial-route-state-reconciled",
        "Partial candidate route state was restored to the protected baseline; a fresh protected execution is required",
      );
    }
    throw new CandidateE2eError(
      "unexpected-overlapping-route",
      "An unexpected Worker route overlaps the candidate surface",
      { doNotRetry: true },
    );
  }
  let mutationError = null;
  try {
    const acknowledgement = await adapters.routes.activate({
      expectedStateSha256: before.stateSha256,
      patterns: [...publicCandidateRoutePatterns],
      releaseBindingSha256,
      workerName: release.workerName,
      zoneId: release.zoneId,
    });
    validateMutationAcknowledgement(
      acknowledgement,
      "candidate route activation",
    );
  } catch (error) {
    mutationError = error;
  }
  const after = await inspectRoutes(adapters, release);
  if (!exactCandidateState(after, release.workerName)) {
    if (!exactPreCutoverState(after, release.workerName)) {
      await restorePreCutoverRoutes({
        adapters,
        release,
        releaseBindingSha256,
        state: after,
      });
    }
    throw new CandidateE2eError(
      "route-activation-not-authoritative",
      "Candidate routes are not exact after activation",
      { cause: mutationError },
    );
  }
  const unrelatedBefore = unrelatedRoutes(before);
  const unrelatedAfter = unrelatedRoutes(after);
  if (digest(unrelatedBefore) !== digest(unrelatedAfter)) {
    await restorePreCutoverRoutes({
      adapters,
      release,
      releaseBindingSha256,
      state: after,
    });
    throw new CandidateE2eError(
      "route-activation-drift",
      "An unrelated Worker route changed during candidate activation",
      { doNotRetry: true },
    );
  }
  return Object.freeze({ state: after, resumed: false });
}

async function rollbackCandidateRoutes({
  adapters,
  release,
  expectedActiveState,
  releaseBindingSha256,
}) {
  const current = await inspectRoutes(adapters, release);
  if (!exactCandidateState(current, release.workerName)) {
    throw new CandidateE2eError(
      "route-rollback-precondition-drift",
      "Candidate routes changed before rollback",
      { doNotRetry: true },
    );
  }
  if (current.stateSha256 !== expectedActiveState.stateSha256) {
    throw new CandidateE2eError(
      "route-rollback-precondition-drift",
      "Authoritative route state changed before rollback",
      { doNotRetry: true },
    );
  }
  let mutationError = null;
  try {
    const acknowledgement = await adapters.routes.deactivate({
      expectedStateSha256: current.stateSha256,
      patterns: [...publicCandidateRoutePatterns],
      releaseBindingSha256,
      workerName: release.workerName,
      zoneId: release.zoneId,
    });
    validateMutationAcknowledgement(
      acknowledgement,
      "candidate route rollback",
    );
  } catch (error) {
    mutationError = error;
  }
  const restored = await inspectRoutes(adapters, release);
  if (!exactPreCutoverState(restored, release.workerName)) {
    throw new CandidateE2eError(
      "route-rollback-failed",
      "Public candidate routes remain active or the protected baseline drifted after rollback",
      { cause: mutationError, doNotRetry: true },
    );
  }
  const unrelatedActive = unrelatedRoutes(expectedActiveState);
  if (digest(unrelatedActive) !== digest(unrelatedRoutes(restored))) {
    throw new CandidateE2eError(
      "route-rollback-drift",
      "Candidate rollback did not restore the authoritative protected pre-cutover state",
      { doNotRetry: true },
    );
  }
  return restored;
}

function normalizeHeaders(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CandidateE2eError(
      "http-contract-invalid",
      "HTTP headers are invalid",
    );
  }
  const entries = Object.entries(value);
  if (entries.length > 100) {
    throw new CandidateE2eError(
      "http-contract-invalid",
      "HTTP headers exceed the boundary",
    );
  }
  const normalized = {};
  for (const [name, headerValue] of entries) {
    if (
      name !== name.toLowerCase() ||
      !/^[a-z0-9-]{1,64}$/.test(name) ||
      typeof headerValue !== "string" ||
      headerValue.length > 4096 ||
      /[\r\n\0]/.test(headerValue)
    ) {
      throw new CandidateE2eError(
        "http-contract-invalid",
        "HTTP header is invalid",
      );
    }
    normalized[name] = headerValue;
  }
  return Object.freeze(normalized);
}

function normalizeHttpResponse(value) {
  exactObject(
    value,
    ["body", "bodySha256", "headers", "status"],
    "HTTP response",
  );
  if (
    !Number.isInteger(value.status) ||
    value.status < 100 ||
    value.status > 599 ||
    !digestPattern.test(value.bodySha256) ||
    digest(value.body) !== value.bodySha256
  ) {
    throw new CandidateE2eError(
      "http-contract-invalid",
      "HTTP response is not digest-bound",
    );
  }
  return Object.freeze({
    body: value.body,
    bodySha256: value.bodySha256,
    headers: normalizeHeaders(value.headers),
    status: value.status,
  });
}

function createSyntheticSubmission({ now, releaseBindingSha256, testRunId }) {
  const startedAt = now.valueOf() - 2_000;
  const payload = Object.freeze({
    name: "Release Candidate",
    company: `Fresh Towels synthetic ${testRunId}`,
    phone: "210 965 2672",
    segment: "hair",
    towelInterest: "hair_50x90",
    area: "other",
    weeklyQuantity: 50,
    message:
      "AUTOMATED SYNTHETIC PRODUCTION RELEASE TEST. NOT A CUSTOMER REQUEST.",
    sourcePath: "/epikoinonia",
    consent: true,
    startedAt,
    website: "",
  });
  const idempotencyKey = `candidate_${sha256(
    Buffer.from(`${releaseBindingSha256}:${testRunId}`, "utf8"),
  ).slice(0, 48)}`;
  return Object.freeze({
    idempotencyKey,
    payload,
    syntheticMarkerSha256: digest({ idempotencyKey, payload, testRunId }),
  });
}

function validateSubmissionResponse(
  response,
  expectedStatus,
  expectedDuplicate,
  leadId = null,
) {
  const normalized = normalizeHttpResponse(response);
  exactObject(
    normalized.body,
    ["duplicate", "id", "notification", "ok"],
    "lead response body",
  );
  if (
    normalized.status !== expectedStatus ||
    normalized.body.ok !== true ||
    normalized.body.duplicate !== expectedDuplicate ||
    !leadIdPattern.test(normalized.body.id) ||
    (leadId !== null && normalized.body.id !== leadId) ||
    !outboxStatuses.includes(normalized.body.notification)
  ) {
    throw new CandidateE2eError(
      "lead-submission-proof-failed",
      "Synthetic lead persistence or idempotency proof failed",
    );
  }
  return normalized;
}

async function proveUnauthorizedDashboard({ adapters, expected }) {
  const response = normalizeHttpResponse(
    await adapters.http.request({
      body: null,
      headers: Object.freeze({ accept: "text/html" }),
      method: "GET",
      redirect: "manual",
      url: `${expectedOrigin}/internal/leads`,
    }),
  );
  if (![302, 401, 403].includes(response.status)) {
    throw new CandidateE2eError(
      "access-unauthorized-not-denied",
      "Unauthenticated dashboard request was not denied",
      { doNotRetry: true },
    );
  }
  if (response.status === 302) {
    let location;
    try {
      location = new URL(response.headers.location);
    } catch {
      throw new CandidateE2eError(
        "access-challenge-invalid",
        "Access challenge location is invalid",
        { doNotRetry: true },
      );
    }
    if (
      location.origin !== expected.accessTeamDomain ||
      !location.pathname.startsWith("/cdn-cgi/access/login/")
    ) {
      throw new CandidateE2eError(
        "access-challenge-invalid",
        "Access challenge is not bound to the reviewed team domain",
        { doNotRetry: true },
      );
    }
  }
  return Object.freeze({
    bodySha256: response.bodySha256,
    challengeSha256: sha256(
      Buffer.from(response.headers.location ?? `status:${response.status}`),
    ),
    status: response.status,
  });
}

function validateFlow(
  value,
  { expected, leadId, syntheticMarkerSha256, testRunId },
) {
  exactObject(
    value,
    ["databaseId", "delivery", "lead", "outbox", "testRunId"],
    "D1 lead-flow state",
  );
  if (
    value.databaseId !== expected.databaseId ||
    value.testRunId !== testRunId
  ) {
    throw new CandidateE2eError(
      "d1-flow-mismatch",
      "D1 lead-flow identity changed",
    );
  }
  exactObject(
    value.lead,
    [
      "id",
      "sourcePath",
      "status",
      "synthetic",
      "syntheticMarkerSha256",
      "version",
    ],
    "D1 lead state",
  );
  if (
    value.lead.id !== leadId ||
    value.lead.sourcePath !== "/epikoinonia" ||
    value.lead.synthetic !== true ||
    value.lead.syntheticMarkerSha256 !== syntheticMarkerSha256 ||
    !leadStatuses.includes(value.lead.status) ||
    !Number.isSafeInteger(value.lead.version) ||
    value.lead.version < 1
  ) {
    throw new CandidateE2eError("d1-flow-mismatch", "D1 lead state changed");
  }
  exactObject(
    value.outbox,
    [
      "id",
      "providerMessageId",
      "providerMessageIdSha256",
      "recipientSha256",
      "senderSha256",
      "status",
    ],
    "D1 outbox state",
  );
  if (
    !outboxIdPattern.test(value.outbox.id) ||
    !outboxStatuses.includes(value.outbox.status) ||
    value.outbox.recipientSha256 !==
      sha256(Buffer.from(expected.notificationRecipient)) ||
    value.outbox.senderSha256 !==
      sha256(Buffer.from(expected.notificationSender)) ||
    (value.outbox.providerMessageId === null
      ? value.outbox.providerMessageIdSha256 !== null
      : !safeProviderIdPattern.test(value.outbox.providerMessageId) ||
        value.outbox.providerMessageIdSha256 !==
          sha256(Buffer.from(value.outbox.providerMessageId, "utf8")))
  ) {
    throw new CandidateE2eError("d1-flow-mismatch", "D1 outbox state changed");
  }
  if (value.delivery !== null) {
    exactObject(
      value.delivery,
      [
        "eventIdSha256",
        "providerCreatedAt",
        "providerMessageIdSha256",
        "receivedAt",
        "status",
      ],
      "D1 delivery state",
    );
    if (
      !deliveryStatuses.includes(value.delivery.status) ||
      !digestPattern.test(value.delivery.eventIdSha256) ||
      value.delivery.providerMessageIdSha256 !==
        value.outbox.providerMessageIdSha256 ||
      canonicalInstant(
        value.delivery.providerCreatedAt,
        "D1 delivery providerCreatedAt",
      ) !== value.delivery.providerCreatedAt ||
      canonicalInstant(value.delivery.receivedAt, "D1 delivery receivedAt") !==
        value.delivery.receivedAt ||
      Date.parse(value.delivery.receivedAt) <
        Date.parse(value.delivery.providerCreatedAt)
    ) {
      throw new CandidateE2eError(
        "d1-flow-mismatch",
        "D1 delivery state changed",
      );
    }
  }
  return value;
}

async function pollDeliveredFlow({
  adapters,
  expected,
  leadId,
  synthetic,
  testRunId,
  poll,
}) {
  const deadline = poll.now().valueOf() + poll.timeoutMilliseconds;
  for (;;) {
    const flow = validateFlow(
      await adapters.d1.inspectFlow({
        databaseId: expected.databaseId,
        leadId,
        syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
        testRunId,
      }),
      {
        expected,
        leadId,
        syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
        testRunId,
      },
    );
    if (
      flow.outbox.status === "sent" &&
      flow.outbox.providerMessageId !== null &&
      flow.delivery?.status === "delivered"
    ) {
      return flow;
    }
    if (["failed", "dead"].includes(flow.outbox.status)) {
      throw new CandidateE2eError(
        "notification-terminal-failure",
        "Notification outbox failed",
      );
    }
    if (
      flow.delivery &&
      ["failed", "bounced", "suppressed", "complained"].includes(
        flow.delivery.status,
      )
    ) {
      throw new CandidateE2eError(
        "delivery-terminal-failure",
        "Notification delivery failed",
      );
    }
    if (poll.now().valueOf() >= deadline) {
      throw new CandidateE2eError(
        "delivery-timeout",
        "Notification delivery proof timed out",
      );
    }
    await poll.sleep(poll.intervalMilliseconds);
  }
}

function validateResendDelivery(value, { expected, flow }) {
  exactObject(
    value,
    ["createdAt", "from", "id", "lastEvent", "to"],
    "Resend email state",
  );
  canonicalInstant(value.createdAt, "Resend email createdAt");
  if (
    value.id !== flow.outbox.providerMessageId ||
    value.from !== expected.notificationSender ||
    !Array.isArray(value.to) ||
    value.to.length !== 1 ||
    value.to[0] !== expected.notificationRecipient ||
    value.lastEvent !== "delivered"
  ) {
    throw new CandidateE2eError(
      "resend-delivery-mismatch",
      "Resend delivery does not match the persisted notification",
    );
  }
  return Object.freeze({
    createdAt: value.createdAt,
    messageIdSha256: sha256(Buffer.from(value.id, "utf8")),
    stateSha256: digest({
      createdAt: value.createdAt,
      fromSha256: sha256(Buffer.from(value.from, "utf8")),
      idSha256: sha256(Buffer.from(value.id, "utf8")),
      lastEvent: value.lastEvent,
      toSha256: value.to.map((item) => sha256(Buffer.from(item, "utf8"))),
    }),
  });
}

async function archiveLead({
  adapters,
  expected,
  flow,
  now,
  releaseBindingSha256,
  testRunId,
}) {
  const transitions = [];
  let current = flow;
  const sequence = Object.freeze({
    new: "in_progress",
    in_progress: "answered",
    answered: "archived",
  });
  while (current.lead.status !== "archived") {
    const next = sequence[current.lead.status];
    if (!next) {
      throw new CandidateE2eError(
        "lifecycle-invalid",
        "Synthetic lead cannot reach archived",
      );
    }
    const transition = await adapters.lifecycle.transition({
      actorSubjectSha256: digest({ releaseBindingSha256, testRunId }),
      changedAt: canonicalInstant(
        now().toISOString(),
        "synthetic lifecycle changedAt",
      ),
      databaseId: expected.databaseId,
      expectedVersion: current.lead.version,
      fromStatus: current.lead.status,
      leadId: current.lead.id,
      releaseBindingSha256,
      testRunId,
      toStatus: next,
    });
    exactObject(
      transition,
      [
        "eventIdSha256",
        "fromStatus",
        "leadId",
        "previousVersion",
        "stateSha256",
        "toStatus",
        "version",
      ],
      "lead lifecycle transition",
    );
    if (
      transition.leadId !== current.lead.id ||
      transition.fromStatus !== current.lead.status ||
      transition.toStatus !== next ||
      transition.previousVersion !== current.lead.version ||
      transition.version !== current.lead.version + 1 ||
      !digestPattern.test(transition.eventIdSha256) ||
      !digestPattern.test(transition.stateSha256)
    ) {
      throw new CandidateE2eError(
        "lifecycle-mismatch",
        "Synthetic lead transition changed",
      );
    }
    transitions.push(transition);
    current = Object.freeze({
      ...current,
      lead: Object.freeze({
        ...current.lead,
        status: next,
        version: transition.version,
      }),
    });
  }
  return Object.freeze({
    flow: current,
    transitionSha256s: Object.freeze(
      transitions.map((transition) => digest(transition)),
    ),
  });
}

function validatePoll(poll) {
  exactObject(
    poll,
    ["intervalMilliseconds", "now", "sleep", "timeoutMilliseconds"],
    "poll controls",
  );
  if (
    typeof poll.now !== "function" ||
    typeof poll.sleep !== "function" ||
    !Number.isSafeInteger(poll.intervalMilliseconds) ||
    poll.intervalMilliseconds < 100 ||
    poll.intervalMilliseconds > 60_000 ||
    !Number.isSafeInteger(poll.timeoutMilliseconds) ||
    poll.timeoutMilliseconds < poll.intervalMilliseconds ||
    poll.timeoutMilliseconds > 20 * 60 * 1000 ||
    !(poll.now() instanceof Date) ||
    !Number.isFinite(poll.now().valueOf())
  ) {
    throw new CandidateE2eError(
      "invalid-contract",
      "poll controls are invalid",
    );
  }
}

function evidenceReceipt({
  accessProof,
  archived,
  completedAt,
  delivered,
  expected,
  flow,
  release,
  releaseBindingSha256,
  routeActive,
  routeBefore,
  routePreCutover,
  synthetic,
  testRunId,
  worker,
}) {
  const body = {
    schema: "deployment-control/production-candidate-e2e/v1",
    receiptType: "fresh-towels-production-candidate-e2e",
    environment: release.environment,
    completedAt,
    release: {
      applicationCommitSha: release.applicationCommitSha,
      artifactSha256: release.artifactSha256,
      controllerCommitSha: release.controllerCommitSha,
      executionClaimSha256: release.executionClaimSha256,
      executionRequestId: release.executionRequestId,
      infrastructureReceiptSha256: release.infrastructureReceiptSha256,
      productionReleaseStateSha256: release.productionReleaseStateSha256,
      releaseBindingSha256,
    },
    worker: {
      stateSha256: worker.stateSha256,
      versionId: worker.versionId,
      workerNameSha256: sha256(Buffer.from(worker.workerName, "utf8")),
    },
    routes: {
      activeStateSha256: routeActive.stateSha256,
      candidatePatternsSha256: digest(candidateRoutePatterns),
      preCutoverStateSha256: routePreCutover.stateSha256,
      preStateSha256: routeBefore.stateSha256,
      rollbackVerified: true,
    },
    accessUnauthorized: {
      challengeSha256: accessProof.challengeSha256,
      responseBodySha256: accessProof.bodySha256,
      status: accessProof.status,
    },
    leadFlow: {
      d1StateSha256: digest(flow),
      deliveryEventIdSha256: flow.delivery.eventIdSha256,
      deliveryStateSha256: digest(flow.delivery),
      duplicateEffectCount: 1,
      finalStatusSha256: sha256(Buffer.from(archived.flow.lead.status, "utf8")),
      leadCount: 1,
      leadIdSha256: sha256(Buffer.from(flow.lead.id, "utf8")),
      outboxIdSha256: sha256(Buffer.from(flow.outbox.id, "utf8")),
      outboxStateSha256: digest(flow.outbox),
      providerMessageIdSha256: flow.outbox.providerMessageIdSha256,
      syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
      testRunIdSha256: sha256(Buffer.from(testRunId, "utf8")),
    },
    resend: {
      deliveryStateSha256: delivered.stateSha256,
      messageIdSha256: delivered.messageIdSha256,
      recipientSha256: sha256(
        Buffer.from(expected.notificationRecipient, "utf8"),
      ),
      senderSha256: sha256(Buffer.from(expected.notificationSender, "utf8")),
    },
    lifecycle: {
      finalStateSha256: digest({
        status: archived.flow.lead.status,
        transitionSha256s: archived.transitionSha256s,
        version: archived.flow.lead.version,
      }),
      transitionSha256s: archived.transitionSha256s,
    },
  };
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

export class CandidateE2eError extends Error {
  constructor(code, message, { cause, doNotRetry = false } = {}) {
    super(message, { cause });
    this.name = "CandidateE2eError";
    this.code = code;
    this.doNotRetry = doNotRetry;
  }
}

export async function executeProductionCandidateE2e({
  adapters,
  expected,
  poll = {
    intervalMilliseconds: 2_000,
    now: () => new Date(),
    sleep: (milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds)),
    timeoutMilliseconds: 15 * 60 * 1000,
  },
  release,
  testRunId,
}) {
  validateExpected(expected);
  const releaseBindingSha256 = validateRelease(release, expected);
  validateAdapters(adapters);
  validatePoll(poll);
  exactUuid(testRunId, "candidate test run ID");

  const worker = validateWorkerState(
    await adapters.worker.inspect({
      artifactSha256: release.artifactSha256,
      workerName: release.workerName,
      workerVersionId: release.workerVersionId,
    }),
    release,
  );
  const routeBefore = await inspectRoutes(adapters, release);
  let routeActive = null;
  let leadId = null;
  let archived = null;
  let synthetic = null;
  let primaryError = null;
  let receipt = null;

  try {
    const activation = await activateCandidateRoutes({
      adapters,
      before: routeBefore,
      release,
      releaseBindingSha256,
    });
    routeActive = activation.state;
    const accessProof = await proveUnauthorizedDashboard({
      adapters,
      expected,
    });
    const now = poll.now();
    synthetic = createSyntheticSubmission({
      now,
      releaseBindingSha256,
      testRunId,
    });
    const request = Object.freeze({
      body: synthetic.payload,
      headers: Object.freeze({
        "content-type": "application/json",
        "idempotency-key": synthetic.idempotencyKey,
        origin: expectedOrigin,
      }),
      method: "POST",
      redirect: "error",
      url: `${expectedOrigin}/api/leads`,
    });
    const first = validateSubmissionResponse(
      await adapters.http.request(request),
      201,
      false,
    );
    leadId = first.body.id;
    const syntheticMark = await adapters.d1.markSynthetic({
      databaseId: expected.databaseId,
      leadId,
      releaseBindingSha256,
      syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
      testRunId,
    });
    exactObject(
      syntheticMark,
      ["leadId", "stateSha256", "synthetic"],
      "synthetic lead mark",
    );
    if (
      syntheticMark.leadId !== leadId ||
      syntheticMark.synthetic !== true ||
      !digestPattern.test(syntheticMark.stateSha256)
    ) {
      throw new CandidateE2eError(
        "synthetic-mark-failed",
        "Persisted release lead was not marked synthetic",
        { doNotRetry: true },
      );
    }
    validateSubmissionResponse(
      await adapters.http.request(request),
      200,
      true,
      leadId,
    );
    const flow = await pollDeliveredFlow({
      adapters,
      expected,
      leadId,
      poll,
      synthetic,
      testRunId,
    });
    const delivered = validateResendDelivery(
      await adapters.resend.inspectEmail({
        messageId: flow.outbox.providerMessageId,
      }),
      { expected, flow },
    );
    archived = await archiveLead({
      adapters,
      expected,
      flow,
      now: poll.now,
      releaseBindingSha256,
      testRunId,
    });
    const finalFlow = validateFlow(
      await adapters.d1.inspectFlow({
        databaseId: expected.databaseId,
        leadId,
        syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
        testRunId,
      }),
      {
        expected,
        leadId,
        syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
        testRunId,
      },
    );
    if (
      finalFlow.lead.status !== "archived" ||
      finalFlow.lead.version !== archived.flow.lead.version
    ) {
      throw new CandidateE2eError(
        "lifecycle-not-authoritative",
        "Synthetic lead is not authoritatively archived",
      );
    }
    archived = Object.freeze({ ...archived, flow: finalFlow });
    receipt = Object.freeze({
      accessProof,
      archived,
      delivered,
      flow,
      synthetic,
    });
  } catch (error) {
    primaryError = error;
    if (leadId && !archived) {
      try {
        if (!synthetic)
          throw new Error("synthetic submission identity is unavailable");
        const cleanupFlow = validateFlow(
          await adapters.d1.inspectFlow({
            databaseId: expected.databaseId,
            leadId,
            syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
            testRunId,
          }),
          {
            expected,
            leadId,
            syntheticMarkerSha256: synthetic.syntheticMarkerSha256,
            testRunId,
          },
        );
        archived = await archiveLead({
          adapters,
          expected,
          flow: cleanupFlow,
          now: poll.now,
          releaseBindingSha256,
          testRunId,
        });
      } catch (cleanupError) {
        primaryError = new CandidateE2eError(
          "synthetic-lead-cleanup-failed",
          "Candidate failed and the synthetic lead could not be archived",
          { cause: cleanupError, doNotRetry: true },
        );
      }
    }
  }

  let routePreCutover;
  if (routeActive) {
    try {
      routePreCutover = await rollbackCandidateRoutes({
        adapters,
        expectedActiveState: routeActive,
        release,
        releaseBindingSha256,
      });
    } catch (rollbackError) {
      throw new CandidateE2eError(
        "candidate-route-cleanup-failed",
        "Candidate routes could not be safely restored to the protected pre-cutover baseline",
        { cause: rollbackError, doNotRetry: true },
      );
    }
  }
  if (primaryError) throw primaryError;
  if (!receipt || !routePreCutover) {
    throw new CandidateE2eError(
      "candidate-incomplete",
      "Candidate execution did not complete",
    );
  }
  return evidenceReceipt({
    ...receipt,
    completedAt: canonicalInstant(
      poll.now().toISOString(),
      "candidate completedAt",
    ),
    expected,
    release,
    releaseBindingSha256,
    routeActive,
    routeBefore,
    routePreCutover,
    testRunId,
    worker,
  });
}

export function serializeProductionCandidateE2eReceipt(receipt) {
  const { receiptSha256, ...body } = receipt;
  if (
    receipt.schema !== "deployment-control/production-candidate-e2e/v1" ||
    receipt.receiptType !== "fresh-towels-production-candidate-e2e" ||
    !digestPattern.test(receiptSha256 ?? "") ||
    digest(body) !== receiptSha256
  ) {
    throw new CandidateE2eError(
      "receipt-invalid",
      "Candidate E2E receipt is invalid",
    );
  }
  const bytes = Buffer.from(JSON.stringify(receipt) + "\n", "utf8");
  for (const forbidden of [
    "info@freshtowels.gr",
    "notifications@notify.freshtowels.gr",
    "210 965 2672",
  ]) {
    if (bytes.includes(Buffer.from(forbidden, "utf8"))) {
      throw new CandidateE2eError(
        "receipt-pii",
        "Candidate receipt contains forbidden contact data",
      );
    }
  }
  return bytes;
}

export const productionCandidateE2eConstants = Object.freeze({
  candidateRoutePatterns,
  preCutoverRoutePatterns,
  publicCandidateRoutePatterns,
  expectedOrigin,
  expectedWorkerName,
});
