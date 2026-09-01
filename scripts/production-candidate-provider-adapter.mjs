import { canonicalJson, sha256 } from "./control-contract.mjs";
import { productionCandidateE2eConstants } from "./production-candidate-e2e.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const zonePattern = /^[a-f0-9]{32}$/;
const routeIdPattern = /^[a-f0-9]{32}$/;
const leadIdPattern = /^lead_[a-f0-9]{32}$/;
const providerIdPattern = /^[A-Za-z0-9_-]{1,256}$/;
const expectedOrigin = productionCandidateE2eConstants.expectedOrigin;
const candidatePatterns = productionCandidateE2eConstants.candidateRoutePatterns;
const activationPatterns = productionCandidateE2eConstants.publicCandidateRoutePatterns;
const exactLead = Object.freeze({
  contactName: "Release Candidate",
  message: "AUTOMATED SYNTHETIC PRODUCTION RELEASE TEST. NOT A CUSTOMER REQUEST.",
  phoneE164: "+302109652672",
  segment: "hair",
  serviceArea: "other",
  sourcePath: "/epikoinonia",
  towelInterest: "hair_50x90",
  weeklyQuantity: 50,
});

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
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
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

async function request(client, method, path, options) {
  if (!client || typeof client.request !== "function") {
    throw new Error("candidate provider client is unavailable");
  }
  return client.request(requestInput(method, path, options));
}

function d1Result(response, label) {
  if (
    !Array.isArray(response?.result) ||
    response.result.length !== 1 ||
    response.result[0]?.success !== true ||
    !Array.isArray(response.result[0].results)
  ) {
    throw new Error(label + " D1 result is malformed");
  }
  return response.result[0];
}

async function d1Query(client, accountId, databaseId, sql, params = []) {
  if (
    typeof sql !== "string" ||
    sql.length < 1 ||
    sql.length > 32_768 ||
    !Array.isArray(params) ||
    params.length > 32 ||
    params.some(
      (value) =>
        !["string", "number"].includes(typeof value) ||
        (typeof value === "string" && (value.length > 4096 || /[\0]/.test(value))) ||
        (typeof value === "number" && !Number.isSafeInteger(value)),
    )
  ) {
    throw new Error("candidate D1 query is outside the fixed boundary");
  }
  const body = { params, sql };
  return d1Result(
    await request(
      client,
      "POST",
      `/accounts/${accountId}/d1/database/${databaseId}/query`,
      { body, bodySha256: digest(body) },
    ),
    "candidate",
  );
}

function normalizedRoutes(value) {
  if (!Array.isArray(value) || value.length > 10_000) {
    throw new Error("candidate route inventory is invalid");
  }
  const result = value.map((route) => {
    if (
      !routeIdPattern.test(route?.id ?? "") ||
      typeof route?.pattern !== "string" ||
      route.pattern.length < 1 ||
      route.pattern.length > 512 ||
      /[\r\n\0]/.test(route.pattern) ||
      (route.script !== null &&
        (typeof route.script !== "string" ||
          !/^[a-z0-9-]{1,63}$/.test(route.script)))
    ) {
      throw new Error("candidate route inventory is invalid");
    }
    return { id: route.id, pattern: route.pattern, script: route.script };
  });
  if (new Set(result.map((route) => route.id)).size !== result.length) {
    throw new Error("candidate route inventory contains duplicate IDs");
  }
  result.sort((left, right) =>
    `${left.pattern}\0${left.script ?? ""}\0${left.id}`.localeCompare(
      `${right.pattern}\0${right.script ?? ""}\0${right.id}`,
      "en",
    ),
  );
  return result;
}

async function listRoutes(cloudflareClient, zoneId) {
  const response = await request(
    cloudflareClient,
    "GET",
    `/zones/${zoneId}/workers/routes`,
  );
  return normalizedRoutes(response.result);
}

function routeStateSha256(routes) {
  return digest(normalizedRoutes(routes));
}

function exactPatternSet(patterns) {
  return (
    Array.isArray(patterns) &&
    patterns.length === activationPatterns.length &&
    canonicalJson([...patterns].sort()) === canonicalJson([...activationPatterns].sort())
  );
}

function expectedLeadIdentity(releaseBindingSha256, testRunId) {
  const idempotencyKey = `candidate_${sha256(
    Buffer.from(`${releaseBindingSha256}:${testRunId}`, "utf8"),
  ).slice(0, 48)}`;
  const idempotencyKeyHash = sha256(Buffer.from(idempotencyKey, "utf8"));
  return Object.freeze({
    companyName: `Fresh Towels synthetic ${testRunId}`,
    idempotencyKeyHash,
    leadId: `lead_${idempotencyKeyHash.slice(0, 32)}`,
  });
}

function validateCandidateLeadRow(row, identity, { requireSynthetic = true } = {}) {
  if (
    row?.id !== identity.leadId ||
    row?.idempotency_key_hash !== identity.idempotencyKeyHash ||
    row?.contact_name !== exactLead.contactName ||
    row?.company_name !== identity.companyName ||
    row?.phone_e164 !== exactLead.phoneE164 ||
    row?.segment !== exactLead.segment ||
    row?.towel_interest !== exactLead.towelInterest ||
    row?.service_area !== exactLead.serviceArea ||
    row?.weekly_quantity !== exactLead.weeklyQuantity ||
    row?.message !== exactLead.message ||
    row?.source_path !== exactLead.sourcePath ||
    row?.form_version !== "quote-v2" ||
    row?.relationship_status !== "non_customer" ||
    row?.anonymized_at !== null ||
    !Number.isSafeInteger(row?.version) ||
    ![0, 1].includes(row?.synthetic) ||
    (requireSynthetic && row.synthetic !== 1)
  ) {
    throw new Error("candidate D1 lead identity changed");
  }
  return row;
}

function senderAddress(value) {
  if (typeof value !== "string" || /[\r\n\0]/.test(value)) return null;
  const match = value.trim().match(/^(?:[^<>]{1,100}\s*)?<([^<>\s,@]+@[^<>\s,@]+\.[^<>\s,@]+)>$|^([^\s,@]+@[^\s,@]+\.[^\s,@]+)$/);
  return (match?.[1] ?? match?.[2] ?? "").toLowerCase() || null;
}

function parseRequestSnapshot(value, expected) {
  if (typeof value !== "string" || value.length < 2 || value.length > 32_768) {
    throw new Error("candidate notification snapshot is invalid");
  }
  let body;
  try {
    body = JSON.parse(value);
  } catch {
    throw new Error("candidate notification snapshot is invalid");
  }
  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    senderAddress(body.from) !== expected.notificationSender ||
    !Array.isArray(body.to) ||
    body.to.length !== 1 ||
    body.to[0] !== expected.notificationRecipient
  ) {
    throw new Error("candidate notification recipient or sender changed");
  }
  return body;
}

function canonicalProviderInstant(value, label) {
  const timestamp = Date.parse(value);
  if (typeof value !== "string" || !Number.isFinite(timestamp)) {
    throw new Error(label + " is invalid");
  }
  return new Date(timestamp).toISOString();
}

async function safeCandidateHttpRequest(fetchImpl, input) {
  exactObject(
    input,
    ["body", "headers", "method", "redirect", "url"],
    "candidate HTTP request",
  );
  let url;
  try {
    url = new URL(input.url);
  } catch {
    throw new Error("candidate HTTP URL is invalid");
  }
  const allowed =
    url.origin === expectedOrigin &&
    url.search === "" &&
    url.hash === "" &&
    ((input.method === "POST" && url.pathname === "/api/leads") ||
      (input.method === "GET" && url.pathname === "/internal/leads"));
  if (
    !allowed ||
    !["error", "manual"].includes(input.redirect) ||
    input.headers === null ||
    typeof input.headers !== "object" ||
    Array.isArray(input.headers)
  ) {
    throw new Error("candidate HTTP request exceeds the exact route boundary");
  }
  const headers = new Headers(input.headers);
  let body;
  if (input.method === "POST") {
    if (input.redirect !== "error" || headers.get("content-type") !== "application/json") {
      throw new Error("candidate lead request is invalid");
    }
    body = JSON.stringify(input.body);
  } else if (input.body !== null || input.redirect !== "manual") {
    throw new Error("candidate dashboard request is invalid");
  }
  let response;
  try {
    response = await fetchImpl(url, {
      body,
      headers,
      method: input.method,
      redirect: input.redirect,
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new Error("candidate public HTTP result is ambiguous");
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.byteLength > 256 * 1024) {
    throw new Error("candidate public HTTP response exceeds the boundary");
  }
  let responseBody;
  try {
    responseBody = bytes.byteLength ? JSON.parse(bytes.toString("utf8")) : {};
  } catch {
    responseBody = { textSha256: sha256(bytes) };
  }
  const responseHeaders = {};
  for (const name of ["content-type", "location", "server"]) {
    const value = response.headers.get(name);
    if (value !== null && value.length <= 4096 && !/[\r\n\0]/.test(value)) {
      responseHeaders[name] = value;
    }
  }
  return Object.freeze({
    body: responseBody,
    bodySha256: digest(responseBody),
    headers: Object.freeze(responseHeaders),
    status: response.status,
  });
}

export function createProductionCandidateProviderAdapter({
  accountId,
  candidateExpected,
  cloudflareClient,
  databaseId,
  fetchImpl = globalThis.fetch,
  productionWranglerAdapter,
  releaseBindingSha256,
  resendAdminClient,
  testRunId,
  workerExpected,
  zoneId,
} = {}) {
  if (
    !/^[a-f0-9]{32}$/.test(accountId ?? "") ||
    !uuidPattern.test(databaseId ?? "") ||
    !zonePattern.test(zoneId ?? "") ||
    !digestPattern.test(releaseBindingSha256 ?? "") ||
    !uuidPattern.test(testRunId ?? "") ||
    !cloudflareClient?.request ||
    !resendAdminClient?.request ||
    typeof fetchImpl !== "function" ||
    !productionWranglerAdapter?.inspectWorkerVersion ||
    !productionWranglerAdapter?.inspectDeployment ||
    candidateExpected?.databaseId !== databaseId ||
    candidateExpected?.zoneId !== zoneId ||
    workerExpected?.workerName !== candidateExpected?.workerName ||
    candidateExpected?.workerVersionId === undefined
  ) {
    throw new Error("candidate provider adapter configuration is invalid");
  }
  const identity = expectedLeadIdentity(releaseBindingSha256, testRunId);

  async function candidateLeadRow() {
    const result = await d1Query(
      cloudflareClient,
      accountId,
      databaseId,
      `SELECT l.id, l.idempotency_key_hash, l.contact_name, l.company_name,
              l.phone_e164, l.segment,
              COALESCE(l.towel_interest_v2, l.towel_interest) AS towel_interest,
              l.service_area,
              COALESCE(l.weekly_quantity_estimate, l.weekly_quantity) AS weekly_quantity,
              l.message, l.source_path, l.form_version, l.status, l.version,
              l.synthetic, l.relationship_status, l.anonymized_at
       FROM leads AS l WHERE l.id = ?1 LIMIT 2`,
      [identity.leadId],
    );
    if (result.results.length !== 1) {
      throw new Error("candidate D1 lead is absent or ambiguous");
    }
    return result.results[0];
  }

  return Object.freeze({
    worker: Object.freeze({
      async inspect(input) {
        exactObject(
          input,
          ["artifactSha256", "workerName", "workerVersionId"],
          "candidate Worker inspection",
        );
        if (
          input.artifactSha256 !== candidateExpected.artifactSha256 ||
          input.workerName !== candidateExpected.workerName ||
          input.workerVersionId !== candidateExpected.workerVersionId
        ) {
          throw new Error("candidate Worker inspection identity changed");
        }
        const [version, deployment] = await Promise.all([
          productionWranglerAdapter.inspectWorkerVersion(
            workerExpected,
            candidateExpected.workerVersionId,
          ),
          productionWranglerAdapter.inspectDeployment({
            workerName: candidateExpected.workerName,
          }),
        ]);
        if (
          version?.versionId !== candidateExpected.workerVersionId ||
          deployment?.versionId !== candidateExpected.workerVersionId ||
          deployment?.percentage !== 100
        ) {
          throw new Error("candidate Worker deployment changed");
        }
        return Object.freeze({
          applicationCommitSha: candidateExpected.applicationCommitSha,
          artifactSha256: candidateExpected.artifactSha256,
          stateSha256: digest({
            deploymentStateSha256: deployment.stateSha256,
            versionStateSha256: version.stateSha256,
          }),
          trafficPercentage: deployment.percentage,
          versionId: version.versionId,
          workerName: workerExpected.workerName,
        });
      },
    }),
    routes: Object.freeze({
      async list(input) {
        exactObject(input, ["zoneId"], "candidate route list");
        if (input.zoneId !== zoneId) throw new Error("candidate route zone changed");
        return listRoutes(cloudflareClient, zoneId);
      },
      async activate(input) {
        exactObject(
          input,
          [
            "expectedStateSha256",
            "patterns",
            "releaseBindingSha256",
            "workerName",
            "zoneId",
          ],
          "candidate route activation",
        );
        const before = await listRoutes(cloudflareClient, zoneId);
        if (
          input.zoneId !== zoneId ||
          input.workerName !== candidateExpected.workerName ||
          input.releaseBindingSha256 !== releaseBindingSha256 ||
          input.expectedStateSha256 !== routeStateSha256(before) ||
          !exactPatternSet(input.patterns)
        ) {
          throw new Error("candidate route activation precondition changed");
        }
        for (const pattern of activationPatterns) {
          const body = { pattern, script: candidateExpected.workerName };
          await request(cloudflareClient, "POST", `/zones/${zoneId}/workers/routes`, {
            body,
            bodySha256: digest(body),
            idempotencyKey: digest({ action: "activate", pattern, releaseBindingSha256 }),
          });
        }
        return Object.freeze({
          accepted: true,
          operationSha256: digest({
            action: "activate",
            expectedStateSha256: input.expectedStateSha256,
            patterns: activationPatterns,
            releaseBindingSha256,
          }),
        });
      },
      async deactivate(input) {
        exactObject(
          input,
          [
            "expectedStateSha256",
            "patterns",
            "releaseBindingSha256",
            "workerName",
            "zoneId",
          ],
          "candidate route deactivation",
        );
        const before = await listRoutes(cloudflareClient, zoneId);
        if (
          input.zoneId !== zoneId ||
          input.workerName !== candidateExpected.workerName ||
          input.releaseBindingSha256 !== releaseBindingSha256 ||
          input.expectedStateSha256 !== routeStateSha256(before) ||
          !Array.isArray(input.patterns) ||
          input.patterns.some((pattern) => !activationPatterns.includes(pattern)) ||
          new Set(input.patterns).size !== input.patterns.length
        ) {
          throw new Error("candidate route deactivation precondition changed");
        }
        const owned = before.filter(
          (route) =>
            input.patterns.includes(route.pattern) &&
            route.script === candidateExpected.workerName,
        );
        if (owned.length !== input.patterns.length) {
          throw new Error("candidate route deactivation target is absent or ambiguous");
        }
        for (const route of owned) {
          await request(
            cloudflareClient,
            "DELETE",
            `/zones/${zoneId}/workers/routes/${route.id}`,
          );
        }
        return Object.freeze({
          accepted: true,
          operationSha256: digest({
            action: "deactivate",
            expectedStateSha256: input.expectedStateSha256,
            patterns: [...input.patterns].sort(),
            releaseBindingSha256,
          }),
        });
      },
    }),
    http: Object.freeze({
      request: (input) => safeCandidateHttpRequest(fetchImpl, input),
    }),
    d1: Object.freeze({
      async markSynthetic(input) {
        exactObject(
          input,
          [
            "databaseId",
            "leadId",
            "releaseBindingSha256",
            "syntheticMarkerSha256",
            "testRunId",
          ],
          "candidate synthetic mark",
        );
        if (
          input.databaseId !== databaseId ||
          input.leadId !== identity.leadId ||
          input.releaseBindingSha256 !== releaseBindingSha256 ||
          input.testRunId !== testRunId ||
          !digestPattern.test(input.syntheticMarkerSha256)
        ) {
          throw new Error("candidate synthetic mark identity changed");
        }
        const before = validateCandidateLeadRow(await candidateLeadRow(), identity, {
          requireSynthetic: false,
        });
        if (before.status !== "new" || before.version !== 1) {
          throw new Error("candidate synthetic mark lifecycle changed");
        }
        if (before.synthetic === 0) {
          await d1Query(
            cloudflareClient,
            accountId,
            databaseId,
            `UPDATE leads SET synthetic = 1
             WHERE id = ?1 AND idempotency_key_hash = ?2 AND synthetic = 0
               AND status = 'new' AND version = 1
               AND contact_name = ?3 AND company_name = ?4 AND phone_e164 = ?5
               AND source_path = '/epikoinonia' AND relationship_status = 'non_customer'
               AND anonymized_at IS NULL`,
            [
              identity.leadId,
              identity.idempotencyKeyHash,
              exactLead.contactName,
              identity.companyName,
              exactLead.phoneE164,
            ],
          );
        }
        const after = validateCandidateLeadRow(await candidateLeadRow(), identity);
        return Object.freeze({
          leadId: after.id,
          stateSha256: digest({
            idempotencyKeyHash: identity.idempotencyKeyHash,
            leadId: after.id,
            synthetic: true,
            syntheticMarkerSha256: input.syntheticMarkerSha256,
          }),
          synthetic: true,
        });
      },
      async inspectFlow(input) {
        exactObject(
          input,
          ["databaseId", "leadId", "syntheticMarkerSha256", "testRunId"],
          "candidate D1 flow inspection",
        );
        if (
          input.databaseId !== databaseId ||
          input.leadId !== identity.leadId ||
          input.testRunId !== testRunId ||
          !digestPattern.test(input.syntheticMarkerSha256)
        ) {
          throw new Error("candidate D1 flow identity changed");
        }
        const result = await d1Query(
          cloudflareClient,
          accountId,
          databaseId,
          `SELECT l.id, l.idempotency_key_hash, l.contact_name, l.company_name,
                  l.phone_e164, l.segment,
                  COALESCE(l.towel_interest_v2, l.towel_interest) AS towel_interest,
                  l.service_area,
                  COALESCE(l.weekly_quantity_estimate, l.weekly_quantity) AS weekly_quantity,
                  l.message, l.source_path, l.form_version, l.status, l.version,
                  l.synthetic, l.relationship_status, l.anonymized_at,
                  o.id AS outbox_id, o.status AS outbox_status,
                  o.provider_message_id, o.provider_message_id_sha256,
                  o.request_body, o.request_body_sha256
           FROM leads AS l
           JOIN notification_outbox AS o
             ON o.lead_id = l.id AND o.kind = 'new_lead_email'
           WHERE l.id = ?1 LIMIT 2`,
          [identity.leadId],
        );
        if (result.results.length !== 1) {
          throw new Error("candidate D1 flow is absent or ambiguous");
        }
        const row = validateCandidateLeadRow(result.results[0], identity);
        const requestSnapshot = parseRequestSnapshot(row.request_body, candidateExpected);
        if (
          row.request_body_sha256 !== sha256(Buffer.from(row.request_body, "utf8")) ||
          !/^mail_[a-f0-9]{32}$/.test(row.outbox_id ?? "") ||
          !["pending", "processing", "sent", "failed", "dead"].includes(
            row.outbox_status,
          ) ||
          (row.provider_message_id !== null &&
            (!providerIdPattern.test(row.provider_message_id) ||
              row.provider_message_id_sha256 !==
                sha256(Buffer.from(row.provider_message_id, "utf8"))))
        ) {
          throw new Error("candidate D1 outbox state changed");
        }
        let delivery = null;
        if (row.provider_message_id !== null) {
          const deliveryResult = await d1Query(
            cloudflareClient,
            accountId,
            databaseId,
            `SELECT id, provider_message_id, delivery_status,
                    provider_created_at, received_at
             FROM notification_delivery_events
             WHERE provider_message_id = ?1
             ORDER BY provider_created_at DESC, id DESC LIMIT 1`,
            [row.provider_message_id],
          );
          if (deliveryResult.results.length === 1) {
            const event = deliveryResult.results[0];
            if (
              event.provider_message_id !== row.provider_message_id ||
              typeof event.id !== "string" ||
              event.id.length < 1 ||
              event.id.length > 512
            ) {
              throw new Error("candidate D1 delivery event changed");
            }
            delivery = Object.freeze({
              eventIdSha256: sha256(Buffer.from(event.id, "utf8")),
              providerCreatedAt: canonicalProviderInstant(
                event.provider_created_at,
                "candidate provider-created time",
              ),
              providerMessageIdSha256: sha256(
                Buffer.from(row.provider_message_id, "utf8"),
              ),
              receivedAt: canonicalProviderInstant(
                event.received_at,
                "candidate delivery received time",
              ),
              status: event.delivery_status,
            });
          } else if (deliveryResult.results.length > 1) {
            throw new Error("candidate D1 delivery event is ambiguous");
          }
        }
        return Object.freeze({
          databaseId,
          delivery,
          lead: Object.freeze({
            id: row.id,
            sourcePath: row.source_path,
            status: row.status,
            synthetic: row.synthetic === 1,
            syntheticMarkerSha256: input.syntheticMarkerSha256,
            version: row.version,
          }),
          outbox: Object.freeze({
            id: row.outbox_id,
            providerMessageId: row.provider_message_id,
            providerMessageIdSha256:
              row.provider_message_id === null
                ? null
                : sha256(Buffer.from(row.provider_message_id, "utf8")),
            recipientSha256: sha256(
              Buffer.from(requestSnapshot.to[0], "utf8"),
            ),
            senderSha256: sha256(
              Buffer.from(senderAddress(requestSnapshot.from), "utf8"),
            ),
            status: row.outbox_status,
          }),
          testRunId,
        });
      },
    }),
    resend: Object.freeze({
      async inspectEmail(input) {
        exactObject(input, ["messageId"], "candidate Resend inspection");
        if (!providerIdPattern.test(input.messageId ?? "")) {
          throw new Error("candidate Resend message ID is invalid");
        }
        const response = await request(
          resendAdminClient,
          "GET",
          `/emails/${input.messageId}`,
        );
        const value = response.result;
        if (
          value?.id !== input.messageId ||
          senderAddress(value?.from) !== candidateExpected.notificationSender ||
          !Array.isArray(value?.to) ||
          value.to.length !== 1 ||
          value.to[0] !== candidateExpected.notificationRecipient
        ) {
          throw new Error("candidate Resend message identity changed");
        }
        return Object.freeze({
          createdAt: canonicalProviderInstant(
            value.created_at,
            "candidate Resend created time",
          ),
          from: senderAddress(value.from),
          id: value.id,
          lastEvent: value.last_event,
          to: Object.freeze([...value.to]),
        });
      },
    }),
    lifecycle: Object.freeze({
      async transition(input) {
        exactObject(
          input,
          [
            "actorSubjectSha256",
            "changedAt",
            "databaseId",
            "expectedVersion",
            "fromStatus",
            "leadId",
            "releaseBindingSha256",
            "testRunId",
            "toStatus",
          ],
          "candidate lifecycle transition",
        );
        const next = { new: "in_progress", in_progress: "answered", answered: "archived" };
        if (
          input.databaseId !== databaseId ||
          input.leadId !== identity.leadId ||
          input.releaseBindingSha256 !== releaseBindingSha256 ||
          input.testRunId !== testRunId ||
          next[input.fromStatus] !== input.toStatus ||
          !Number.isSafeInteger(input.expectedVersion) ||
          input.expectedVersion < 1 ||
          !digestPattern.test(input.actorSubjectSha256) ||
          canonicalProviderInstant(input.changedAt, "candidate lifecycle time") !==
            input.changedAt
        ) {
          throw new Error("candidate lifecycle transition identity changed");
        }
        const current = validateCandidateLeadRow(await candidateLeadRow(), identity);
        if (
          current.status !== input.fromStatus ||
          current.version !== input.expectedVersion
        ) {
          throw new Error("candidate lifecycle precondition changed");
        }
        await d1Query(
          cloudflareClient,
          accountId,
          databaseId,
          `UPDATE leads
           SET status = ?1, version = version + 1,
               updated_at = MAX(updated_at, ?2)
           WHERE id = ?3 AND version = ?4 AND status = ?5 AND synthetic = 1`,
          [
            input.toStatus,
            input.changedAt,
            input.leadId,
            input.expectedVersion,
            input.fromStatus,
          ],
        );
        const version = input.expectedVersion + 1;
        const eventId = `${input.leadId}:status:${version}`;
        await d1Query(
          cloudflareClient,
          accountId,
          databaseId,
          `INSERT OR IGNORE INTO lead_status_events (
             id, lead_id, from_status, to_status, changed_at, actor_subject
           )
           SELECT ?1, id, ?2, ?3, updated_at, ?4
           FROM leads
           WHERE id = ?5 AND version = ?6 AND status = ?3 AND synthetic = 1`,
          [
            eventId,
            input.fromStatus,
            input.toStatus,
            `release-candidate:${input.actorSubjectSha256}`,
            input.leadId,
            version,
          ],
        );
        const after = validateCandidateLeadRow(await candidateLeadRow(), identity);
        const event = await d1Query(
          cloudflareClient,
          accountId,
          databaseId,
          `SELECT id, lead_id, from_status, to_status, changed_at, actor_subject
           FROM lead_status_events WHERE id = ?1 LIMIT 2`,
          [eventId],
        );
        if (
          after.status !== input.toStatus ||
          after.version !== version ||
          event.results.length !== 1 ||
          event.results[0]?.lead_id !== input.leadId ||
          event.results[0]?.from_status !== input.fromStatus ||
          event.results[0]?.to_status !== input.toStatus ||
          event.results[0]?.actor_subject !==
            `release-candidate:${input.actorSubjectSha256}`
        ) {
          throw new Error("candidate lifecycle transition did not converge");
        }
        return Object.freeze({
          eventIdSha256: sha256(Buffer.from(eventId, "utf8")),
          fromStatus: input.fromStatus,
          leadId: input.leadId,
          previousVersion: input.expectedVersion,
          stateSha256: digest({
            actorSubjectSha256: input.actorSubjectSha256,
            eventIdSha256: sha256(Buffer.from(eventId, "utf8")),
            fromStatus: input.fromStatus,
            leadIdSha256: sha256(Buffer.from(input.leadId, "utf8")),
            toStatus: input.toStatus,
            version,
          }),
          toStatus: input.toStatus,
          version,
        });
      },
    }),
  });
}

export const productionCandidateProviderAdapterConstants = Object.freeze({
  activationPatterns,
  candidatePatterns,
  exactLead,
  expectedOrigin,
});
