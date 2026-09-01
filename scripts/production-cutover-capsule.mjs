import { canonicalJson, sha256 } from "./control-contract.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const decimalPattern = /^[1-9][0-9]{0,19}$/;
const candidateRoutes = Object.freeze([
  "freshtowels.gr/api/internal/*",
  "freshtowels.gr/api/leads",
  "freshtowels.gr/api/webhooks/resend",
  "freshtowels.gr/internal/leads",
  "freshtowels.gr/internal/leads/*",
]);
const preCutoverRoutes = Object.freeze([
  "freshtowels.gr/api/internal/*",
  "freshtowels.gr/internal/leads",
  "freshtowels.gr/internal/leads/*",
]);
const liveRoutes = Object.freeze(["freshtowels.gr/*", "www.freshtowels.gr/*"]);

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

function instant(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error(label + " is not a canonical UTC instant");
  }
  return parsed;
}

export function validateProductionCutoverCapsule(capsule, bytes) {
  exactObject(
    capsule,
    [
      "application",
      "capsuleType",
      "controller",
      "createdAt",
      "cutover",
      "operation",
      "schemaVersion",
      "validUntil",
    ],
    "production cutover capsule",
  );
  exactObject(
    capsule.cutover,
    ["cutoverId", "intent", "prerequisite", "safeguards", "targets"],
    "production cutover declaration",
  );
  exactObject(
    capsule.cutover.prerequisite,
    ["requestId", "runId", "receiptSha256", "completedAt"],
    "production cutover prerequisite",
  );
  exactObject(
    capsule.cutover.targets,
    ["zone", "worker", "candidateRoutes", "preCutoverRoutes", "liveRoutes"],
    "production cutover targets",
  );
  exactObject(
    capsule.cutover.safeguards,
    [
      "exactPrerequisiteRequired",
      "accessOwnerLoginRequired",
      "candidateEmailDeliveryRequired",
      "rollbackToPreCutoverRoutesRequired",
      "legacyWordPressPreserved",
      "productionTrafficMutationAuthorized",
    ],
    "production cutover safeguards",
  );
  const prerequisite = capsule.cutover.prerequisite;
  const targets = capsule.cutover.targets;
  const safeguards = capsule.cutover.safeguards;
  const completedAt = instant(prerequisite.completedAt, "production cutover prerequisite time");
  const createdAt = instant(capsule.createdAt, "production cutover creation time");
  if (
    capsule.schemaVersion !== 1 ||
    capsule.capsuleType !== "fresh-towels-production-cutover-capsule" ||
    capsule.operation !== "production-cutover" ||
    capsule.cutover.intent !== "activate-exact-qualified-release-with-automatic-route-rollback" ||
    !digestPattern.test(capsule.cutover.cutoverId ?? "") ||
    !uuidPattern.test(prerequisite.requestId ?? "") ||
    !decimalPattern.test(prerequisite.runId ?? "") ||
    !digestPattern.test(prerequisite.receiptSha256 ?? "") ||
    completedAt > createdAt + 60_000 ||
    targets.zone !== "freshtowels.gr" ||
    targets.worker !== "fresh-towels-production" ||
    canonicalJson(targets.candidateRoutes) !== canonicalJson(candidateRoutes) ||
    canonicalJson(targets.preCutoverRoutes) !== canonicalJson(preCutoverRoutes) ||
    canonicalJson(targets.liveRoutes) !== canonicalJson(liveRoutes) ||
    Object.values(safeguards).some((value) => value !== true)
  ) {
    throw new Error("production cutover declaration is invalid");
  }
  const expectedId = sha256(
    Buffer.from(
      canonicalJson({
        application: capsule.application,
        controller: capsule.controller,
        createdAt: capsule.createdAt,
        prerequisite,
        safeguards,
        targets,
      }),
      "utf8",
    ),
  );
  if (capsule.cutover.cutoverId !== expectedId) {
    throw new Error("production cutover identity is not exact");
  }
  const canonical = Buffer.from(canonicalJson(capsule) + "\n", "utf8");
  if (!Buffer.from(bytes).equals(canonical) || canonical.byteLength > 8192) {
    throw new Error("production cutover capsule is not canonical or exceeds its boundary");
  }
  return capsule;
}

export const productionCutoverCapsuleConstants = Object.freeze({
  candidateRoutes,
  preCutoverRoutes,
  liveRoutes,
});
