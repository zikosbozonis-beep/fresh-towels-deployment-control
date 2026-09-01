import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  materializeProductionCapsule,
  validateProductionCapsuleContents,
} from "../scripts/production-capsule.mjs";
import { sha256 } from "../scripts/control-contract.mjs";

function treeSha256(entries) {
  const hash = createHash("sha256");
  for (const entry of entries) {
    hash.update(entry.path);
    hash.update("\0");
    hash.update(String(entry.bytes));
    hash.update("\0");
    hash.update(entry.sha256);
    hash.update("\0");
  }
  return hash.digest("hex");
}

function runtimeVariables() {
  return {
    NEXT_PUBLIC_SITE_ENV: "production",
    PRODUCTION_CANONICAL_URL: "https://freshtowels.gr",
    PRODUCTION_VERSION_PREVIEW_URL_SUFFIX:
      "__FRESH_TOWELS_WORKERS_DEV_PREVIEW_SUFFIX__",
    LEAD_NOTIFICATION_MODE: "resend",
    LEAD_NOTIFICATION_TO: "info@freshtowels.gr",
    RESEND_FROM: "Fresh Towels <notifications@notify.freshtowels.gr>",
    LEAD_CONSENT_VERSION: "privacy-2026-09-01",
    LEAD_ANTISPAM_MODE: "honeypot_rate_limit",
    CLOUDFLARE_ACCESS_AUD: "__FRESH_TOWELS_ACCESS_AUD__",
    CLOUDFLARE_ACCESS_TEAM_DOMAIN: "__FRESH_TOWELS_ACCESS_TEAM_DOMAIN__",
    PRODUCTION_INFRASTRUCTURE_RECEIPT_SHA256: "6".repeat(64),
    PRODUCTION_RELEASE_READY: "confirmed",
    PRODUCTION_DATABASE_READY: "confirmed",
    PRODUCTION_D1_BACKUP_READY: "confirmed",
    PRODUCTION_DASHBOARD_AUTH_READY: "confirmed",
    PRODUCTION_ACCESS_POLICY_VERIFIED: "confirmed",
    PRODUCTION_EMAIL_DOMAIN_VERIFIED: "confirmed",
    PRODUCTION_RESEND_WEBHOOK_REGISTERED: "confirmed",
    PRODUCTION_PRIVACY_LEGAL_APPROVED: "confirmed",
    PRODUCTION_LAUNCH_MEDIA_APPROVED: "confirmed",
    PRODUCTION_REDIRECT_CANDIDATE_VERIFIED: "confirmed",
    PRODUCTION_WORKERS_DEV_DISABLED: "confirmed",
    PRODUCTION_CUTOVER_APPROVED: "confirmed",
  };
}

function entry(path, content) {
  const buffer = Buffer.from(content);
  return {
    path: ".wrangler/production-upload/" + path,
    bytes: buffer.byteLength,
    sha256: sha256(buffer),
    encoding: "base64",
    content: buffer.toString("base64"),
  };
}

function fixture() {
  const releaseIntegrity = {
    buildArtifactSha256: "a".repeat(64),
    databaseSchemaSha256: "b".repeat(64),
    releaseApprovalManifestSha256: "c".repeat(64),
    configurationTemplateSha256: "",
    uploadArtifactSha256: "",
    capsuleTreeSha256: "",
    productionInfrastructureReceiptSha256: "6".repeat(64),
  };
  const configuration = {
    name: "fresh-towels-production",
    account_id: "__FRESH_TOWELS_CLOUDFLARE_ACCOUNT_ID__",
    main: "./worker/index.js",
    compatibility_date: "2026-08-28",
    compatibility_flags: ["nodejs_compat"],
    vars: runtimeVariables(),
    workers_dev: false,
    preview_urls: false,
    assets: {
      directory: "./assets",
      run_worker_first: [
        "/internal/leads",
        "/internal/leads/*",
        "/api/internal/*",
        "/api/leads",
        "/api/webhooks/resend",
      ],
    },
    d1_databases: [
      {
        binding: "LEADS_DB",
        database_name: "fresh-towels-leads-prod",
        database_id: "__FRESH_TOWELS_PRODUCTION_D1_ID__",
        migrations_dir: "./migrations",
        migrations_table: "d1_migrations",
      },
    ],
    triggers: { crons: ["*/5 * * * *"] },
    observability: {
      enabled: true,
      logs: { enabled: true, invocation_logs: true, persist: true },
    },
  };
  const payloadEntries = [
    entry("assets/index.html", "<main>synthetic</main>\n"),
    entry("migrations/0001_init.sql", "CREATE TABLE synthetic(id INTEGER);\n"),
    entry("schema-version.json", JSON.stringify({ currentLeadSchemaVersion: 1 }, null, 2) + "\n"),
    entry("worker/index.js", 'export default {fetch(){return new Response("ok")}};\n'),
    entry("wrangler.template.jsonc", JSON.stringify(configuration, null, 2) + "\n"),
  ].sort((left, right) => left.path.localeCompare(right.path, "en"));
  const stripped = payloadEntries.map((value) => ({
    path: value.path.slice(".wrangler/production-upload/".length),
    bytes: value.bytes,
    sha256: value.sha256,
  }));
  const assets = stripped.filter((value) => value.path.startsWith("assets/"));
  const database = stripped.filter(
    (value) => value.path === "schema-version.json" || value.path.startsWith("migrations/"),
  );
  releaseIntegrity.uploadArtifactSha256 = treeSha256(stripped);
  const manifest = {
    schemaVersion: 2,
    artifactType: "fresh-towels-cloudflare-immutable-upload",
    wranglerVersion: "4.127.1",
    sourceIntegrity: {
      buildArtifactSha256: releaseIntegrity.buildArtifactSha256,
      databaseSchemaSha256: releaseIntegrity.databaseSchemaSha256,
      releaseApprovalManifestSha256: releaseIntegrity.releaseApprovalManifestSha256,
      productionInfrastructureReceiptSha256:
        releaseIntegrity.productionInfrastructureReceiptSha256,
    },
    workerModuleSha256: stripped.find((value) => value.path === "worker/index.js").sha256,
    staticAssetsTreeSha256: treeSha256(assets),
    databasePayloadTreeSha256: treeSha256(database),
    configurationTemplateSha256: stripped.find(
      (value) => value.path === "wrangler.template.jsonc",
    ).sha256,
    uploadTreeSha256: releaseIntegrity.uploadArtifactSha256,
    fileCount: stripped.length,
    totalBytes: stripped.reduce((total, value) => total + value.bytes, 0),
    deployContract: {
      command: "wrangler versions upload",
      configurationMaterialization: "protected-infrastructure-receipt-v1",
      noBundleRequired: true,
      secretsFileRequired: true,
    },
  };
  releaseIntegrity.configurationTemplateSha256 = manifest.configurationTemplateSha256;
  const entries = [
    ...payloadEntries,
    entry("upload-manifest.json", JSON.stringify(manifest, null, 2) + "\n"),
  ].sort((left, right) => left.path.localeCompare(right.path, "en"));
  releaseIntegrity.capsuleTreeSha256 = treeSha256(entries);
  const capsule = {
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
      workflowRef:
        "zikosbozonis-beep/fresh-towels-deployment-control/.github/workflows/package-release.yml@" +
        "2".repeat(40),
    },
    createdAt: "2026-09-01T09:59:00.000Z",
    operation: "production-release",
    payload: {
      encoding: "base64-per-file",
      rawBytes: entries.reduce((total, value) => total + value.bytes, 0),
      fileCount: entries.length,
      entries,
    },
    releaseId: "",
    releaseIntegrity,
    releasePrerequisite: {
      requestId: "77777777-7777-4777-8777-777777777777",
      receiptSha256: "8".repeat(64),
      runId: "33524593667",
    },
    schemaVersion: 2,
    capsuleType: "fresh-towels-private-release-capsule",
    validUntil: "2026-09-01T11:59:00.000Z",
  };
  capsule.releaseId = sha256(
    Buffer.from(
      [
        capsule.application.commitSha,
        capsule.controller.commitSha,
        capsule.operation,
        capsule.releaseIntegrity.buildArtifactSha256,
        capsule.releaseIntegrity.uploadArtifactSha256,
        capsule.releaseIntegrity.productionInfrastructureReceiptSha256,
        capsule.releasePrerequisite.requestId,
        capsule.releasePrerequisite.receiptSha256,
        capsule.releasePrerequisite.runId,
        capsule.application.runId,
        capsule.application.runAttempt,
        capsule.createdAt,
      ].join("\0"),
    ),
  );
  return capsule;
}

function bytes(capsule) {
  return Buffer.from(JSON.stringify(capsule) + "\n");
}

test("validates every production entry, manifest, upload tree, config, and migration semantic", () => {
  const capsule = fixture();
  const result = validateProductionCapsuleContents(capsule, bytes(capsule));
  assert.equal(result.release.releaseId, capsule.releaseId);
  assert.equal(result.manifest.wranglerVersion, "4.127.1");
  assert.equal(result.configurationTemplate.workerName, "fresh-towels-production");
  assert.equal(result.database.currentLeadSchemaVersion, 1);
  assert.equal(result.entries.length, 6);
  assert.ok(!Object.values(result.configurationTemplate).includes("info@freshtowels.gr"));
});

test("materializes a digest-verified private regular-file tree without executing Worker code", async () => {
  const root = await mkdtemp(join(tmpdir(), "controller-capsule-parent-"));
  const output = resolve(root, "verified");
  const capsule = fixture();
  const worker = capsule.payload.entries.find((value) => value.path.endsWith("worker/index.js"));
  const inert = Buffer.from('throw new Error("payload must never execute during materialization");\n');
  worker.bytes = inert.length;
  worker.sha256 = sha256(inert);
  worker.content = inert.toString("base64");

  const manifestEntry = capsule.payload.entries.find((value) =>
    value.path.endsWith("upload-manifest.json"),
  );
  const manifest = JSON.parse(Buffer.from(manifestEntry.content, "base64"));
  manifest.workerModuleSha256 = worker.sha256;
  const stripped = capsule.payload.entries
    .filter((value) => !value.path.endsWith("upload-manifest.json"))
    .map((value) => ({
      path: value.path.slice(".wrangler/production-upload/".length),
      bytes: value.bytes,
      sha256: value.sha256,
    }));
  manifest.uploadTreeSha256 = treeSha256(stripped);
  manifest.totalBytes = stripped.reduce((total, value) => total + value.bytes, 0);
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n");
  manifestEntry.bytes = manifestBytes.length;
  manifestEntry.sha256 = sha256(manifestBytes);
  manifestEntry.content = manifestBytes.toString("base64");
  capsule.releaseIntegrity.uploadArtifactSha256 = manifest.uploadTreeSha256;
  capsule.releaseIntegrity.capsuleTreeSha256 = treeSha256(capsule.payload.entries);
  capsule.payload.rawBytes = capsule.payload.entries.reduce((total, value) => total + value.bytes, 0);
  capsule.releaseId = sha256(
    Buffer.from(
      [
        capsule.application.commitSha,
        capsule.controller.commitSha,
        capsule.operation,
        capsule.releaseIntegrity.buildArtifactSha256,
        capsule.releaseIntegrity.uploadArtifactSha256,
        capsule.releaseIntegrity.productionInfrastructureReceiptSha256,
        capsule.releasePrerequisite.requestId,
        capsule.releasePrerequisite.receiptSha256,
        capsule.releasePrerequisite.runId,
        capsule.application.runId,
        capsule.application.runAttempt,
        capsule.createdAt,
      ].join("\0"),
    ),
  );
  try {
    const result = await materializeProductionCapsule({
      capsule,
      rawPayload: bytes(capsule),
      outputRoot: output,
    });
    assert.equal(
      await readFile(resolve(output, "worker/index.js"), "utf8"),
      inert.toString(),
    );
    for (const file of result.files) {
      const status = await lstat(resolve(output, file.path));
      assert.equal(status.isFile(), true);
      assert.equal(status.isSymbolicLink(), false);
      assert.equal(status.nlink, 1);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects traversal, separators, duplicates, unsorted paths, and pre-existing/symlink roots", async () => {
  for (const badPath of [
    ".wrangler/production-upload/../worker/index.js",
    ".wrangler/production-upload/assets\\index.html",
    ".wrangler/production-upload/assets/%2e%2e/index.html",
    ".wrangler/production-upload/private/source.js",
  ]) {
    const capsule = fixture();
    capsule.payload.entries[0].path = badPath;
    assert.throws(() => validateProductionCapsuleContents(capsule), /path|allowlist/);
  }
  {
    const capsule = fixture();
    capsule.payload.entries[1].path = capsule.payload.entries[0].path;
    assert.throws(() => validateProductionCapsuleContents(capsule), /unique|sorted/);
  }
  {
    const capsule = fixture();
    capsule.payload.entries.reverse();
    assert.throws(() => validateProductionCapsuleContents(capsule), /sorted/);
  }
  const root = await mkdtemp(join(tmpdir(), "controller-existing-"));
  try {
    await assert.rejects(
      materializeProductionCapsule({
        capsule: fixture(),
        rawPayload: bytes(fixture()),
        outputRoot: root,
      }),
      /must not already exist/,
    );
    const link = root + "-link";
    await symlink(root, link, "junction");
    try {
      await assert.rejects(
        materializeProductionCapsule({
          capsule: fixture(),
          rawPayload: bytes(fixture()),
          outputRoot: link,
        }),
        /must not already exist/,
      );
    } finally {
      await rm(link, { force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects non-canonical base64, changed bytes/counts/hashes and tree substitution", () => {
  const mutations = [
    (capsule) => {
      capsule.payload.entries[0].content += "\n";
    },
    (capsule) => {
      capsule.payload.entries[0].content = capsule.payload.entries[0].content.slice(0, -1) + "A";
    },
    (capsule) => {
      capsule.payload.entries[0].bytes += 1;
    },
    (capsule) => {
      capsule.payload.entries[0].sha256 = "0".repeat(64);
    },
    (capsule) => {
      capsule.payload.rawBytes += 1;
    },
    (capsule) => {
      capsule.releaseIntegrity.capsuleTreeSha256 = "0".repeat(64);
    },
    (capsule) => {
      capsule.releaseIntegrity.uploadArtifactSha256 = "0".repeat(64);
    },
  ];
  for (const mutate of mutations) {
    const capsule = fixture();
    mutate(capsule);
    assert.throws(
      () => validateProductionCapsuleContents(capsule),
      /base64|bytes|byte total|digest|tree|binding/,
    );
  }
});

test("rejects upload-manifest and Wrangler semantic drift even when local hashes are recomputed", () => {
  const capsule = fixture();
  const configEntry = capsule.payload.entries.find((value) =>
    value.path.endsWith("wrangler.template.jsonc"),
  );
  const configuration = JSON.parse(Buffer.from(configEntry.content, "base64"));
  configuration.workers_dev = true;
  const configBytes = Buffer.from(JSON.stringify(configuration, null, 2) + "\n");
  configEntry.bytes = configBytes.length;
  configEntry.sha256 = sha256(configBytes);
  configEntry.content = configBytes.toString("base64");
  const manifestEntry = capsule.payload.entries.find((value) =>
    value.path.endsWith("upload-manifest.json"),
  );
  const manifest = JSON.parse(Buffer.from(manifestEntry.content, "base64"));
  manifest.configurationTemplateSha256 = configEntry.sha256;
  capsule.releaseIntegrity.configurationTemplateSha256 = configEntry.sha256;
  const stripped = capsule.payload.entries
    .filter((value) => !value.path.endsWith("upload-manifest.json"))
    .map((value) => ({
      path: value.path.slice(".wrangler/production-upload/".length),
      bytes: value.bytes,
      sha256: value.sha256,
    }));
  manifest.uploadTreeSha256 = treeSha256(stripped);
  manifest.totalBytes = stripped.reduce((total, value) => total + value.bytes, 0);
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n");
  manifestEntry.bytes = manifestBytes.length;
  manifestEntry.sha256 = sha256(manifestBytes);
  manifestEntry.content = manifestBytes.toString("base64");
  capsule.payload.rawBytes = capsule.payload.entries.reduce((total, value) => total + value.bytes, 0);
  capsule.releaseIntegrity.uploadArtifactSha256 = manifest.uploadTreeSha256;
  capsule.releaseIntegrity.capsuleTreeSha256 = treeSha256(capsule.payload.entries);
  capsule.releaseId = sha256(
    Buffer.from(
      [
        capsule.application.commitSha,
        capsule.controller.commitSha,
        capsule.operation,
        capsule.releaseIntegrity.buildArtifactSha256,
        capsule.releaseIntegrity.uploadArtifactSha256,
        capsule.releaseIntegrity.productionInfrastructureReceiptSha256,
        capsule.releasePrerequisite.requestId,
        capsule.releasePrerequisite.receiptSha256,
        capsule.releasePrerequisite.runId,
        capsule.application.runId,
        capsule.application.runAttempt,
        capsule.createdAt,
      ].join("\0"),
    ),
  );
  assert.throws(
    () => validateProductionCapsuleContents(capsule, bytes(capsule)),
    /runtime mode/,
  );
});
