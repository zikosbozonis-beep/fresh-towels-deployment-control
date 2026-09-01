import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const sourceUrl = new URL("../scripts/run-production-release.mjs", import.meta.url);

test("release runner consumes the exact bootstrap prerequisite before provider construction", async () => {
  const source = await readFile(sourceUrl, "utf8");
  const materialize = source.indexOf('binding: "PRODUCTION_INFRASTRUCTURE_RECEIPT"');
  const verify = source.indexOf("await verifyPrerequisite(");
  const cloudflare = source.indexOf("createCloudflareHttpAdapter(");
  const execute = source.indexOf("executeProductionReleaseAdapter(");
  assert.ok(materialize >= 0 && verify > materialize && cloudflare > verify && execute > cloudflare);
  assert.doesNotMatch(source, /console\.(?:log|error)\([^\n]*(?:TOKEN|PRIVATE_KEY|PASSPHRASE)/);
  assert.match(source, /protected pre-cutover routes; hash-only evidence written/);
});

test("release runner has no application-code execution or post-approval build path", async () => {
  const source = await readFile(sourceUrl, "utf8");
  assert.doesNotMatch(source, /npm\s+(?:run\s+)?build|vite\s+build|import\([^)]*worker|node\s+.*worker\/index/);
  assert.match(source, /materializeProductionCapsule/);
  assert.match(source, /recoveryBackupSink/);
  assert.match(source, /receipt_sha256=/);
});

test("release runner stores the exact private candidate package only after E2E completion", async () => {
  const source = await readFile(sourceUrl, "utf8");
  const executeCandidate = source.indexOf("await executeProductionCandidateE2e(");
  const createPrivatePackage = source.indexOf(
    "createProductionReleaseCandidateReceipt({",
  );
  const storePrivatePackage = source.indexOf(
    "custody.productionReleaseReceiptSink.store({",
  );
  const zeroPrivateBytes = source.indexOf("package_.bytes.fill(0)");
  assert.ok(
    executeCandidate >= 0 &&
      createPrivatePackage > executeCandidate &&
      storePrivatePackage > createPrivatePackage &&
      zeroPrivateBytes > storePrivatePackage,
  );
  assert.match(source, /candidate\.routes\.preCutoverStateSha256/);
  assert.match(source, /candidate\.lifecycle\.finalStateSha256/);
  assert.match(source, /candidate\.resend\.deliveryStateSha256/);
  assert.doesNotMatch(source, /writeFile\([^\n]*package_\.(?:bytes|receipt)/);
});
