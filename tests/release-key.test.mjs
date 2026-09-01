import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256 } from "../scripts/control-contract.mjs";

const expectedPublicKeySha256 =
  "ed4ee4390fd2def7ac4180c57862cd2f1b91f4276440ba5ad401639af32ed566";

function keyRecords(listing) {
  const records = [];
  let current;
  for (const line of listing.split("\n")) {
    const fields = line.split(":");
    if (["pub", "sub"].includes(fields[0])) {
      current = { capabilities: (fields[11] ?? "").toLowerCase(), record: fields[0] };
    } else if (fields[0] === "fpr" && current) {
      records.push({ ...current, fingerprint: fields[9] });
      current = undefined;
    }
  }
  return records;
}

test("pinned release key has one exact primary and encryption subkey", async () => {
  const [publicKey, primaryFingerprint, encryptionSubkeyFingerprint] = await Promise.all([
    readFile(new URL("../keys/release-encryption-public.asc", import.meta.url)),
    readFile(new URL("../keys/release-encryption-fingerprint.txt", import.meta.url), "utf8").then(
      (value) => value.trim(),
    ),
    readFile(
      new URL("../keys/release-encryption-subkey-fingerprint.txt", import.meta.url),
      "utf8",
    ).then((value) => value.trim()),
  ]);
  assert.equal(sha256(publicKey), expectedPublicKeySha256);
  const listing = spawnSync(
    "gpg",
    [
      "--batch",
      "--with-colons",
      "--import-options",
      "show-only",
      "--import",
      fileURLToPath(new URL("../keys/release-encryption-public.asc", import.meta.url)),
    ],
    { encoding: "utf8", windowsHide: true },
  );
  assert.equal(listing.status, 0);
  const records = keyRecords(listing.stdout);
  assert.deepEqual(
    records.filter((record) => record.record === "pub").map((record) => record.fingerprint),
    [primaryFingerprint],
  );
  assert.deepEqual(
    records
      .filter((record) => record.record === "sub" && record.capabilities.includes("e"))
      .map((record) => record.fingerprint),
    [encryptionSubkeyFingerprint],
  );
});

test("packaging and protected execution both enforce the exact GPG proof path", async () => {
  const [packaging, executor] = await Promise.all([
    readFile(new URL("../.github/workflows/package-release.yml", import.meta.url), "utf8"),
    readFile(new URL("../.github/workflows/execute-release.yml", import.meta.url), "utf8"),
  ]);
  assert.match(packaging, /release-encryption-subkey-fingerprint\.txt/);
  assert.match(packaging, /--recipient "\$\{encryption_fingerprint\}!"/);
  assert.match(executor, /name: Prove exact protected GPG pair offline/);
  assert.match(executor, /node scripts\/gpg-offline-proof\.mjs/);
  assert.ok(
    executor.indexOf("Prove exact protected GPG pair offline") <
      executor.indexOf("Atomically claim this exact execution"),
  );
});
