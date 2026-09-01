import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "../scripts/control-contract.mjs";
import { decryptBoundCiphertext } from "../scripts/protected-transport.mjs";

const linuxWithGpg =
  process.platform === "linux" &&
  spawnSync("gpg", ["--version"], { encoding: "utf8" }).status === 0;

function runGpg(home, arguments_, input) {
  return spawnSync("gpg", ["--batch", "--no-tty", "--homedir", home, ...arguments_], {
    encoding: arguments_.includes("--armor") || arguments_.includes("--with-colons")
      ? "utf8"
      : undefined,
    env: { GNUPGHOME: home, HOME: home, PATH: process.env.PATH },
    input,
    maxBuffer: 8 * 1024 * 1024,
  });
}

function requireSuccess(result, label) {
  assert.equal(result.status, 0, label);
}

function fingerprints(listing) {
  const result = [];
  let current;
  for (const line of listing.split("\n")) {
    const fields = line.split(":");
    if (["sec", "ssb"].includes(fields[0])) {
      current = { capabilities: (fields[11] ?? "").toLowerCase(), record: fields[0] };
    } else if (fields[0] === "fpr" && current) {
      result.push({ ...current, fingerprint: fields[9] });
      current = undefined;
    }
  }
  return result;
}

function environmentFor(privateKey, passphrase) {
  const canonical = `${privateKey.trim().replaceAll("\r\n", "\n")}\n`;
  return {
    RELEASE_DECRYPTION_PASSPHRASE: passphrase,
    RELEASE_DECRYPTION_PASSPHRASE_SHA256: sha256(Buffer.from(passphrase)),
    RELEASE_DECRYPTION_PRIVATE_KEY: canonical.replaceAll("\n", "\r\n").trimEnd(),
    RELEASE_DECRYPTION_PRIVATE_KEY_SHA256: sha256(Buffer.from(canonical)),
  };
}

function killAgent(home) {
  spawnSync("gpgconf", ["--homedir", home, "--kill", "all"], {
    stdio: "ignore",
  });
}

test(
  "fresh Ubuntu GPG home proves the protected secret representation cryptographically",
  { skip: !linuxWithGpg, timeout: 120_000 },
  async () => {
    const root = await mkdtemp(join(tmpdir(), "deployment-control-gpg-roundtrip-"));
    const generationHome = join(root, "generation");
    const encryptionHome = join(root, "encryption");
    const wrongRoot = join(root, "wrong-passphrase-proof");
    const correctRoot = join(root, "correct-passphrase-proof");
    const passphrase = "synthetic-offline-roundtrip-passphrase-2026";
    const wrongPassphrase = `${passphrase}-wrong`;
    try {
      await mkdir(generationHome, { mode: 0o700 });
      await mkdir(encryptionHome, { mode: 0o700 });
      await mkdir(wrongRoot, { mode: 0o700 });
      await mkdir(correctRoot, { mode: 0o700 });

      const generated = runGpg(
        generationHome,
        [
          "--pinentry-mode",
          "loopback",
          "--passphrase-fd",
          "0",
          "--quick-generate-key",
          "Deployment Control Synthetic Round Trip",
          "rsa2048",
          "cert",
          "1d",
        ],
        `${passphrase}\n`,
      );
      requireSuccess(generated, "synthetic primary key generation failed");
      const primaryListing = runGpg(
        generationHome,
        ["--with-colons", "--list-secret-keys", "--fingerprint", "--fingerprint"],
      );
      requireSuccess(primaryListing, "synthetic primary key inspection failed");
      const primaryFingerprint = fingerprints(primaryListing.stdout).find(
        (record) => record.record === "sec",
      )?.fingerprint;
      assert.match(primaryFingerprint, /^[A-F0-9]{40}$/);

      const added = runGpg(
        generationHome,
        [
          "--pinentry-mode",
          "loopback",
          "--passphrase-fd",
          "0",
          "--quick-add-key",
          primaryFingerprint,
          "rsa2048",
          "encr",
          "1d",
        ],
        `${passphrase}\n`,
      );
      requireSuccess(added, "synthetic encryption subkey generation failed");

      const secretListing = runGpg(
        generationHome,
        ["--with-colons", "--list-secret-keys", "--fingerprint", "--fingerprint"],
      );
      requireSuccess(secretListing, "synthetic secret key inspection failed");
      const encryptionSubkeyFingerprint = fingerprints(secretListing.stdout).find(
        (record) => record.record === "ssb" && record.capabilities.includes("e"),
      )?.fingerprint;
      assert.match(encryptionSubkeyFingerprint, /^[A-F0-9]{40}$/);

      const publicExport = runGpg(generationHome, ["--armor", "--export", primaryFingerprint]);
      requireSuccess(publicExport, "synthetic public key export failed");
      const secretExport = runGpg(
        generationHome,
        [
          "--pinentry-mode",
          "loopback",
          "--passphrase-fd",
          "0",
          "--armor",
          "--export-secret-keys",
          primaryFingerprint,
        ],
        `${passphrase}\n`,
      );
      requireSuccess(secretExport, "synthetic secret key export failed");

      const publicPath = join(root, "public.asc");
      const ciphertextPath = join(root, "synthetic.gpg");
      const plaintextPath = join(root, "synthetic.bin");
      const plaintext = Buffer.from("synthetic protected executor bytes\n\0with-binary-tail\u0001");
      await writeFile(publicPath, publicExport.stdout, { mode: 0o400 });
      await writeFile(plaintextPath, plaintext, { mode: 0o400 });
      requireSuccess(
        runGpg(encryptionHome, ["--import", publicPath]),
        "synthetic public key import failed",
      );
      requireSuccess(
        runGpg(encryptionHome, [
          "--trust-model",
          "always",
          "--recipient",
          `${encryptionSubkeyFingerprint}!`,
          "--output",
          ciphertextPath,
          "--encrypt",
          plaintextPath,
        ]),
        "synthetic payload encryption failed",
      );

      await assert.rejects(
        decryptBoundCiphertext(
          ciphertextPath,
          environmentFor(secretExport.stdout, wrongPassphrase),
          wrongRoot,
          primaryFingerprint,
          encryptionSubkeyFingerprint,
        ),
        /Offline GPG decryption failed/,
      );

      const decryptedPath = await decryptBoundCiphertext(
        ciphertextPath,
        environmentFor(secretExport.stdout, passphrase),
        correctRoot,
        primaryFingerprint,
        encryptionSubkeyFingerprint,
      );
      assert.deepEqual(await readFile(decryptedPath), plaintext);
    } finally {
      for (const home of [
        generationHome,
        encryptionHome,
        join(wrongRoot, "gpg"),
        join(correctRoot, "gpg"),
      ])
        killAgent(home);
      await rm(root, { force: true, recursive: true });
    }
  },
);
