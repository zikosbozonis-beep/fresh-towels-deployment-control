#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "./control-contract.mjs";
import {
  decryptBoundCiphertext,
  validateDecryptionBindings,
} from "./protected-transport.mjs";

function runGpg(home, arguments_, options = {}) {
  return spawnSync("gpg", ["--batch", "--no-tty", "--homedir", home, ...arguments_], {
    encoding: options.encoding,
    env: { GNUPGHOME: home, HOME: home, PATH: process.env.PATH },
    input: options.input,
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
}

function requireSuccess(result, message) {
  if (result.status !== 0) throw new Error(message);
}

function killAgent(home) {
  spawnSync("gpgconf", ["--homedir", home, "--kill", "all"], {
    stdio: "ignore",
    windowsHide: true,
  });
}

export async function proveOfflineGpgRoundTrip(environment = process.env) {
  validateDecryptionBindings(environment);
  const root = await mkdtemp(join(tmpdir(), "deployment-control-gpg-self-test-"));
  const publicHome = join(root, "public-gpg");
  const decryptionRoot = join(root, "decryption-proof");
  try {
    await mkdir(publicHome, { mode: 0o700 });
    await mkdir(decryptionRoot, { mode: 0o700 });
    const publicKeyPath = fileURLToPath(
      new URL("../keys/release-encryption-public.asc", import.meta.url),
    );
    const [primaryFingerprint, encryptionSubkeyFingerprint] = await Promise.all([
      readFile(
        fileURLToPath(new URL("../keys/release-encryption-fingerprint.txt", import.meta.url)),
        "utf8",
      ).then((value) => value.trim()),
      readFile(
        fileURLToPath(
          new URL("../keys/release-encryption-subkey-fingerprint.txt", import.meta.url),
        ),
        "utf8",
      ).then((value) => value.trim()),
    ]);
    if (
      !/^[A-F0-9]{40}$/.test(primaryFingerprint) ||
      !/^[A-F0-9]{40}$/.test(encryptionSubkeyFingerprint)
    ) {
      throw new Error("Pinned GPG fingerprints are invalid");
    }
    requireSuccess(
      runGpg(publicHome, ["--import", publicKeyPath]),
      "Pinned GPG public key import failed",
    );
    const payload = Buffer.concat([
      Buffer.from("Fresh Towels protected executor offline round trip\n", "utf8"),
      randomBytes(256),
    ]);
    const payloadPath = join(root, "synthetic-payload.bin");
    const ciphertextPath = join(root, "synthetic-payload.gpg");
    await writeFile(payloadPath, payload, { flag: "wx", mode: 0o400 });
    requireSuccess(
      runGpg(publicHome, [
        "--trust-model",
        "always",
        "--recipient",
        `${encryptionSubkeyFingerprint}!`,
        "--output",
        ciphertextPath,
        "--encrypt",
        payloadPath,
      ]),
      "Pinned GPG public encryption subkey is unusable",
    );
    const decryptedPath = await decryptBoundCiphertext(
      ciphertextPath,
      environment,
      decryptionRoot,
      primaryFingerprint,
      encryptionSubkeyFingerprint,
    );
    const decrypted = await readFile(decryptedPath);
    if (!decrypted.equals(payload) || sha256(decrypted) !== sha256(payload)) {
      throw new Error("Offline GPG decrypted bytes differ");
    }
    return Object.freeze({
      exactByteMatch: true,
      passphraseUnlock: true,
      publicPrivateKeyMatch: true,
    });
  } finally {
    killAgent(publicHome);
    killAgent(join(decryptionRoot, "gpg"));
    await rm(root, { force: true, recursive: true });
  }
}

if (process.argv[1]?.endsWith("gpg-offline-proof.mjs")) {
  proveOfflineGpgRoundTrip().then(
    () => {
      process.stdout.write("GPG OFFLINE ROUND-TRIP: PASS\n");
      process.stdout.write("PUBLIC/PRIVATE KEY MATCH: PASS\n");
      process.stdout.write("PASSPHRASE UNLOCK: PASS\n");
    },
    (error) => {
      console.error(`GPG offline self-test rejected: ${error.message}`);
      process.exitCode = 1;
    },
  );
}
