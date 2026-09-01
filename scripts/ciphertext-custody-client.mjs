import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateReleaseRequest,
} from "./control-contract.mjs";
import { decryptBoundCiphertext } from "./protected-transport.mjs";

const digestPattern = /^[a-f0-9]{64}$/;
const fingerprintPattern = /^[A-F0-9]{40}$/;
const maximumResponseBytes = 131_072;
const privateReceiptBinding = "PRODUCTION_INFRASTRUCTURE_RECEIPT";
const productionDnsStageReceiptBinding = "PRODUCTION_DNS_STAGE_RECEIPT";
const recoveryBackupBinding = "PRODUCTION_D1_INITIAL_RECOVERY";
const productionReleaseReceiptBinding = "PRODUCTION_RELEASE_CANDIDATE_RECEIPT";

export const ciphertextCustodyClientBindings = Object.freeze({
  privateReceiptBinding,
  productionDnsStageReceiptBinding,
  productionReleaseReceiptBinding,
  recoveryBackupBinding,
});

function exactObject(value, keys, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(label + " is not an object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(label + " fields differ");
  }
}

function exactDigest(value, label) {
  if (typeof value !== "string" || !digestPattern.test(value)) {
    throw new Error(label + " is invalid");
  }
  return value;
}

function canonicalOrigin(value) {
  const origin = new URL(value);
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new Error("custody broker origin is invalid");
  }
  return origin;
}

function releaseIdentity(releaseRequestBase64) {
  const bytes = decodeCanonicalBase64Url(releaseRequestBase64, "custody release request");
  const request = JSON.parse(bytes.toString("utf8"));
  const validated = validateReleaseRequest(request);
  if (validated.canonical !== bytes.toString("utf8")) {
    throw new Error("custody release request is not canonical");
  }
  return validated;
}

function canonicalBase64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function boundedResponseText(response) {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > maximumResponseBytes)) {
    throw new Error("ciphertext custody broker response exceeds the byte boundary");
  }
  if (!response.body || typeof response.body.getReader !== "function") {
    const fallback = await response.text();
    if (Buffer.byteLength(fallback) > maximumResponseBytes) {
      throw new Error("ciphertext custody broker response exceeds the byte boundary");
    }
    return fallback;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumResponseBytes) {
      await reader.cancel();
      throw new Error("ciphertext custody broker response exceeds the byte boundary");
    }
    chunks.push(Buffer.from(value));
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, total));
}

async function parseResponse(response, expectedKeys, identity) {
  const text = await boundedResponseText(response);
  if (!response.ok || text.length < 2) {
    throw new Error("ciphertext custody broker rejected the protected operation");
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error("ciphertext custody broker returned malformed JSON");
  }
  exactObject(body, ["requestDigest", "requestId", ...expectedKeys], "ciphertext custody response");
  if (
    body.requestId !== identity.request.requestId ||
    body.requestDigest !== identity.digest
  ) {
    throw new Error("ciphertext custody response differs from the exact release");
  }
  return body;
}

export function createCiphertextCustodyBrokerClient({
  dispatcherOrigin,
  fetcher = fetch,
  getOidcToken,
  releaseRequestBase64,
}) {
  const origin = canonicalOrigin(dispatcherOrigin);
  const identity = releaseIdentity(releaseRequestBase64);
  if (typeof fetcher !== "function" || typeof getOidcToken !== "function") {
    throw new Error("ciphertext custody broker dependencies are unavailable");
  }

  async function request(path, payload, responseKeys) {
    const token = await getOidcToken();
    if (
      typeof token !== "string" ||
      token.length < 100 ||
      token.length > 16_384 ||
      token.split(".").length !== 3 ||
      /[\r\n\0]/.test(token)
    ) {
      throw new Error("ciphertext custody OIDC identity is invalid");
    }
    const response = await fetcher(new URL(path, origin), {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "user-agent": "deployment-control-protected-custody",
      },
      body: JSON.stringify({ releaseRequestBase64, ...payload }),
      redirect: "error",
    });
    return parseResponse(response, responseKeys, identity);
  }

  return Object.freeze({
    identity,
    async confirm(input) {
      return request(
        "/v1/custody/confirm",
        input,
        [
          "bindingVersionSha256",
          "custodySha256",
          "decryptionProofSha256",
          "resourceIdentitySha256",
          "stored",
        ],
      );
    },
    async inspect(input) {
      return request(
        "/v1/custody/inspect",
        input,
        ["bindingVersionSha256", "present", "resourceIdentitySha256"],
      );
    },
    async read(input) {
      return request(
        "/v1/custody/read",
        input,
        [
          "binding",
          "ciphertextBase64Url",
          "ciphertextSha256",
          "custodySha256",
          "encryptionKeySha256",
          "payloadKind",
          "plaintextBytes",
          "plaintextSha256",
          "resourceIdentitySha256",
          "state",
        ],
      );
    },
    async resolve(input) {
      return request(
        "/v1/custody/resolve",
        input,
        [
          "binding",
          "bindingVersionSha256",
          "ciphertextSha256",
          "custodySha256",
          "encryptionKeySha256",
          "payloadKind",
          "plaintextBytes",
          "plaintextSha256",
          "resourceIdentitySha256",
        ],
      );
    },
    async revoke(input) {
      return request(
        "/v1/custody/revoke",
        input,
        ["custodySha256", "revoked"],
      );
    },
    async store(input) {
      return request(
        "/v1/custody/store",
        input,
        [
          "binding",
          "ciphertextSha256",
          "custodySha256",
          "plaintextSha256",
          "resourceIdentitySha256",
          "state",
        ],
      );
    },
  });
}

function gpg(home, arguments_, options = {}) {
  return spawnSync(
    "gpg",
    [
      "--batch",
      "--no-tty",
      "--homedir",
      home,
      "--no-auto-key-retrieve",
      "--auto-key-locate",
      "clear",
      ...arguments_,
    ],
    {
      encoding: options.encoding ?? "utf8",
      env: { GNUPGHOME: home, HOME: dirname(home), PATH: process.env.PATH },
      input: options.input,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    },
  );
}

function requireGpgSuccess(result, label) {
  if (result.status !== 0) throw new Error(label);
  return result;
}

function publicFingerprints(listing) {
  const found = [];
  let pending = null;
  for (const line of listing.split("\n")) {
    const fields = line.split(":");
    if (["pub", "sub"].includes(fields[0])) {
      pending = { capabilities: (fields[11] ?? "").toLowerCase(), record: fields[0] };
    } else if (fields[0] === "fpr" && pending) {
      found.push({ ...pending, fingerprint: fields[9] ?? "" });
      pending = null;
    }
  }
  return found;
}

function verifyPublicKey(listing, primaryFingerprint, encryptionSubkeyFingerprint) {
  if (
    !fingerprintPattern.test(primaryFingerprint) ||
    !fingerprintPattern.test(encryptionSubkeyFingerprint)
  ) {
    throw new Error("custody encryption fingerprint is invalid");
  }
  const keys = publicFingerprints(listing);
  const primary = keys.filter((key) => key.record === "pub");
  const encryption = keys.filter(
    (key) => key.record === "sub" && key.capabilities.includes("e"),
  );
  if (
    primary.length !== 1 ||
    primary[0].fingerprint !== primaryFingerprint ||
    encryption.length !== 1 ||
    encryption[0].fingerprint !== encryptionSubkeyFingerprint
  ) {
    throw new Error("custody encryption key identity differs");
  }
}

function killAgent(home) {
  spawnSync("gpgconf", ["--homedir", home, "--kill", "all"], {
    encoding: "utf8",
    windowsHide: true,
  });
}

async function encryptionIdentity(identity) {
  const base = new URL("../", import.meta.url);
  const [publicKey, primaryFingerprint, encryptionSubkeyFingerprint] = await Promise.all([
    readFile(fileURLToPath(new URL("keys/release-encryption-public.asc", base))),
    readFile(fileURLToPath(new URL("keys/release-encryption-fingerprint.txt", base)), "utf8").then(
      (value) => value.trim(),
    ),
    readFile(
      fileURLToPath(new URL("keys/release-encryption-subkey-fingerprint.txt", base)),
      "utf8",
    ).then((value) => value.trim()),
  ]);
  if (sha256(publicKey) !== identity.request.artifact.encryptionKeySha256) {
    throw new Error("custody public key differs from the approved release");
  }
  return Object.freeze({ encryptionSubkeyFingerprint, primaryFingerprint, publicKey });
}

async function encrypt(root, plaintext, encryption) {
  const home = join(root, "encrypt-gpg");
  const publicKeyPath = join(root, "release-encryption-public.asc");
  const plaintextPath = join(root, "plaintext.bin");
  const ciphertextPath = join(root, "ciphertext.gpg");
  await mkdir(home, { mode: 0o700 });
  await writeFile(publicKeyPath, encryption.publicKey, { flag: "wx", mode: 0o400 });
  await writeFile(plaintextPath, plaintext, { flag: "wx", mode: 0o600 });
  requireGpgSuccess(gpg(home, ["--import", publicKeyPath]), "custody public-key import failed");
  const listing = requireGpgSuccess(
    gpg(home, ["--with-colons", "--list-keys", "--fingerprint", "--fingerprint"]),
    "custody public-key inspection failed",
  ).stdout;
  verifyPublicKey(
    listing,
    encryption.primaryFingerprint,
    encryption.encryptionSubkeyFingerprint,
  );
  requireGpgSuccess(
    gpg(home, [
      "--trust-model",
      "always",
      "--recipient",
      `${encryption.encryptionSubkeyFingerprint}!`,
      "--output",
      ciphertextPath,
      "--encrypt",
      plaintextPath,
    ]),
    "custody encryption failed",
  );
  await chmod(plaintextPath, 0o600);
  await writeFile(plaintextPath, Buffer.alloc(0), { mode: 0o600 });
  return { ciphertext: await readFile(ciphertextPath), home };
}

function proofDigest({ binding, custodySha256, readback }) {
  return sha256(
    Buffer.from(
      canonicalJson({
        binding,
        ciphertextSha256: readback.ciphertextSha256,
        custodySha256,
        encryptionKeySha256: readback.encryptionKeySha256,
        plaintextSha256: readback.plaintextSha256,
        resourceIdentitySha256: readback.resourceIdentitySha256,
        schema: "deployment-control/ciphertext-custody-decryption-proof/v1",
      }),
      "utf8",
    ),
  );
}

export async function createGpgCiphertextCustodySinks({
  brokerClient,
  decryptionEnvironment,
}) {
  if (!brokerClient?.identity || typeof brokerClient.store !== "function") {
    throw new Error("ciphertext custody broker client is unavailable");
  }
  const encryption = await encryptionIdentity(brokerClient.identity);

  async function storeAndVerify({
    binding,
    context,
    payloadKind,
    plaintextBytes,
    plaintextSha256,
  }) {
    const plaintext = Buffer.from(plaintextBytes);
    if (
      plaintext.length < 1 ||
      plaintext.length > 65_536 ||
      sha256(plaintext) !== plaintextSha256
    ) {
      plaintext.fill(0);
      throw new Error("custody plaintext differs from its exact digest");
    }
    const root = await mkdtemp(join(tmpdir(), "deployment-control-custody-"));
    let stored = null;
    let revocable = false;
    try {
      const encrypted = await encrypt(root, plaintext, encryption);
      const ciphertextSha256 = sha256(encrypted.ciphertext);
      stored = await brokerClient.store({
        binding,
        ciphertextBase64Url: canonicalBase64Url(encrypted.ciphertext),
        ciphertextSha256,
        context,
        encryptionKeySha256: brokerClient.identity.request.artifact.encryptionKeySha256,
        payloadKind,
        plaintextBytes: plaintext.length,
        plaintextSha256,
      });
      revocable = stored.state === "pending";
      exactDigest(stored.custodySha256, "stored custody digest");
      const readback = await brokerClient.read({
        binding,
        expectedCiphertextSha256: stored.ciphertextSha256,
        expectedPlaintextSha256: stored.plaintextSha256,
      });
      if (
        readback.custodySha256 !== stored.custodySha256 ||
        readback.encryptionKeySha256 !==
          brokerClient.identity.request.artifact.encryptionKeySha256 ||
        readback.plaintextBytes !== plaintext.length ||
        readback.plaintextSha256 !== plaintextSha256 ||
        readback.resourceIdentitySha256 !== stored.resourceIdentitySha256
      ) {
        throw new Error("custody readback metadata differs");
      }
      const readbackCiphertext = Buffer.from(readback.ciphertextBase64Url, "base64url");
      if (
        readbackCiphertext.toString("base64url") !== readback.ciphertextBase64Url ||
        sha256(readbackCiphertext) !== readback.ciphertextSha256
      ) {
        throw new Error("custody readback ciphertext differs");
      }
      const ciphertextPath = join(root, "readback.gpg");
      await writeFile(ciphertextPath, readbackCiphertext, { flag: "wx", mode: 0o400 });
      const decryptionRoot = join(root, "decrypt");
      await mkdir(decryptionRoot, { mode: 0o700 });
      const decryptedPath = await decryptBoundCiphertext(
        ciphertextPath,
        decryptionEnvironment,
        decryptionRoot,
        encryption.primaryFingerprint,
        encryption.encryptionSubkeyFingerprint,
      );
      const decrypted = await readFile(decryptedPath);
      const exact = decrypted.equals(plaintext) && sha256(decrypted) === plaintextSha256;
      decrypted.fill(0);
      readbackCiphertext.fill(0);
      if (!exact) throw new Error("custody decrypted readback differs byte-for-byte");
      const decryptionProofSha256 = proofDigest({
        binding,
        custodySha256: stored.custodySha256,
        readback,
      });
      const confirmed = await brokerClient.confirm({
        binding,
        custodySha256: stored.custodySha256,
        decryptionProofSha256,
        expectedCiphertextSha256: readback.ciphertextSha256,
        expectedPlaintextSha256: plaintextSha256,
      });
      if (
        confirmed.stored !== true ||
        confirmed.custodySha256 !== stored.custodySha256 ||
        confirmed.decryptionProofSha256 !== decryptionProofSha256 ||
        confirmed.resourceIdentitySha256 !== stored.resourceIdentitySha256
      ) {
        throw new Error("custody activation confirmation differs");
      }
      revocable = false;
      return Object.freeze({
        bindingVersionSha256: confirmed.bindingVersionSha256,
        ciphertextSha256: readback.ciphertextSha256,
        custodySha256: confirmed.custodySha256,
        decryptionProofSha256,
        plaintextSha256,
        resourceIdentitySha256: confirmed.resourceIdentitySha256,
      });
    } catch (error) {
      if (stored && revocable) {
        try {
          await brokerClient.revoke({
            binding,
            custodySha256: stored.custodySha256,
            expectedCiphertextSha256: stored.ciphertextSha256,
            expectedPlaintextSha256: stored.plaintextSha256,
          });
        } catch {
          throw new Error("custody verification failed and revocation is ambiguous");
        }
      }
      throw error;
    } finally {
      plaintext.fill(0);
      killAgent(join(root, "encrypt-gpg"));
      killAgent(join(root, "decrypt", "gpg"));
      await rm(root, { force: true, recursive: true });
    }
  }

  const secretSink = Object.freeze({
    async inspect({ binding, context }) {
      const result = await brokerClient.inspect({ binding, context, payloadKind: "secret" });
      exactObject(
        result,
        [
          "bindingVersionSha256",
          "present",
          "requestDigest",
          "requestId",
          "resourceIdentitySha256",
        ],
        "custody inspection response",
      );
      return Object.freeze({
        bindingVersionSha256: result.bindingVersionSha256,
        present: result.present,
        resourceIdentitySha256: result.resourceIdentitySha256,
      });
    },
    async store({ binding, context, secretBytes, secretSha256 }) {
      const result = await storeAndVerify({
        binding,
        context,
        payloadKind: "secret",
        plaintextBytes: secretBytes,
        plaintextSha256: secretSha256,
      });
      return Object.freeze({
        bindingVersionSha256: result.bindingVersionSha256,
        resourceIdentitySha256: result.resourceIdentitySha256,
        stored: true,
      });
    },
  });

  const privateReceiptSink = Object.freeze({
    async store({ context, receiptBytes, receiptSha256 }) {
      const result = await storeAndVerify({
        binding: privateReceiptBinding,
        context,
        payloadKind: "private_receipt",
        plaintextBytes: receiptBytes,
        plaintextSha256: receiptSha256,
      });
      return Object.freeze({
        custodySha256: result.custodySha256,
        decryptedReceiptSha256: result.plaintextSha256,
        decryptionProofSha256: result.decryptionProofSha256,
        decryptVerified: true,
        encrypted: true,
        encryptedArtifactSha256: result.ciphertextSha256,
        stored: true,
      });
    },
  });

  const dnsStageReceiptSink = Object.freeze({
    async store({ context, receiptBytes, receiptSha256 }) {
      if (brokerClient.identity.request.operation !== "production-dns-stage") {
        throw new Error("DNS-stage receipt custody is restricted to production DNS stage");
      }
      const result = await storeAndVerify({
        binding: productionDnsStageReceiptBinding,
        context,
        payloadKind: "private_receipt",
        plaintextBytes: receiptBytes,
        plaintextSha256: receiptSha256,
      });
      return Object.freeze({
        custodySha256: result.custodySha256,
        decryptedReceiptSha256: result.plaintextSha256,
        decryptionProofSha256: result.decryptionProofSha256,
        decryptVerified: true,
        encrypted: true,
        encryptedArtifactSha256: result.ciphertextSha256,
        stored: true,
      });
    },
  });

  const recoveryBackupSink = Object.freeze({
    async store({ context, backupBytes, backupSha256 }) {
      const result = await storeAndVerify({
        binding: recoveryBackupBinding,
        context,
        payloadKind: "private_receipt",
        plaintextBytes: backupBytes,
        plaintextSha256: backupSha256,
      });
      return Object.freeze({
        bindingVersionSha256: result.bindingVersionSha256,
        ciphertextSha256: result.ciphertextSha256,
        custodySha256: result.custodySha256,
        decryptionProofSha256: result.decryptionProofSha256,
        stored: true,
      });
    },
  });

  const productionReleaseReceiptSink = Object.freeze({
    async store({ context, receiptBytes, receiptSha256 }) {
      if (brokerClient.identity.request.operation !== "production-release") {
        throw new Error("production-release receipt custody is restricted to production release");
      }
      const result = await storeAndVerify({
        binding: productionReleaseReceiptBinding,
        context,
        payloadKind: "private_receipt",
        plaintextBytes: receiptBytes,
        plaintextSha256: receiptSha256,
      });
      return Object.freeze({
        bindingVersionSha256: result.bindingVersionSha256,
        ciphertextSha256: result.ciphertextSha256,
        custodySha256: result.custodySha256,
        decryptionProofSha256: result.decryptionProofSha256,
        receiptSha256: result.plaintextSha256,
        stored: true,
      });
    },
  });

  async function materializeBinding({ binding }) {
    const operation = brokerClient.identity.request.operation;
    if (
      (operation === "production-bootstrap" && binding !== productionDnsStageReceiptBinding) ||
      (operation === "production-release" &&
        [productionReleaseReceiptBinding, recoveryBackupBinding].includes(binding)) ||
      (operation === "production-cutover" && binding !== productionReleaseReceiptBinding) ||
      !["production-bootstrap", "production-release", "production-cutover"].includes(operation)
    ) {
      throw new Error("custody materialization is restricted to production release/cutover exact bindings");
    }
    const resolved = await brokerClient.resolve({ binding });
    if (
      resolved.encryptionKeySha256 !==
        brokerClient.identity.request.artifact.encryptionKeySha256
    ) {
      throw new Error("resolved custody encryption key differs from the approved release");
    }
    const readback = await brokerClient.read({
      binding,
      expectedCiphertextSha256: resolved.ciphertextSha256,
      expectedPlaintextSha256: resolved.plaintextSha256,
    });
    if (
      readback.binding !== binding ||
      readback.custodySha256 !== resolved.custodySha256 ||
      readback.ciphertextSha256 !== resolved.ciphertextSha256 ||
      readback.plaintextSha256 !== resolved.plaintextSha256 ||
      readback.plaintextBytes !== resolved.plaintextBytes ||
      readback.resourceIdentitySha256 !== resolved.resourceIdentitySha256 ||
      readback.state !== "active"
    ) {
      throw new Error("resolved custody object changed before materialization");
    }
    const ciphertext = Buffer.from(readback.ciphertextBase64Url, "base64url");
    if (
      ciphertext.toString("base64url") !== readback.ciphertextBase64Url ||
      sha256(ciphertext) !== resolved.ciphertextSha256
    ) {
      ciphertext.fill(0);
      throw new Error("materialized custody ciphertext differs");
    }
    const root = await mkdtemp(join(tmpdir(), "deployment-control-custody-read-"));
    try {
      const ciphertextPath = join(root, "readback.gpg");
      await writeFile(ciphertextPath, ciphertext, { flag: "wx", mode: 0o400 });
      const decryptionRoot = join(root, "decrypt");
      await mkdir(decryptionRoot, { mode: 0o700 });
      const decryptedPath = await decryptBoundCiphertext(
        ciphertextPath,
        decryptionEnvironment,
        decryptionRoot,
        encryption.primaryFingerprint,
        encryption.encryptionSubkeyFingerprint,
      );
      const plaintext = await readFile(decryptedPath);
      if (
        plaintext.length !== resolved.plaintextBytes ||
        sha256(plaintext) !== resolved.plaintextSha256
      ) {
        plaintext.fill(0);
        throw new Error("materialized custody plaintext differs");
      }
      return Object.freeze({
        bindingVersionSha256: resolved.bindingVersionSha256,
        bytes: plaintext,
        custodySha256: resolved.custodySha256,
        payloadKind: resolved.payloadKind,
        plaintextSha256: resolved.plaintextSha256,
        resourceIdentitySha256: resolved.resourceIdentitySha256,
      });
    } finally {
      ciphertext.fill(0);
      killAgent(join(root, "decrypt", "gpg"));
      await rm(root, { force: true, recursive: true });
    }
  }

  async function materializeProductionReleaseReceipt() {
    if (brokerClient.identity.request.operation !== "production-cutover") {
      throw new Error("production-release receipt materialization is restricted to production cutover");
    }
    return materializeBinding({ binding: productionReleaseReceiptBinding });
  }

  return Object.freeze({
    brokerClient,
    dnsStageReceiptSink,
    materializeBinding,
    materializeProductionReleaseReceipt,
    privateReceiptSink,
    productionReleaseReceiptSink,
    recoveryBackupSink,
    secretSink,
  });
}
