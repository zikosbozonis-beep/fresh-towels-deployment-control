#!/usr/bin/env node

import {
  canonicalJson,
  decodeCanonicalBase64Url,
  sha256,
  validateReleaseRequest,
} from "./control-contract.mjs";
import { pathToFileURL } from "node:url";

function required(environment, name, pattern, maximum = 32_768) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\r\n\0]/.test(value) ||
    (pattern && !pattern.test(value))
  ) {
    throw new Error("ambiguous execution identity is incomplete");
  }
  return value;
}

export function createAmbiguousReceipt(environment = process.env) {
  const encoded = required(environment, "RELEASE_REQUEST_BASE64", /^[A-Za-z0-9_-]+$/);
  const bytes = decodeCanonicalBase64Url(encoded, "ambiguous execution release request");
  const request = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  const validated = validateReleaseRequest(request);
  if (validated.canonical !== bytes.toString("utf8")) {
    throw new Error("ambiguous execution release request is not canonical");
  }
  const receipt = Object.freeze({
    schema: "deployment-control/execution-ambiguous/v1",
    outcome: "execution_ambiguous",
    requestId: request.requestId,
    requestSha256: validated.digest,
    controllerRunId: required(environment, "GITHUB_RUN_ID", /^[1-9][0-9]{0,19}$/, 20),
    controllerRunAttempt: Number(
      required(environment, "GITHUB_RUN_ATTEMPT", /^[1-9][0-9]{0,9}$/, 10),
    ),
  });
  return Object.freeze({ receipt, receiptSha256: sha256(Buffer.from(canonicalJson(receipt))) });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    process.stdout.write(`${createAmbiguousReceipt().receiptSha256}\n`);
  } catch {
    console.error("Ambiguous execution receipt stopped: invalid-public-release-identity");
    process.exitCode = 1;
  }
}
