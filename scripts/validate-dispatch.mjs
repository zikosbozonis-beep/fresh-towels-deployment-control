#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { validateDispatchContext, validateReleaseRequest } from './control-contract.mjs';

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function parseArguments(arguments_) {
  const parsed = { eventPath: '', outputPath: '' };
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (!value || !['--event', '--output'].includes(key)) {
      throw new Error('usage: validate-dispatch --event <path> --output <path>');
    }
    parsed[key === '--event' ? 'eventPath' : 'outputPath'] = value;
  }
  if (!parsed.eventPath || !parsed.outputPath) {
    throw new Error('event and output paths are required');
  }
  return parsed;
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  const event = JSON.parse(await readFile(resolve(arguments_.eventPath), 'utf8'));
  const encodedRequest = event.inputs?.release_request_base64;
  if (
    typeof encodedRequest !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(encodedRequest) ||
    encodedRequest.length > 32_768
  ) {
    throw new Error('release_request_base64 is invalid');
  }
  const requestBytes = Buffer.from(encodedRequest, 'base64url');
  if (requestBytes.length < 2 || requestBytes.length > 24_576) {
    throw new Error('decoded release request size is invalid');
  }
  const request = JSON.parse(requestBytes.toString('utf8'));
  validateDispatchContext({
    actorId: requiredEnvironment('GITHUB_ACTOR_ID'),
    checkedOutSha: requiredEnvironment('CHECKED_OUT_CONTROLLER_SHA'),
    controllerSha: requiredEnvironment('GITHUB_SHA'),
    eventName: requiredEnvironment('GITHUB_EVENT_NAME'),
    expectedRequesterActorId: requiredEnvironment('EXPECTED_REQUESTER_ACTOR_ID'),
    ref: requiredEnvironment('GITHUB_REF'),
    refProtected: requiredEnvironment('GITHUB_REF_PROTECTED'),
    senderType: event.sender?.type,
  });
  const verified = validateReleaseRequest(request, {
    expectedControllerRepositoryId: requiredEnvironment(
      'EXPECTED_CONTROLLER_REPOSITORY_ID',
    ),
    expectedControllerSha: requiredEnvironment('GITHUB_SHA'),
    expectedSourceRepositoryId: requiredEnvironment('EXPECTED_SOURCE_REPOSITORY_ID'),
  });
  const output = {
    artifactCiphertextSha256: verified.request.artifact.ciphertextSha256,
    artifactReleaseId: verified.request.artifact.releaseId,
    artifactTransportTag: verified.request.artifact.transportTag,
    artifactTransportCommitSha: verified.request.artifact.transportCommitSha,
    artifactCiphertextBlobSha1: verified.request.artifact.ciphertextBlobSha1,
    artifactManifestBlobSha1: verified.request.artifact.manifestBlobSha1,
    artifactPlaintextBytes: verified.request.artifact.plaintextBytes,
    artifactPlaintextSha256: verified.request.artifact.plaintextSha256,
    controllerCommitSha: verified.request.controller.commitSha,
    evidenceManifestSha256: verified.request.evidence.manifestSha256,
    evidenceOidcTokenSha256: verified.request.evidence.oidcTokenSha256,
    operation: verified.request.operation,
    requestDigest: verified.digest,
    requestId: verified.request.requestId,
    sourceCommitSha: verified.request.source.commitSha,
    sourceRepositoryId: verified.request.source.repositoryId,
    sourceWorkflowRunId: verified.request.source.workflowRunId,
  };
  await writeFile(resolve(arguments_.outputPath), `${JSON.stringify(output)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o400,
  });
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

main().catch((error) => {
  console.error(`Release request rejected: ${error.message}`);
  process.exitCode = 1;
});
