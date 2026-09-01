#!/usr/bin/env node

import { validateApprovalHistory } from './control-contract.mjs';

export async function fetchAndVerifyApproval(environment = process.env, fetcher = fetch) {
  const apiBase = environment.GITHUB_API_URL?.trim();
  const repository = environment.GITHUB_REPOSITORY?.trim();
  const runId = environment.GITHUB_RUN_ID?.trim();
  const token = environment.GITHUB_TOKEN?.trim();
  if (!apiBase || !repository || !/^\d+$/.test(runId ?? '') || !token) {
    throw new Error('GitHub approval API context is incomplete');
  }
  const response = await fetcher(
    `${apiBase}/repos/${repository}/actions/runs/${runId}/approvals`,
    {
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
      },
    },
  );
  if (!response.ok) throw new Error(`approval API returned ${response.status}`);
  const history = await response.json();
  return validateApprovalHistory(history, {
    environmentName: environment.PROTECTED_ENVIRONMENT_NAME,
    expectedReviewerActorId: environment.EXPECTED_REVIEWER_ACTOR_ID,
    requesterActorId: environment.REQUESTER_ACTOR_ID,
  });
}

async function main() {
  const result = await fetchAndVerifyApproval();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1]?.endsWith('verify-approval.mjs')) {
  main().catch((error) => {
    console.error(`Environment approval rejected: ${error.message}`);
    process.exitCode = 1;
  });
}
