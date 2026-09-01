import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflows = [
  '.github/workflows/quality.yml',
  '.github/workflows/package-release.yml',
  '.github/workflows/execute-release.yml',
];

test('all external Actions are immutable full-SHA pins', async () => {
  for (const path of workflows) {
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    for (const line of source.split(/\r?\n/)) {
      const match = /^\s*- uses:\s+([^\s#]+)/.exec(line);
      if (!match) continue;
      assert.match(match[1], /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/);
    }
  }
});

test('public pull requests cannot enter the dispatch or secret-bearing workflows', async () => {
  const packageWorkflow = await readFile(
    new URL('../.github/workflows/package-release.yml', import.meta.url),
    'utf8',
  );
  const executeWorkflow = await readFile(
    new URL('../.github/workflows/execute-release.yml', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(packageWorkflow, /pull_request_target/);
  assert.doesNotMatch(executeWorkflow, /pull_request_target|pull_request:/);
  assert.match(executeWorkflow, /environment:\s+production/);
  assert.match(executeWorkflow, /PROTECTED_EXECUTOR_CANARY_NOT_YET_PROVEN/);
  assert.doesNotMatch(packageWorkflow, /secrets:\s+inherit/);
  assert.doesNotMatch(packageWorkflow, /REQUESTER_APP_TOKEN|GITHUB_APP_PRIVATE_KEY/);
  assert.doesNotMatch(packageWorkflow, /manifest\.json packaging-oidc\.jwt payload\.bin/);
  assert.match(packageWorkflow, /manifest\.json payload\.bin/);
});

test('packaging keeps plaintext private and uploads only encrypted bytes', async () => {
  const source = await readFile(
    new URL('../.github/workflows/package-release.yml', import.meta.url),
    'utf8',
  );
  assert.match(source, /actions\/download-artifact@[a-f0-9]{40}/);
  assert.doesNotMatch(source, /actions\/upload-artifact/);
  assert.match(source, /--encrypt/);
  assert.match(source, /publish-private-transport\.mjs/);
  assert.match(source, /immutable private Release/);
  assert.match(source, /dispatch-controller\.mjs/);
});
