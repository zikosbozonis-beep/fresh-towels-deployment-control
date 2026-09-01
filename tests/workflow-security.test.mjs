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
  assert.match(executeWorkflow, /environment:\s*\n\s+name:.*'canary'.*'production'/);
  assert.doesNotMatch(executeWorkflow, /PRODUCTION_RELEASE_ADAPTER_NOT_YET_PROVEN/);
  assert.match(executeWorkflow, /run-production-release\.mjs/);
  assert.doesNotMatch(packageWorkflow, /secrets:\s+inherit/);
  assert.match(packageWorkflow, /operation:\s*\{ required: true, type: string \}/);
  assert.match(
    packageWorkflow,
    /\^\(canary\|provider-canary\|production-dns-stage\|production-bootstrap\|production-release\|production-cutover\)\$/,
  );
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
  const cleanup = source.slice(source.indexOf('name: Remove local transport material'));
  for (const path of [
    'private-capsule',
    'payload.bin',
    'envelope.tar',
    'control-gpg',
    'release.gpg',
    'manifest.json',
    'transport.json',
    'packaging-oidc.jwt',
  ]) {
    assert.match(cleanup, new RegExp(path.replace('.', '\\.')));
  }
});

test('every failure after the atomic claim is always finalized as ambiguous', async () => {
  const source = await readFile(
    new URL('../.github/workflows/execute-release.yml', import.meta.url),
    'utf8',
  );
  const claim = source.indexOf('id: execution-claim');
  const cleanup = source.indexOf('name: Remove protected executor material');
  const failFinalize = source.indexOf('name: Fail-finalize a claimed execution as ambiguous');
  assert.ok(claim >= 0 && cleanup > claim && failFinalize > cleanup);
  const block = source.slice(failFinalize);
  assert.match(
    block,
    /if: \$\{\{ always\(\) && steps\.execution-claim\.outcome == 'success' && !success\(\) \}\}/,
  );
  assert.match(block, /EXECUTION_OUTCOME=execution_ambiguous/);
  assert.match(block, /create-ambiguous-receipt\.mjs/);
  assert.match(block, /execute-finish/);
  assert.doesNotMatch(block, /EXECUTION_OUTCOME=(?:executed|canary_verified)/);
  assert.doesNotMatch(block, /secrets\./);
});

test('provider Canary and the exact production release remain operation-separated', async () => {
  const source = await readFile(
    new URL('../.github/workflows/execute-release.yml', import.meta.url),
    'utf8',
  );
  assert.match(source, /needs\.intake\.outputs\.operation == 'provider-canary'/);
  assert.match(source, /name:.*operation == 'canary'.*'canary'.*'production'/);
  assert.match(source, /create-canary-receipt\.mjs/);
  assert.match(source, /provider-canary\.mjs/);
  assert.match(source, /CLOUDFLARE_PROVIDER_CANARY_TOKEN: \$\{\{ secrets\./);
  assert.match(source, /RESEND_PROVIDER_CANARY_TOKEN: \$\{\{ secrets\./);
  assert.match(source, /provider-canary-receipt-/);
  assert.match(source, /EXECUTION_OUTCOME:\s+canary_verified/);
  assert.match(source, /EXECUTION_OUTCOME:\s+executed/);
  assert.match(source, /Execute exact production release with protected pre-cutover routes/);
  assert.match(source, /production-release-evidence-/);
  assert.match(source, /steps\.production-release\.outputs\.receipt_sha256/);
  assert.doesNotMatch(source, /wrangler\s+(?:deploy|publish)/);
});

test('production Bootstrap verifies the exact provider Canary before credentials or mutation', async () => {
  const source = await readFile(
    new URL('../.github/workflows/execute-release.yml', import.meta.url),
    'utf8',
  );
  const transport = source.indexOf('name: Fetch and decrypt exact approved private transport');
  const prerequisite = source.indexOf('name: Verify exact operation prerequisite');
  const bootstrap = source.indexOf('name: Execute exact production provider Bootstrap');
  const retain = source.indexOf('name: Retain immutable hash-only production Bootstrap evidence');
  const bootstrapBlock = source.slice(bootstrap, retain);
  assert.ok(transport >= 0 && prerequisite > transport && bootstrap > prerequisite && retain > bootstrap);
  assert.match(source, /PRODUCTION_ACCESS_ADMIN_EMAIL: \$\{\{ needs\.intake\.outputs\.operation == 'production-bootstrap' && secrets\.PRODUCTION_ACCESS_ADMIN_EMAIL \|\| '' \}\}/);
  assert.match(source, /PRODUCTION_ACCESS_ADMIN_EMAIL: \$\{\{ secrets\.PRODUCTION_ACCESS_ADMIN_EMAIL \}\}/);
  assert.match(source, /PREREQUISITE_REQUEST_ID: \$\{\{ steps\.protected-transport\.outputs\.prerequisite_request_id \}\}/);
  assert.match(source, /PREREQUISITE_RECEIPT_SHA256: \$\{\{ steps\.protected-transport\.outputs\.prerequisite_receipt_sha256 \}\}/);
  assert.match(source, /PREREQUISITE_RUN_ID: \$\{\{ steps\.protected-transport\.outputs\.prerequisite_run_id \}\}/);
  assert.match(source, /verify-prerequisite/);
  assert.match(source, /run-production-provider-bootstrap\.mjs/);
  assert.match(source, /EXPECTED_CAPSULE_REQUEST_SHA256: \$\{\{ steps\.protected-transport\.outputs\.capsule_request_sha256 \}\}/);
  assert.match(source, /CLOUDFLARE_PRODUCTION_TOKEN: \$\{\{ secrets\.CLOUDFLARE_PRODUCTION_TOKEN \}\}/);
  assert.match(source, /RESEND_PRODUCTION_ADMIN_TOKEN: \$\{\{ secrets\.RESEND_PRODUCTION_ADMIN_TOKEN \}\}/);
  assert.match(bootstrapBlock, /RELEASE_DECRYPTION_PRIVATE_KEY: \$\{\{ secrets\.RELEASE_DECRYPTION_PRIVATE_KEY \}\}/);
  assert.match(bootstrapBlock, /RELEASE_DECRYPTION_PASSPHRASE: \$\{\{ secrets\.RELEASE_DECRYPTION_PASSPHRASE \}\}/);
  assert.match(source, /production-bootstrap-evidence-/);
  assert.match(source, /steps\.production-bootstrap\.outputs\.receipt_sha256/);
  assert.doesNotMatch(source, /path:\s*\$\{\{ runner\.temp \}\}\/verified-release/);
});

test('production cutover is prerequisite-bound, secret-gated and finalized only from hash-only evidence', async () => {
  const source = await readFile(
    new URL('../.github/workflows/execute-release.yml', import.meta.url),
    'utf8',
  );
  const prerequisite = source.indexOf('name: Verify exact operation prerequisite');
  const cutover = source.indexOf(
    'name: Execute exact production cutover from protected pre-cutover fallback',
  );
  const retain = source.indexOf(
    'name: Retain immutable hash-only production cutover evidence',
  );
  const finalize = source.indexOf('name: Record successful production cutover');
  const cleanup = source.indexOf('name: Remove protected executor material');
  assert.ok(
    prerequisite >= 0 &&
      cutover > prerequisite &&
      retain > cutover &&
      finalize > retain &&
      cleanup > finalize,
  );
  const block = source.slice(cutover, retain);
  assert.match(block, /if: needs\.intake\.outputs\.operation == 'production-cutover'/);
  assert.match(block, /run-production-cutover\.mjs/);
  assert.match(
    block,
    /EXPECTED_CAPSULE_REQUEST_SHA256: \$\{\{ steps\.protected-transport\.outputs\.capsule_request_sha256 \}\}/,
  );
  assert.match(
    block,
    /EXPECTED_BROKER_REQUEST_ID: \$\{\{ needs\.intake\.outputs\.requestId \}\}/,
  );
  assert.match(
    block,
    /CLOUDFLARE_PRODUCTION_TOKEN: \$\{\{ secrets\.CLOUDFLARE_PRODUCTION_TOKEN \}\}/,
  );
  assert.match(
    block,
    /RESEND_PRODUCTION_ADMIN_TOKEN: \$\{\{ secrets\.RESEND_PRODUCTION_ADMIN_TOKEN \}\}/,
  );
  assert.match(
    block,
    /PRODUCTION_ACCESS_ADMIN_EMAIL: \$\{\{ secrets\.PRODUCTION_ACCESS_ADMIN_EMAIL \}\}/,
  );
  assert.match(source, /production-cutover-evidence-/);
  assert.match(
    source.slice(finalize, cleanup),
    /steps\.production-cutover\.outputs\.receipt_sha256/,
  );
  assert.doesNotMatch(block, /wrangler\s+(?:deploy|publish)/);
});
