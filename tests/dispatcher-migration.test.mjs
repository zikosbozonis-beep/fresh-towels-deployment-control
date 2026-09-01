import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

test('dispatcher migration enforces unique consumption and one-way execution states', async () => {
  const database = new DatabaseSync(':memory:');
  try {
    database.exec(
      await readFile(
        new URL('../dispatcher/migrations/0001_dispatch_consumption.sql', import.meta.url),
        'utf8',
      ),
    );
    const insert = database.prepare(`INSERT INTO dispatch_consumptions (
      request_id, oidc_jti_sha256, nonce_sha256, request_sha256,
      source_repository_id, source_commit_sha, controller_commit_sha,
      source_workflow_run_id, source_workflow_run_attempt, state,
      claimed_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, ?)`);
    const values = ['request-1', 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64), '1', 'd'.repeat(40), 'e'.repeat(40), '2', 1, 1, 1];
    assert.equal(insert.run(...values).changes, 1);
    assert.throws(
      () => insert.run('request-2', ...values.slice(1)),
      /UNIQUE constraint failed/,
    );
    assert.equal(
      database.prepare("UPDATE dispatch_consumptions SET state = 'dispatched' WHERE request_id = ? AND state = 'claimed'").run('request-1').changes,
      1,
    );
    assert.equal(
      database.prepare("UPDATE dispatch_consumptions SET state = 'executing' WHERE request_id = ? AND state = 'dispatched'").run('request-1').changes,
      1,
    );
    assert.equal(
      database.prepare("UPDATE dispatch_consumptions SET state = 'executing' WHERE request_id = ? AND state = 'dispatched'").run('request-1').changes,
      0,
    );
  } finally {
    database.close();
  }
});

test('operation-prerequisite migration preserves rows and enforces one-time prerequisite consumption', async () => {
  const database = new DatabaseSync(':memory:');
  try {
    database.exec(
      await readFile(
        new URL('../dispatcher/migrations/0001_dispatch_consumption.sql', import.meta.url),
        'utf8',
      ),
    );
    database.prepare(`INSERT INTO dispatch_consumptions (
      request_id, oidc_jti_sha256, nonce_sha256, request_sha256,
      source_repository_id, source_commit_sha, controller_commit_sha,
      source_workflow_run_id, source_workflow_run_attempt, state,
      claimed_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, ?)`).run(
      'legacy-request',
      'a'.repeat(64),
      'b'.repeat(64),
      'c'.repeat(64),
      '1001',
      'd'.repeat(40),
      'e'.repeat(40),
      '5005',
      1,
      1,
      1,
    );
    database.exec(
      await readFile(
        new URL('../dispatcher/migrations/0002_operation_prerequisites.sql', import.meta.url),
        'utf8',
      ),
    );
    assert.equal(
      database.prepare('SELECT operation FROM dispatch_consumptions WHERE request_id = ?')
        .get('legacy-request').operation,
      'legacy',
    );
    const insert = database.prepare(`INSERT INTO dispatch_consumptions (
      request_id, oidc_jti_sha256, nonce_sha256, request_sha256, operation,
      source_repository_id, source_commit_sha, controller_commit_sha,
      source_workflow_run_id, source_workflow_run_attempt, state,
      prerequisite_request_id, prerequisite_receipt_sha256,
      claimed_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'executing', ?, ?, ?, ?)`);
    insert.run(
      'bootstrap-one', '1'.repeat(64), '2'.repeat(64), '3'.repeat(64),
      'production-bootstrap', '1001', '4'.repeat(40), '5'.repeat(40), '6006', 1,
      'provider-canary-one', '6'.repeat(64), 2, 2,
    );
    assert.throws(
      () => insert.run(
        'bootstrap-two', '7'.repeat(64), '8'.repeat(64), '9'.repeat(64),
        'production-bootstrap', '1001', '4'.repeat(40), '5'.repeat(40), '7007', 1,
        'provider-canary-one', 'a'.repeat(64), 3, 3,
      ),
      /UNIQUE constraint failed/,
    );
    assert.throws(
      () => database.prepare(`INSERT INTO dispatch_consumptions (
        request_id, oidc_jti_sha256, nonce_sha256, request_sha256, operation,
        source_repository_id, source_commit_sha, controller_commit_sha,
        source_workflow_run_id, source_workflow_run_attempt, state,
        prerequisite_request_id, prerequisite_receipt_sha256,
        claimed_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'executing', ?, NULL, ?, ?)`).run(
        'bootstrap-three', 'b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64),
        'production-bootstrap', '1001', '4'.repeat(40), '5'.repeat(40), '8008', 1,
        'provider-canary-three', 4, 4,
      ),
      /CHECK constraint failed/,
    );
  } finally {
    database.close();
  }
});
