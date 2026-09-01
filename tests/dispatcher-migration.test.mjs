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
