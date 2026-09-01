CREATE TABLE dispatch_consumptions_v2 (
  request_id TEXT PRIMARY KEY NOT NULL,
  oidc_jti_sha256 TEXT NOT NULL UNIQUE,
  nonce_sha256 TEXT NOT NULL UNIQUE,
  request_sha256 TEXT NOT NULL UNIQUE,
  operation TEXT NOT NULL CHECK (
    operation IN ('legacy', 'canary', 'provider-canary', 'production-dns-stage', 'production-bootstrap', 'production-release', 'production-cutover')
  ),
  source_repository_id TEXT NOT NULL,
  source_commit_sha TEXT NOT NULL,
  controller_commit_sha TEXT NOT NULL,
  source_workflow_run_id TEXT NOT NULL,
  source_workflow_run_attempt INTEGER NOT NULL,
  executor_jti_sha256 TEXT UNIQUE,
  controller_workflow_run_id TEXT UNIQUE,
  controller_workflow_run_attempt INTEGER,
  execution_receipt_sha256 TEXT,
  prerequisite_request_id TEXT UNIQUE,
  prerequisite_receipt_sha256 TEXT,
  state TEXT NOT NULL CHECK (
    state IN ('claimed', 'dispatched', 'ambiguous', 'executing', 'canary_verified', 'executed', 'execution_ambiguous')
  ),
  dispatch_http_status INTEGER,
  claimed_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (
    (prerequisite_request_id IS NULL AND prerequisite_receipt_sha256 IS NULL) OR
    (prerequisite_request_id IS NOT NULL AND prerequisite_receipt_sha256 IS NOT NULL)
  )
) WITHOUT ROWID;

INSERT INTO dispatch_consumptions_v2 (
  request_id, oidc_jti_sha256, nonce_sha256, request_sha256, operation,
  source_repository_id, source_commit_sha, controller_commit_sha,
  source_workflow_run_id, source_workflow_run_attempt,
  executor_jti_sha256, controller_workflow_run_id,
  controller_workflow_run_attempt, execution_receipt_sha256, state,
  prerequisite_request_id, prerequisite_receipt_sha256,
  dispatch_http_status, claimed_at, updated_at
)
SELECT
  request_id, oidc_jti_sha256, nonce_sha256, request_sha256, 'legacy',
  source_repository_id, source_commit_sha, controller_commit_sha,
  source_workflow_run_id, source_workflow_run_attempt,
  executor_jti_sha256, controller_workflow_run_id,
  controller_workflow_run_attempt, execution_receipt_sha256, state,
  NULL, NULL, dispatch_http_status, claimed_at, updated_at
FROM dispatch_consumptions;

DROP TABLE dispatch_consumptions;
ALTER TABLE dispatch_consumptions_v2 RENAME TO dispatch_consumptions;

CREATE INDEX dispatch_consumptions_state_updated
  ON dispatch_consumptions (state, updated_at);

CREATE INDEX dispatch_consumptions_prerequisite
  ON dispatch_consumptions (
    operation,
    state,
    source_repository_id,
    source_commit_sha,
    controller_commit_sha,
    execution_receipt_sha256,
    updated_at
  );
