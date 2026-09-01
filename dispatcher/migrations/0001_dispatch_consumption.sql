CREATE TABLE dispatch_consumptions (
  request_id TEXT PRIMARY KEY NOT NULL,
  oidc_jti_sha256 TEXT NOT NULL UNIQUE,
  nonce_sha256 TEXT NOT NULL UNIQUE,
  request_sha256 TEXT NOT NULL UNIQUE,
  source_repository_id TEXT NOT NULL,
  source_commit_sha TEXT NOT NULL,
  controller_commit_sha TEXT NOT NULL,
  source_workflow_run_id TEXT NOT NULL,
  source_workflow_run_attempt INTEGER NOT NULL,
  executor_jti_sha256 TEXT UNIQUE,
  controller_workflow_run_id TEXT UNIQUE,
  controller_workflow_run_attempt INTEGER,
  execution_receipt_sha256 TEXT,
  state TEXT NOT NULL CHECK (
    state IN ('claimed', 'dispatched', 'ambiguous', 'executing', 'canary_verified', 'executed', 'execution_ambiguous')
  ),
  dispatch_http_status INTEGER,
  claimed_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX dispatch_consumptions_state_updated
  ON dispatch_consumptions (state, updated_at);
