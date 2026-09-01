CREATE TABLE ciphertext_custody_objects (
  custody_id TEXT PRIMARY KEY NOT NULL,
  payload_kind TEXT NOT NULL CHECK (
    payload_kind IN ('secret', 'private_receipt')
  ),
  binding TEXT NOT NULL,
  resource_identity_sha256 TEXT NOT NULL,
  plaintext_sha256 TEXT NOT NULL,
  plaintext_bytes INTEGER NOT NULL CHECK (
    plaintext_bytes >= 1 AND plaintext_bytes <= 65536
  ),
  encryption_key_sha256 TEXT NOT NULL,
  ciphertext_sha256 TEXT NOT NULL,
  ciphertext_bytes INTEGER NOT NULL CHECK (
    ciphertext_bytes >= 1 AND ciphertext_bytes <= 65536
  ),
  ciphertext_base64url TEXT,
  state TEXT NOT NULL CHECK (
    state IN ('pending', 'active', 'revoked')
  ),
  decryption_proof_sha256 TEXT,
  created_by_request_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  confirmed_at INTEGER,
  revoked_at INTEGER,
  UNIQUE (payload_kind, binding, resource_identity_sha256),
  FOREIGN KEY (created_by_request_id)
    REFERENCES dispatch_consumptions (request_id),
  CHECK (
    (state = 'pending' AND ciphertext_base64url IS NOT NULL
      AND decryption_proof_sha256 IS NULL AND confirmed_at IS NULL
      AND revoked_at IS NULL) OR
    (state = 'active' AND ciphertext_base64url IS NOT NULL
      AND decryption_proof_sha256 IS NOT NULL AND confirmed_at IS NOT NULL
      AND revoked_at IS NULL) OR
    (state = 'revoked' AND ciphertext_base64url IS NULL
      AND revoked_at IS NOT NULL)
  )
) WITHOUT ROWID;

CREATE TABLE ciphertext_custody_grants (
  request_id TEXT NOT NULL,
  binding TEXT NOT NULL,
  custody_id TEXT NOT NULL,
  capsule_request_sha256 TEXT NOT NULL,
  target_sha256 TEXT,
  application_commit_sha TEXT NOT NULL,
  controller_commit_sha TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (request_id, binding),
  UNIQUE (request_id, custody_id),
  FOREIGN KEY (request_id)
    REFERENCES dispatch_consumptions (request_id),
  FOREIGN KEY (custody_id)
    REFERENCES ciphertext_custody_objects (custody_id)
) WITHOUT ROWID;

CREATE INDEX ciphertext_custody_lookup
  ON ciphertext_custody_objects (
    payload_kind,
    binding,
    resource_identity_sha256,
    state
  );

CREATE INDEX ciphertext_custody_grant_lookup
  ON ciphertext_custody_grants (custody_id, request_id);
