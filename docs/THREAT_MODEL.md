# Deployment-control threat model

Status: design contract for a public, minimal control plane. It does not
authorize or perform a production deployment.

## Security invariant

A production mutation is permitted only when all of these statements are
true:

1. A protected controller revision validates a short-lived request from the
   one configured GitHub App identity.
2. The request names an immutable private-source repository ID and an exact
   40-character commit SHA. Names, branches and tags are never sufficient.
3. The approved release binds the controller SHA, plaintext artifact digest,
   ciphertext digest, release-evidence digest and exact private Release/asset
   numeric IDs.
4. Build/intake code receives no production credential. The protected deploy
   job receives credentials only after GitHub Environment approval.
5. The deploy job checks out only the protected controller. It never checks
   out or executes private application source, artifact scripts or request
   content.
6. The deploy job downloads one encrypted asset from an immutable private
   GitHub Release by exact release/asset IDs, verifies its
   ciphertext digest, decrypts it in a fresh runner, verifies its plaintext
   digest, and executes only an allowlisted controller operation.
7. The deployment initiator and required human reviewer are distinct. GitHub
   must prevent self-review and administrator bypass for the environment.
8. The authoritative provider result is reconciled to an immutable version
   identifier. A signed, hash-bound evidence record is stored outside both
   repositories with retention protection before the next mutation.
9. An interrupted or ambiguous remote operation fails closed and requires
   reconciliation; it is never retried blindly.

Branch protection, required checks and a protected Environment are controls
used to enforce the invariant. They are not substitutes for exact-SHA,
artifact-digest, credential-isolation or external-evidence checks.

## Trust boundaries

| Boundary | Trusted | Treated as hostile |
| --- | --- | --- |
| Public repository | Protected `main` bytes and pinned workflow actions | forks, pull requests, issue text, dispatch payloads |
| Release intake | configured GitHub App numeric actor ID and configured private repository numeric ID | repository names alone, users, mutable refs, stale requests |
| Artifact build | exact reviewed private commit, isolated runner, public encryption key | application code with respect to later production secrets |
| Artifact transport | immutable private GitHub Release, encrypted asset, exact release/asset IDs and digest | release name alone, mutable/latest aliases, public assets |
| Production executor | protected controller SHA, approved Environment, minimal provider credentials | decrypted artifact scripts, PR code, request-provided commands |
| Evidence | canonical hashes plus independently retained signed record | workflow logs or a Markdown claim that a gate passed |

## Threats and controls

- **Forged request:** require `repository_dispatch`, exact event type, configured
  Bot actor ID, configured repository ID, a UUID request ID and a narrow UTC
  validity window.
- **Branch or tag substitution:** accept lowercase full commit SHAs only and
  bind both source and controller commits.
- **Controller drift:** compare the contract controller SHA, event workflow
  SHA, checked-out `HEAD` and `GITHUB_SHA` immediately before execution.
- **Artifact substitution:** bind private release and asset IDs, ciphertext SHA-256,
  plaintext SHA-256, byte count, encryption-key fingerprint and evidence
  SHA-256; verify again after download and decryption.
- **Approval replay:** request IDs and nonces are single-use; expiration is at
  most 30 minutes after issuance; the protected run and public transparency
  attestation record consumption.
- **Self-approval or bypass:** requester is a GitHub App Bot; production
  Environment requires the owner reviewer, prevents self-review and disallows
  administrator bypass. An unapproved job receives no environment secret.
- **Pull-request secret theft:** deployment workflow is dispatch-only on
  protected `main`; fork/PR workflows run public-boundary and unit checks only.
- **Application-code credential theft:** no production secret exists in build
  or intake. Secret-bearing jobs never run application code or application
  package lifecycle scripts.
- **Malicious public contribution:** third-party Actions are pinned to full
  commit SHAs; untrusted event values are read from the event file and parsed,
  never interpolated into shell; operations are enum allowlisted.
- **Public leakage:** a repository-surface scanner rejects archives, databases,
  private keys, environment files, credential patterns, symlinks, oversized
  files and evidence fields outside the public schema.
- **Ambiguous provider outcome:** stop, reconcile authoritative provider state,
  record the outcome, and require a new request if identity cannot be proven.

## Public repository allowlist

Only generic workflows, validators, schemas, tests, public security
documentation and non-sensitive release ledgers are permitted. A release
ledger may contain hashes, exact commit SHAs, provider version IDs and opaque
private-object references. It must not contain source, plaintext artifacts,
configuration values, account identifiers, customer/lead data, credentials,
private keys, database exports, release assets or backups.

## Required remote proof before production use

The local tests prove parser and fail-closed behavior, not GitHub's remote
policy. Production remains blocked until read-back evidence proves:

- protected `main`, required unique checks, no force-push/delete and no bypass;
- a production Environment with the exact owner reviewer, prevent-self-review,
  protected-branch restriction and no administrator bypass;
- a GitHub App dispatch from its numeric Bot identity and least-privilege
  installation permissions;
- an unapproved/denied canary cannot read environment secrets;
- an immutable private Release with one encrypted asset, exact ID/digest
  retrieval and a public Sigstore transparency attestation of the approved
  ciphertext/receipt;
- every adversarial canary case fails before any provider mutation.
