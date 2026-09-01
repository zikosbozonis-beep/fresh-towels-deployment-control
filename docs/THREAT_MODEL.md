# Deployment-control threat model

Status: design contract for a public, minimal control plane. It does not
authorize or perform a production deployment.

## Security invariant

A production mutation is permitted only when all of these statements are
true:

1. An external dispatcher validates GitHub-signed OIDC claims from the exact
   reusable controller workflow, atomically consumes the request in D1, and
   dispatches through one public-repository-only GitHub App installation.
2. The request names an immutable private-source repository ID and an exact
   40-character commit SHA. Names, branches and tags are never sufficient.
3. The approved release binds the controller SHA, plaintext artifact digest,
   ciphertext digest, release-evidence digest, private Release ID, exact tag,
   parentless transport commit and the two expected Git blob IDs.
4. Build/intake code receives no production credential. The protected deploy
   job receives credentials only after GitHub Environment approval.
5. The deploy job checks out only the protected controller. It never checks
   out or executes private application source, artifact scripts or request
   content.
6. The deploy job uses a read-only SSH deploy key to fetch only the exact tag
   into an empty bare repository. It requires a parentless commit whose tree is
   exactly `manifest.json` plus `release.gpg`, verifies every bound digest,
   decrypts offline, parses a fixed two-file tar allowlist and never checks out
   or executes private source.
7. The deployment initiator and required human reviewer are distinct. GitHub
   must prevent self-review and administrator bypass for the environment.
8. After Environment approval, a second GitHub OIDC identity atomically moves
   the consumed request from `dispatched` to `executing`. A rerun, duplicate,
   self-review or changed controller cannot obtain a second execution claim.
9. The authoritative provider result is reconciled to an immutable version
   identifier. Its sanitized digest and terminal state are retained outside
   both repositories before another mutation is allowed.
10. An interrupted or ambiguous remote operation fails closed and requires
   reconciliation; it is never retried blindly.

The `canary` operation crosses the same approval, identity, replay and private
transport boundaries as production, then records a hash-only
`canary_verified` receipt without invoking any provider mutation. The
`production-release` operation cannot mutate a provider until the fixed
controller-owned adapter is added after that remote proof.

Branch protection, required checks and a protected Environment are controls
used to enforce the invariant. They are not substitutes for exact-SHA,
artifact-digest, credential-isolation or external-evidence checks.

## Trust boundaries

| Boundary | Trusted | Treated as hostile |
| --- | --- | --- |
| Public repository | Protected `main` bytes and pinned workflow actions | forks, pull requests, issue text, dispatch payloads |
| Release intake | exact GitHub OIDC claims, configured numeric repository IDs, atomic D1 consumption | repository names alone, users, mutable refs, stale or replayed requests |
| Artifact build | exact reviewed private commit, isolated runner, public encryption key | application code with respect to later production secrets |
| Artifact transport | immutable private GitHub Release, exact orphan commit/tag/tree/blob identities, encrypted payload | release name alone, mutable/latest aliases, public artifacts |
| Production executor | protected controller SHA, approved Environment, minimal provider credentials | decrypted artifact scripts, PR code, request-provided commands |
| Evidence | canonical hashes plus independently retained signed record | workflow logs or a Markdown claim that a gate passed |

## Threats and controls

- **Forged request:** verify GitHub's RS256 OIDC signature, issuer, audience,
  source/controller repository IDs, exact workflow refs/SHAs, run identity,
  event, ref, visibility and a narrow UTC validity window.
- **Branch or tag substitution:** accept lowercase full commit SHAs only and
  bind both source and controller commits.
- **Controller drift:** compare the contract controller SHA, event workflow
  SHA, checked-out `HEAD` and `GITHUB_SHA` immediately before execution.
- **Artifact substitution:** bind the private Release ID, tag, commit and blob IDs, ciphertext SHA-256,
  plaintext SHA-256, byte count, encryption-key fingerprint and evidence
  SHA-256; verify again after download and decryption.
- **Approval replay:** D1 uniquely consumes hashed OIDC `jti`, request ID,
  hashed nonce and canonical request digest before dispatch. Failure after the
  claim is terminal/ambiguous and never retried. A second atomic claim after
  Environment approval is required before execution.
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
- an immutable private Release whose exact tag resolves to the approved
  parentless commit and two allowed blobs;
- dispatcher D1 uniqueness under concurrent replay and an ambiguous-failure
  reconciliation drill;
- protected executor OIDC and one-time execution-claim behavior;
- a sanitized provider receipt retained outside both repositories;
- every adversarial canary case fails before any provider mutation.
