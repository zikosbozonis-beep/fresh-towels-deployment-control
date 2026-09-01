# Fresh Towels deployment control

This public repository is a minimal deployment control plane. The application
repository remains private.

The public surface is deliberately limited to generic workflows, schemas,
validators, tests and non-sensitive release identities. It must never contain
application source, plaintext release artifacts, private configuration,
credentials, customer data, database content or backups.

The production executor is fail-closed. A repository clone or a passing local
test is not deployment authority. Remote branch protection, a protected GitHub
Environment, an independent reviewer, the OIDC dispatcher with atomic D1
consumption, the public-only GitHub App, the private encrypted orphan transport
and external provider evidence must all be proven before production use.

The private caller receives no controller/App/production secret. It encrypts a
fixed capsule with the public release key, publishes only `manifest.json` and
`release.gpg` to an immutable private Release, then presents GitHub-signed OIDC
evidence to the dispatcher. The protected executor fetches with a read-only
deploy key only after independent approval. The provider adapter intentionally
remains fail-closed until the non-production remote canary is proven.

The reusable handoff requires an explicit `canary` or `production-release`
operation. A canary still requires independent review, one-time OIDC/D1
execution claiming, private transport fetch, decryption and digest validation,
but it performs no provider mutation and records only a hash receipt. The
production path remains stopped before mutation until that remote canary and a
fixed controller-owned provider adapter are separately proven.

Run the public-surface and adversarial checks with:

```text
npm run check
```

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the invariant and the
remote proof still required.
