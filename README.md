# Fresh Towels deployment control

This public repository is a minimal deployment control plane. The application
repository remains private.

The public surface is deliberately limited to generic workflows, schemas,
validators, tests and non-sensitive release identities. It must never contain
application source, plaintext release artifacts, private configuration,
credentials, customer data, database content or backups.

The production executor is fail-closed. A repository clone or a passing local
test is not deployment authority. Remote branch protection, a protected GitHub
Environment, an independent reviewer, the configured GitHub App identity, a
private encrypted artifact transport and external immutable evidence must all
be proven before production use.

Run the public-surface and adversarial checks with:

```text
npm run check
```

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the invariant and the
remote proof still required.
