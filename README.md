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
deploy key only after independent approval. The provider adapter is a fixed,
least-privilege, exact-release-bound and fail-closed controller component.

The reusable handoff accepts only an explicit allowlisted operation. The
ordered production chain is `provider-canary` -> `production-dns-stage` ->
`production-bootstrap` -> `production-release` -> `production-cutover`.
DNS-stage may create a pending production zone or renew a read-only attestation
for an already-active exact zone, bind the exact DNS mirror and Resend
verification records, and enforce the approved zone security settings;
it cannot change registrar delegation or production traffic. Bootstrap accepts
only the fresh encrypted stage receipt and independently proves active
delegation, DS absence, exact provider state and the external WordPress fallback
before D1 or Access provisioning. The production candidate temporarily adds
only the public lead and webhook routes to the three Access-protected dashboard
routes, then restores that exact three-route pre-cutover baseline. Cutover
requires the same baseline and restores it on any material failure.

The protected Cloudflare production token must be scoped only to the reviewed
account/zone and the implemented operations. DNS stage specifically requires
Zone:Read, DNS:Edit and Zone Settings:Edit; the last permission is exercised by
exact readback of `ssl=strict`, `always_use_https=on` and
`min_tls_version=1.2`. HSTS is deliberately outside this operation.

Run the public-surface and adversarial checks with:

```text
npm run check
```

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the invariant and the
remote proof still required.
