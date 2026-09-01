# Release encryption key

Remote canary configuration must add one ASCII-armored **public** encryption
key as `release-encryption-public.asc` plus its lowercase, 40-hex OpenPGP
fingerprint as `release-encryption-fingerprint.txt`.

The private key must never enter this repository. It belongs only in the
protected GitHub Environment and the independently proven recovery custody
path. Until the public key and remote controller identity are configured,
release handoff fails closed.
