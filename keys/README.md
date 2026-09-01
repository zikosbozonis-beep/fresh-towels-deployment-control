# Release encryption key

Remote canary configuration must add one ASCII-armored **public** encryption
key as `release-encryption-public.asc`, its uppercase 40-hex primary fingerprint
as `release-encryption-fingerprint.txt`, and the exact encryption-subkey
fingerprint as `release-encryption-subkey-fingerprint.txt`.

The private key must never enter this repository. It belongs only in the
protected GitHub Environment and the independently proven recovery custody
path. Until the public key and remote controller identity are configured,
release handoff fails closed.

The protected executor validates both fingerprints after importing the secret
key. A matching primary key without the pinned secret encryption subkey is not
sufficient.
