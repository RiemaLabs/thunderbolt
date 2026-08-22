# Bitcoin Thunderbolt runtime configuration

This crate parses one secret-free TOML document for a Ledger, Holder, or
Committee process and maps it through the role policy constructors. TOML
values may contain public identities and owner-only file references, never
passwords, tokens, credentials, private keys, Shamir shares, Paillier private
keys, signing nonces, or secret material.

Parsing is deliberately two-phase. `ParsedRuntimeConfig::parse_toml` rejects
unknown fields, forbidden secret-bearing keys, ambiguous networks, inconsistent
profile derivations, unsafe URL forms, zero values, unsupported versions, and
out-of-range limits. `validate_filesystem` then checks absolute normalized
paths, rejects symlinks, requires owner-only directories and files, and verifies
the exact hashes of public descriptor, profile, trust-root, and checkpoint
provider-manifest references. It retains validated file descriptors plus inode
and digest receipts, rejects hard-link aliases, and requires a fresh
`revalidate_for_handoff` before role policies become accessible. Public
references are rehashed and TLS inputs are parsed again at handoff.

A checkpoint provider manifest records provider metadata. The runtime checks
its provider, trust-domain, and profile identifiers against the injected
checkpoint capability before reporting readiness. The redacted view omits
paths and network endpoints.

The finality verifier profile is mechanically derived from the canonical
profile-manifest digest plus a digest of the exact Comet root, source roster,
trust policy, coordinator bounds, and RPC policy. Cross-role policy drift
therefore changes the profile ID and is rejected.

HTTPS Comet profiles additionally require one to eight digest-pinned CA files
and owner-only client-certificate/private-key references. The config stores no
certificate or key bytes. The concrete runtime must load those references
through the Comet RPC client's `ClientIdentityProvider`. Literal-loopback HTTP
is accepted only for regtest and rejects TLS credential references to avoid an
ambiguous security profile. RPC response, aggregate, validator, header, retry,
and deadline limits map through the committed Comet RPC constructors.

The three files under `examples/` are structurally valid regtest samples. Their
placeholder reference hashes and absolute paths must be replaced with hashes
of actual canonical owner-only files before filesystem validation.
