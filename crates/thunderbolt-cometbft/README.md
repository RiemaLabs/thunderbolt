# Thunderbolt CometBFT finality

`thunderbolt-cometbft` turns a pinned CometBFT light-client trust root and a
strictly adjacent primary trace plus independently sourced witness traces into
a typed Bitcoin Thunderbolt execution-finality receipt.

The binding follows CometBFT's ABCI 2.0 timing precisely. Application state
produced while executing height `H` is committed in the header at height
`H + 1`. A receipt therefore verifies both the signed header at `H` and the
signed committing header at `H + 1`. It checks the execution time and previous
application hash against header `H`, and the resulting application hash
against header `H + 1`.

The verifier rejects a primary-only update. It requires at least one bounded,
fully verified witness trace from a distinct provider and compares every header
hash before issuing a receipt or an updated trust root. `FinalityVerifier` owns
a `TraceSourceAuthenticator`; the verifier ignores `LightBlock.provider` and
accepts a peer identity only through a one-use capability bound to the exact
trace. A production authenticator must prove independently configured RPC
sessions, such as pinned mTLS peers. This crate intentionally provides no
permissive authenticator. It also does not fetch headers, choose a trust root,
produce attack evidence, persist trusted state, verify application-state
inclusion proofs, or run ABCI.

Operators must pin the initial height, application version, and header hash out
of band, keep the trust root within the configured trusting period, durably
advance it, and enforce a raw RPC body limit before decoding `LightBlock`
values. A receipt is an in-process capability and is intentionally not
serializable. Cross-process users must receive the full untrusted proof and run
the verifier locally.
