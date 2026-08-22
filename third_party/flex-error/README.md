# Vendored flex-error 0.4.4

This directory contains the source distributed as `flex-error` 0.4.4 by
Informal Systems under Apache-2.0.

Bitcoin Thunderbolt carries one maintenance patch: the archived `paste`
procedural macro dependency is replaced with the maintained, API-compatible
`pastey` successor. The library API and all other source are unchanged.

The copy exists because `tendermint-rs` 0.40.4 depends on `flex-error` 0.4.4,
whose released manifest still selects `paste`. Remove this patch when an
upstream `tendermint-rs` release no longer resolves the archived dependency.

Upstream: <https://github.com/informalsystems/flex-error/tree/v0.4.4>
