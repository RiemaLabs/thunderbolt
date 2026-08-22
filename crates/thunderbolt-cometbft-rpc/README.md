# Thunderbolt authenticated CometBFT RPC

`thunderbolt-cometbft-rpc` is the concrete network boundary for
`thunderbolt-cometbft-client`. It fetches every adjacent signed header and the
complete current/next validator sets, then returns an undecoded bounded trace
body plus a non-serializable authenticated-session capability.

Production peers use HTTPS with a caller-supplied CA set, exact DNS name,
expected CometBFT node id, exact leaf-SPKI SHA-256, and a client-certificate
resolver supplied by a private-key provider. The built-in PEM provider opens
owner-only absolute key paths with no-follow semantics and loads the key once;
key bytes never enter peer configuration, serde, or `Debug`. The transport uses
direct TCP and hyper/rustls, so redirects, proxies, environment credentials,
cookies, and ambient trust roots are absent.

Plain HTTP is absent from default builds. Enabling the non-default `regtest`
feature exposes an explicit constructor that accepts only a literal loopback
IP. It is not a production authentication mechanism.

All RPC bodies are byte-capped before JSON decode. Status, HTTP status,
content type, JSON-RPC id, chain id, node id, height, validator pagination,
validator hashes, and aggregate trace work are checked. Retries are limited to
configured idempotent reads and share the coordinator deadline.

One authenticated HTTP/1.1 connection is reused for the complete trace. The
session transcript binds the actual leaf SPKI and TLS exporter, status-derived
node id, exact request, and exact trace. RPC traces are capped at 256 adjacent
headers; larger trust gaps must advance in multiple coordinator updates.

## Production configuration

An HTTPS peer needs five explicit inputs: its origin URL, CometBFT node id,
leaf-certificate SPKI pin, CA certificates, and client-identity provider. The
SPKI pin is SHA-256 over the exact DER `SubjectPublicKeyInfo` bytes from the
leaf certificate. It is not a hash of the complete certificate or of a raw
public-key encoding.

```rust,no_run
use std::num::NonZeroU8;
use std::str::FromStr;
use std::time::Duration;
use tendermint::node::Id;
use thunderbolt_cometbft_rpc::{
    CometBftRpcTransport, HttpsPeer, OwnerOnlyPemClientIdentity, RetryPolicy,
    RpcLimits, RpcPeer, RpcTransportConfig,
};

# fn configure(
#     ca_der: Vec<rustls::pki_types::CertificateDer<'static>>,
#     spki_sha256: [u8; 32],
# ) -> Result<CometBftRpcTransport, Box<dyn std::error::Error>> {
let client = OwnerOnlyPemClientIdentity::load(
    "/var/lib/thunderbolt/tls/client-chain.pem",
    "/var/lib/thunderbolt/tls/client-key.pem",
)?;
let peer = HttpsPeer::new(
    "https://rpc-1.example.net:26657",
    Id::from_str("0123456789abcdef0123456789abcdef01234567")?,
    spki_sha256,
    ca_der,
    &client,
)?;
let limits = RpcLimits::new(
    1 << 20,
    16 << 20,
    256,
    64,
    NonZeroU8::new(50).ok_or("page size")?,
    32,
    32 << 10,
)?;
let retry = RetryPolicy::new(
    NonZeroU8::new(3).ok_or("attempts")?,
    Duration::from_millis(100),
)?;
let transport = CometBftRpcTransport::new(RpcTransportConfig::new(
    vec![RpcPeer::Https(peer)],
    limits,
    retry,
)?)?;
# Ok(transport)
# }
```

CA files are parsed by the operator/runtime layer and passed as DER
certificates; there are no ambient system roots. The RPC server must require
and validate the configured client certificate. The client rejects a server
that does not request one. `ClientIdentityProvider` and rustls signing are
synchronous handshake hooks, so implementations must be bounded and
nonblocking. A remote HSM/KMS signer that can block is unsupported unless a
local provider enforces its own shorter deadline outside the Tokio task.

The built-in PEM provider requires absolute paths under an owner-private
canonical directory, opens files without following the final symlink, and
requires the key to be owner-readable with no group/other permissions (normally
`0400` or `0600`).

## Operations

- Certificate or CA rotation is an explicit roster change. Deploy the new
  server and client trust material first, calculate the new leaf-SPKI pin, then
  install a new immutable peer and advance the coordinator source-configuration
  version. Because the SPKI digest is the transport identity, never reuse the
  old identity for a new certificate.
- A gap above 256 headers is advanced through consecutive coordinator updates
  of at most 256 headers each. Every update must still complete within the
  pinned root's trusting period; the transport does not extend an expired root.
- Retry attempts are limited to one through five. TCP connection failures,
  incomplete responses after an authenticated response, and HTTP
  408/429/500/502/503/504 are retryable. Certificate, SPKI, content, identity,
  pagination, and bound failures are permanent. Before the first authenticated
  HTTPS response, a reset is deliberately treated as a permanent TLS failure:
  with TLS 1.3 the client-certificate rejection alert can otherwise be
  indistinguishable from an early connection close.
- The caller must run inside a Tokio runtime with networking, timers, and task
  spawning enabled. Dropping the fetch future aborts the Hyper connection
  driver and closes the session; one absolute coordinator deadline covers DNS,
  TCP, TLS, every RPC body, and retry delay.

## Four-node compatibility gate

The ignored `optional_live_four_node_regtest_gate` exercises four stock local
CometBFT RPC nodes. Build with the non-default `regtest` feature, set
`THUNDERBOLT_COMETBFT_LIVE_CONFIG` to an owner-controlled JSON file containing
`chain_id`, `first_height`, `last_height`, and exactly four entries with
`url`, `node_id`, and 32-byte `binding_hex`, then run:

```text
cargo test -p thunderbolt-cometbft-rpc --features regtest \
  tests::optional_live_four_node_regtest_gate -- --ignored --exact
```

Every URL in this gate must be a literal loopback HTTP origin. The gate is for
wire/schema compatibility only and does not weaken the production HTTPS path.
