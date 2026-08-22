# `thunderbolt-bitcoin`

This crate is Bitcoin Thunderbolt's fail-closed Bitcoin Core boundary. It
provides a bounded JSON-RPC client, explicit network and genesis checks, a
reorg-aware chain cursor, and pure funding and closing-transaction validators.

The release candidate supports regtest, signet, and testnet3. Mainnet and
testnet4 are intentionally rejected until the release gates for those networks
are complete.

## Security boundary

- Plain HTTP is accepted only for literal loopback IP addresses. Remote nodes
  require HTTPS with normal certificate validation.
- Authentication comes from a no-follow, owner-only Bitcoin Core cookie or an
  operator-provided credential provider. Credentials are never formatted or
  logged by this crate.
- Request and response bodies, timeouts, retries, and chain synchronization are
  bounded. Only idempotent reads are retried. Transaction broadcasts are sent
  exactly once.
- Every response must contain the exact JSON-RPC request ID. Returned block
  headers and transactions are checked against the requested hash or txid.
- The crate does not contain private-key, wallet, or signing functionality.

Applications should construct [`RpcConfig`](https://docs.rs/thunderbolt-bitcoin/latest/thunderbolt_bitcoin/struct.RpcConfig.html),
choose a credential provider, and call `BitcoinCoreClient::connect`. Connection
does not succeed until both the chain name and genesis block match the selected
network.
