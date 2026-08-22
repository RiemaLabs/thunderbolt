# Thunderbolt ABCI Server

`thunderbolt-abci-server` is the shared, production-bounded CometBFT v0.38
ABCI 2.0 transport for Thunderbolt applications. It dispatches every v0.38
request to the matching `tendermint_abci::Application` callback and never
interprets application state, consensus, or finality.

## Boundary

- TCP is numeric loopback-only. There is no remote-bind or TLS mode. Loopback
  TCP is not per-user authentication; deployments that need local user
  isolation should use the Unix endpoint.
- Unix sockets live under a canonical, current-user-owned `0700` directory.
  The server uses a separate owner-only inode lock, rejects active, foreign,
  symlinked, or hard-linked paths, creates the socket as `0600`, and removes
  only the exact socket and lock inodes it acquired.
- Canonical protobuf lengths are capped before payload allocation. Connection
  count, request and response sizes, and aggregate in-flight reservations are
  all hard bounded. A zero-allocation v0.38 schema preflight counts every
  allocation-producing repeated request value before `prost` decode; its cap
  must be identical across consensus replicas. Compile-time type-size checks
  bind the per-item reservation to the exact v0.38 schema.
- Idle, header, individual read, complete-frame, schema-decode, write, callback,
  and shutdown deadlines are mandatory and capped. Malformed or over-budget
  decode work closes only its connection; the process-fatal callback timer
  starts only after successful decode. A shutdown stops admission first, closes
  current sockets, then joins every connection and callback worker.
- `RunningServer` is `must_use`. Dropping it performs the same stop-and-join
  path as `shutdown_and_join`.

## Fatal policy

Synchronous `Application` callbacks cannot be safely cancelled. A callback
panic, callback deadline, server invariant failure, unjoined worker, or exact
cleanup failure therefore crosses `FatalServerHandler::terminate`, whose
return type is `!`. Production implementations must terminate the complete
process or otherwise end the hosting session. They must not panic, park, or
return a clean server status. `ProcessExitFatalServerHandler` is the supplied
production policy.

No response is written after a callback deadline. The per-handler byte permit
stays owned by that callback until it returns or the process terminates.
Every completed callback thread is joined before the connection accepts its
next request; callback join handles do not accumulate behind listener polling.
Application callbacks must not perform externally visible side effects that
violate their own ABCI commit boundary. The transport bounds its frame and
worker reservations; each application remains responsible for bounding its
own callback-internal computation and allocation.

## Integration

Construct a validated `ServerLimits`, `ServerDeadlines`, and local
`ServerEndpoint`, then call `start` with either the Ledger or rollback-floor
ABCI adapter. The adapter remains responsible for application version,
genesis/profile validation, durable Commit semantics, and any fatal storage
boundary. This crate does not provide network finality, TLS, authorization, a
remote listener, snapshots, or vote-extension policy of its own.
