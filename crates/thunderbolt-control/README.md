# Thunderbolt local control plane

`thunderbolt-control` is the local CLI-to-daemon boundary shared by Bitcoin
Thunderbolt roles. It is not the participant network protocol.

The server binds one absolute Unix-domain socket inside an owner-owned mode-0700
directory, rejects foreign or renameable canonical ancestry, hardens the socket
to mode 0600, and checks the kernel-reported peer effective UID before reading a
request. The client performs the same path and peer checks. Active sockets are
never replaced. Optional stale recovery and shutdown cleanup remove only the
previously inspected owner-owned socket inode; cleanup failure is reported.

Requests and responses use a fixed versioned binary frame with exact lengths,
nonzero 128-bit request IDs, restricted method names, and configurable bounds
under a 16 MiB absolute ceiling. A connection carries one request and one
response. Partial reads, oversized frames, handler deadlines, concurrency,
aggregate in-flight bytes, and shutdown drain time are bounded. Cancellation is
biased before accept and before handler admission.

`ControlClient::from_server_config` reuses the exact socket and frame bound and
derives a separate response deadline with checked
`handler_timeout + io_timeout` arithmetic. Connect and write operations remain
under the server's maximum 60-second I/O deadline. Only the post-write response
wait may reach 360 seconds, covering the maximum 300-second handler plus one
60-second response write. The response length prefix and body share that one
absolute budget rather than restarting it. Zero, overflow, and values even one
nanosecond above either bound fail before any socket I/O.

Payloads and error strings use zeroizing storage. Their `Debug` implementations
show lengths but not contents, and the envelopes are not `Clone`. Role handlers
must still keep private keys inside signer or keystore capabilities rather than
putting them in RPC payloads. Handlers are asynchronous, cancellation-safe
futures; blocking work must use a role-owned bounded executor and transactional
rollback on cancellation.

Any failure after a client begins writing is an ambiguous result. Handler
deadline, panic, response-ID mismatch, or oversized response returns a
correlated `Ambiguous` status when possible. The caller must retry the exact
same `RequestId`; it must never generate a fresh ID for an uncertain mutation.

Durable request idempotency remains the role service's responsibility. The
control layer preserves and checks the request ID but does not pretend an
in-memory cache can replace the Holder, Committee, or Ledger database.
