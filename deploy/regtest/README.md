# Container operator shell

This Compose file runs the fail-closed Thunderbolt operator shell on regtest. It
does not create protocol trust, credentials, committee material, or signing
hooks. The packaged daemon reports `Live` and `NotReady` because its role
handlers are unavailable. A later reviewed binary integration is required
before this topology can execute protocol work.

Provision two host directories before starting the container:

- `THUNDERBOLT_CONFIG_DIR` is mounted read-only at
  `/var/lib/thunderbolt/config`. It must be owned by UID and GID `10001`, have
  mode `0700`, and contain an owner-only `runtime.toml` plus every exact public
  manifest and credential reference named by that configuration. Files must
  have mode `0400` or `0600`; do not use symlinks or hard-link aliases.
- `THUNDERBOLT_DATA_DIR` is mounted read-write at
  `/var/lib/thunderbolt/data`. It must be owned by UID and GID `10001` with mode
  `0700`. Role databases and vault paths in `runtime.toml` must remain below
  this mount.

Set `control_dir` to `/run/thunderbolt` and `control_socket` to
`/run/thunderbolt/control.sock`. Start only after materializing one of the
role-specific templates under
[`crates/thunderbolt-runtime-config/examples`](../../crates/thunderbolt-runtime-config/examples/)
with the deployment's real paths, digests, identities, trust policy, and
credential references.

```bash
export THUNDERBOLT_CONFIG_DIR=/absolute/operator-owned/config
export THUNDERBOLT_DATA_DIR=/absolute/operator-owned/data
docker compose --file deploy/regtest/compose.yaml up --build --detach
docker compose --file deploy/regtest/compose.yaml exec -T thunderboltd \
  thunderbolt-cli --config /var/lib/thunderbolt/config/runtime.toml status
docker compose --file deploy/regtest/compose.yaml exec -T thunderboltd \
  thunderbolt-cli --config /var/lib/thunderbolt/config/runtime.toml blockers
```

The Compose health check is process liveness only. It does not assert protocol
readiness. Inspect `status` and `blockers` before allowing any dependent
service to treat this process as ready.

## Floor container

The image also contains the independently reviewed `thunderbolt-floor-node`,
but it must run as UID and GID `10002`, not as the role-daemon user. Provision
separate owner-only Floor configuration and data directories. In `node.toml`,
place manifests below `/var/lib/thunderbolt-floor/config`, the database below
`/var/lib/thunderbolt-floor/data`, and the ABCI socket at
`/run/thunderbolt-floor/abci.sock`.

```bash
docker run --rm --read-only --user 10002:10002 \
  --entrypoint /usr/local/bin/thunderbolt-floor-node \
  --mount type=bind,src=/absolute/floor-config,dst=/var/lib/thunderbolt-floor/config,readonly \
  --mount type=bind,src=/absolute/floor-data,dst=/var/lib/thunderbolt-floor/data \
  --tmpfs /run/thunderbolt-floor:rw,noexec,nosuid,nodev,mode=0700,uid=10002,gid=10002 \
  bitcoin-thunderbolt:1.0.0 \
  --config /var/lib/thunderbolt-floor/config/node.toml check
```

Use the same mounts with `genesis` to create and independently compare the
CometBFT genesis, then with `start` to serve ABCI. Set CometBFT `proxy_app` to
`unix:///run/thunderbolt-floor/abci.sock`. Do not mount role-daemon state or
credentials into the Floor container.
