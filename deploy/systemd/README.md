# systemd installation

The release archive ships the service unit and system user definition, but no
runtime configuration, credential, trust root, checkpoint, or signing
material. Provision those values for the exact deployment before enabling the
service.

Install `thunderboltd` and `thunderbolt-cli` under `/usr/local/bin`, install the
unit and sysusers file, then create the service account and private state tree:

```bash
systemd-sysusers /etc/sysusers.d/thunderbolt.conf
install -d -o thunderbolt -g thunderbolt -m 0700 /var/lib/thunderbolt
install -d -o thunderbolt -g thunderbolt -m 0700 /var/lib/thunderbolt/data
install -d -o thunderbolt -g thunderbolt -m 0700 /var/lib/thunderbolt/config
install -o thunderbolt -g thunderbolt -m 0600 runtime.toml \
  /var/lib/thunderbolt/runtime.toml
```

Place every referenced public manifest and credential file under an
operator-controlled owner-only directory. Do not store secret values inside
`runtime.toml`. For the packaged unit, configure `data_dir` below
`/var/lib/thunderbolt/data`, `control_dir` as `/run/thunderbolt`, and
`control_socket` as `/run/thunderbolt/control.sock`.

Validate as the service account before starting:

```bash
runuser -u thunderbolt -- \
  /usr/local/bin/thunderboltd --config /var/lib/thunderbolt/runtime.toml check
systemctl enable --now thunderboltd.service
runuser -u thunderbolt -- \
  /usr/local/bin/thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml status
```

The current packaged runtime is an operator shell. It reports process
liveness and immutable readiness blockers, but its role handlers are
unavailable and it remains `NotReady`. A later reviewed binary integration is
required before protocol work can execute. Do not interpret a running systemd
unit as protocol readiness.

## Independent Floor node

The rollback-floor node uses a different operating-system identity so it
cannot read Holder, Committee, or Ledger runtime material. Provision its state
tree separately:

```bash
install -d -o thunderbolt-floor -g thunderbolt-floor -m 0700 \
  /var/lib/thunderbolt-floor
install -d -o thunderbolt-floor -g thunderbolt-floor -m 0700 \
  /var/lib/thunderbolt-floor/config
install -d -o thunderbolt-floor -g thunderbolt-floor -m 0700 \
  /var/lib/thunderbolt-floor/data
install -o thunderbolt-floor -g thunderbolt-floor -m 0600 node.toml \
  /var/lib/thunderbolt-floor/config/node.toml
```

The Floor configuration must reference the reviewed canonical registry and
validator manifests by exact digest. Set its database below
`/var/lib/thunderbolt-floor/data`, and set the Unix ABCI endpoint to
`/run/thunderbolt-floor/abci.sock`. Generate the exact CometBFT genesis before
enabling the service:

```bash
runuser -u thunderbolt-floor -- \
  /usr/local/bin/thunderbolt-floor-node \
  --config /var/lib/thunderbolt-floor/config/node.toml check
test ! -e floor-genesis.json
umask 077
set -C
runuser -u thunderbolt-floor -- \
  /usr/local/bin/thunderbolt-floor-node \
  --config /var/lib/thunderbolt-floor/config/node.toml genesis > floor-genesis.json
```

Install `floor-genesis.json` into every Floor CometBFT validator only after its
bytes and validator set are independently compared. Configure CometBFT
`proxy_app` as `unix:///run/thunderbolt-floor/abci.sock`, then enable
`thunderbolt-floor-node.service`. Never run this service as the `thunderbolt`
role-daemon user.
