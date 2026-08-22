# Support

Bitcoin Thunderbolt `v1.0.0` supports the protocol libraries, reference Ledger and rollback floor, local control CLI, and documented regtest and signet environments.

## Where to ask

- Open a bug report for reproducible incorrect behavior in a supported release.
- Open a feature request for a scoped proposal that fits the documented architecture.
- Use a documentation issue when a command, role, configuration field, or limitation is unclear.
- Use the private route in [SECURITY.md](SECURITY.md) for any suspected security or privacy issue.

Do not post a seed, key, committee share, wallet, database, control credential, operator configuration, or unredacted log.

## Before opening an issue

Check the README, operator guide, release notes, existing issues, and current changelog. Confirm the command exists in `thunderbolt-cli --help` for your exact commit. Planned APIs in `docs/api.md` are not necessarily implemented.

For a bug, include:

- Bitcoin Thunderbolt version and source commit
- operating system and architecture
- Bitcoin network, with regtest preferred
- daemon role and redacted effective configuration
- exact command or API operation
- expected and observed behavior
- minimal reproduction steps
- relevant redacted logs and correlation identifiers

Replace secret values with a description such as `[redacted control token]`. Do not replace only part of a private key or seed.

## Support boundaries

Maintainers can help with the documented source build, the current stable interface, regtest and signet behavior, and reproducible project defects. They cannot recover lost keys or funds, operate a committee for a user, audit a private deployment through a public issue, or guarantee response times.

Research benchmarks are maintained for reproducibility and regression. They are not a supported production service or a substitute for the daemon architecture.

If a third-party package, container, fork, Ledger, or deployment script causes the problem, reproduce it with the official source tree before filing a core issue.
