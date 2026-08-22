# Security policy

## Release status

Bitcoin Thunderbolt is currently released for regtest and signet deployments. Mainnet activation is not enabled in this release candidate.

Once the RC is public, the latest RC receives security fixes. Older development snapshots may be used to reproduce research results, but they are not supported operator releases.

| Version | Security fixes | Mainnet approved |
| --- | --- | --- |
| `1.0.0-rc.1` | Yes | No |
| Older RCs and research snapshots | No | No |

## Report a vulnerability

Use the private "Report a vulnerability" form on this repository's Security tab. GitHub private vulnerability reporting must be enabled and tested before the repository is made public.

Do not open a public issue, discussion, or pull request for a suspected vulnerability.

Include:

- affected commit, release, and component
- impact and the assumptions needed to trigger it
- minimal reproduction steps or a proof of concept
- whether mainnet, testnet, signet, or regtest is involved
- any evidence that a secret, share, credential, or real asset is at risk
- a safe way for maintainers to ask follow-up questions through the private report

Redact secrets and personal data. Do not upload private keys, seeds, committee shares, control tokens, database wrapping keys, threshold nonces, or credentials. Describe their type and location instead.

## What happens next

The security team targets an acknowledgement within three business days and an initial triage within seven business days. Complex cryptographic or distributed-systems reports may take longer to validate. Maintainers will use the private report for status updates and coordinate a disclosure date after affected users have a fix or mitigation.

A report may lead to a private advisory, patch, release, dependency update, operator mitigation, or a documented explanation that the behavior is outside the supported threat model. Credit is offered unless the reporter asks to remain anonymous.

## Scope

High-priority areas include:

- ownership or fixed-key invariant violations
- forged, replayed, cross-channel, wrong-network, or stale-state protocol events
- committee share recovery below threshold
- threshold-signing nonce reuse or unauthorized finalization
- Ledger equivocation, ordering, persistence, or availability failures under the documented model
- control-plane authentication or authorization bypass
- secret leakage through storage, backup, logs, metrics, crashes, or releases
- database corruption, rollback, duplicate operation, or restart safety defects
- Bitcoin transaction, fee, confirmation, replacement, or reorganization handling
- dependency or build compromise affecting release artifacts

The paper's research benchmarks and unsupported third-party deployment configurations are not operator products, but security defects in shared code are still in scope.

## Safe testing

Use regtest, local fixtures, and assets you control. Do not test against another operator, public service, or real funds without written permission. Avoid denial of service, privacy invasion, data destruction, social engineering, and access to information beyond what is needed to demonstrate the issue.

There is no public bug bounty at this time. A report does not create a payment obligation.
