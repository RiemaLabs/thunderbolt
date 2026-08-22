# Governance

Bitcoin Thunderbolt is maintained in public. Technical decisions favor safety, protocol clarity, reviewable changes, and reproducible evidence.

## Roles

Contributor
: Anyone who reports an issue, reviews a change, improves documentation, submits code, or helps test a release.

Reviewer
: A contributor with demonstrated knowledge in an area who can provide a required focused review. Reviewers do not merge changes unless they are also maintainers.

Maintainer
: A trusted contributor with merge and triage access. Maintainers protect release branches, appoint reviewers, resolve ordinary design decisions, and keep project documentation current.

Security responder
: A maintainer or delegated expert with access to private vulnerability reports. Responders coordinate validation, patches, advisories, and disclosure.

Release manager
: A maintainer assigned to one release. The release manager records gates, coordinates sign-off, builds or verifies artifacts, and checks the published remote.

The confirmed maintainer and security rosters must be published through valid GitHub teams and repository ownership rules before publication. The project does not use placeholder accounts.

## Decisions

Routine changes use pull-request review. Maintainers seek rough consensus by addressing concrete technical objections and recording the chosen tradeoff.

Changes to protocol semantics, cryptographic assumptions, trust boundaries, wire encoding, database compatibility, mainnet policy, licensing, or governance need a public design issue before implementation. The issue should contain:

- problem and scope
- affected invariants and roles
- alternatives considered
- compatibility and migration plan
- security and operational effects
- test and rollout plan

If consensus is unclear, two uninvolved maintainers decide after the discussion has had a reasonable review period. Security response may happen privately first, with a public record after coordinated disclosure.

## Merge policy

- Every change requires a review from someone other than its author.
- Protocol, cryptography, signing, authorization, storage migration, and Bitcoin settlement changes require two approvals, including one focused reviewer for the affected area.
- A maintainer must not bypass failing required checks.
- Emergency fixes use the same review standard when possible. If immediate private action is needed, a second security responder must approve the release before publication.
- Force pushes to protected release branches are forbidden.

A correct test result does not settle a design objection about the threat model or fail-closed behavior.

## Releases

The release manager follows [Release process](docs/release-process.md). No single person should both produce and provide the only verification of release artifacts. Mainnet activation requires the documented mainnet gates and external review; maintainers cannot waive those requirements through ordinary review.

## Adding maintainers

A candidate should have sustained, constructive contributions, sound security judgment, reliable review, and familiarity with the protocol and operator risks. Two existing maintainers nominate and approve the candidate. The change is announced publicly with the person's scope.

Access follows least privilege. A reviewer may own one area without receiving release, security, or repository-administration access.

## Removing maintainers

A maintainer may step down at any time. Maintainers may remove access for prolonged inactivity, repeated policy violations, compromised credentials, conflicts of interest, or conduct violations. Two uninvolved maintainers approve a non-emergency removal. A confirmed credential compromise permits immediate suspension followed by review.

Rotate repository, signing, security, package, and deployment access promptly when responsibilities change.

## Conflicts of interest

Reviewers disclose employment, investment, authorship, audit, bounty, or personal relationships that could affect judgment. A conflicted person may provide technical context but does not supply a required approval or decide their own dispute.

## Governance changes

A governance change uses a public pull request and two maintainer approvals. It takes effect when merged and is recorded in `CHANGELOG.md` when it changes contributor or release expectations.
