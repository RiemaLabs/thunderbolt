# Differential security review, 2026-08-21

## Executive summary

This review covered commit `fd6206b` and the new protocol, configuration, storage, wire, and reference-node layers on `release/1.0`. The review treated cryptography, Bitcoin settlement, authorization, and ledger state as high risk.

This is a historical review of that commit. Later commits added Holder, one-share committee, Trusted Verifier, encrypted Keystore, and Bitcoin Core libraries. They are not covered by this report and are not wired into `thunderboltd`. See [Architecture](architecture.md) and [Production roadmap](roadmap.md) for current scope.

| Severity | Found | Resolved in branch |
| --- | ---: | ---: |
| Critical | 0 | 0 |
| High | 4 | 4 |
| Medium | 3 | 3 |
| Low | 0 | 0 |

Recommendation: conditionally approve these changes for the regtest release candidate. Reject mainnet promotion. The distributed committee, production Ledger, wallet state, Bitcoin backend, recovery design, and external audit gates remain incomplete.

## Scope and change risk

The review used a focused strategy over the security-sensitive diff and its direct callers. It examined:

- Paillier nonce generation, statement validation, and verifier bounds
- Taproot transaction construction, signing, witness assembly, and regression fixtures
- event ordering, idempotency, invoice expiry, and finalization requirements
- token loading, constant-time authentication, and scope resolution
- storage transaction boundaries and trusted ledger time

The main blast radius is the public cryptographic API and every future wallet, committee, or Ledger service that calls the reducer or Bitcoin transaction builder.

## Findings and resolution

### High: Taproot sighash type was not serialized

The code signed the redeem transaction with `SIGHASH_ALL` but emitted a bare 64-byte BIP340 signature. Bitcoin interprets a 64-byte Taproot signature as `SIGHASH_DEFAULT`, so the witness committed to a different digest.

Resolution: [`bitcoin_tx.rs`](../crates/thunderbolt-core/src/bitcoin_tx.rs) now returns `bitcoin::taproot::Signature`, preserves `TapSighashType::All`, and writes the required 65th byte at `sign_redeem_script_path` and `aggregate_redeem` around lines 460 and 486.

Verification: [`bitcoin_settlement.rs`](../crates/thunderbolt-eval/tests/bitcoin_settlement.rs) validates both the prepare and redeem inputs with `libbitcoinconsensus` and asserts that both Taproot signatures contain 65 bytes.

### High: regression flow signed a different transaction with mismatched keys

The regression helper signed an empty-output PSBT, then attached those signatures to a PSBT with outputs. It also used Taproot-tweaked keypairs although the TapScript committed to the untweaked keys.

Resolution: [`mock_transactions.rs`](../crates/thunderbolt-eval/src/mock_transactions.rs) builds the final output-bearing PSBT before signing and uses keypairs that match the script, around lines 37 through 50 and 96 through 134.

Verification: the Bitcoin consensus test exercises transaction construction and the final witnesses.

### High: Finalize omitted closing-transaction verification

The reducer required Holder ownership and committee quorum evidence but did not require evidence that the closing transaction matched the channel state.

Resolution: [`event.rs`](../crates/thunderbolt-protocol/src/event.rs) adds `ClosingTransaction` to the mandatory Finalize verification set around line 322. A negative test removes that evidence and confirms rejection.

### High: caller-controlled time could bypass a live invoice

Invoice expiry and finalization used the event timestamp supplied by the caller. A Holder could submit a future timestamp and make an invoice appear expired.

Resolution: [`reducer.rs`](../crates/thunderbolt-protocol/src/reducer.rs) requires a trusted `ledger_time_ms` in `HistoryContext` around line 82. Expiry, monotonic state time, verification time, and finalization now use that value. Storage samples it only after acquiring the SQLite writer lock. Events that claim a time after the trusted ledger time fail closed.

Verification: protocol and storage tests cover future timestamps, expiry at the trusted time, and time spent waiting for the writer lock.

### Medium: Paillier verifier work was attacker-sized

Direct proof statements could carry arbitrary Paillier moduli. Validation would then perform GCD and modular exponentiation on attacker-chosen integer widths.

Resolution: [`paillier.rs`](../crates/thunderbolt-core/src/paillier.rs) validates the RC's exact 256-byte modulus encoding before proof verification around line 65. Invoice, transfer, and share statement validators call this check before expensive arithmetic. Tests reject undersized and oversized moduli.

The RC uses a 2048-bit parameter while the accepted paper evaluates 3072-bit Paillier. This remains a documented compatibility and mainnet gate.

### Medium: malformed redeem PSBT could panic or sign the wrong channel

Witness assembly indexed input zero without validating the PSBT. A malformed or unrelated PSBT could panic or receive signatures.

Resolution: [`bitcoin_tx.rs`](../crates/thunderbolt-core/src/bitcoin_tx.rs) validates input count, funding outpoint, witness UTXO, script, and amount before signing or aggregation around line 504. Redeem outputs must be nonempty, non-dust, and within the locked amount.

Verification: a unit test passes an empty-input PSBT and confirms a structured error.

### Medium: duplicate bearer tokens could gain the wrong scope

Two token files could contain identical bytes. Authentication scanned every token and returned the last matching identity, so configuration order could change the effective privilege.

Resolution: [`auth.rs`](../crates/thunderbolt-config/src/auth.rs) compares fixed-size token values during loading and rejects duplicate contents around line 55. The error reports token identifiers only. A test covers a duplicated read and administrator credential.

## Test evidence

Focused validation after the fixes includes:

- 5 Bitcoin utility tests
- 26 core unit tests and 4 core integration tests
- 22 protocol tests
- 20 storage tests
- 14 configuration and authorization tests
- 5 daemon, CLI, and HTTP integration tests
- 2 bounded wire-codec tests
- 1 Bitcoin consensus settlement test

Formatting and strict Clippy checks run with warnings denied. The full release gate also includes locked builds, dependency advisories, license policy, secret scanning, SBOM generation, and release archive verification.

## Remaining production blockers

- The reference daemon implements a single-node Ledger control plane, not the paper's Byzantine Ledger guarantees.
- Holder wallet and independent committee processes are not implemented.
- Threshold opening and finalization are not integrated with FROST or a Bitcoin Core backend.
- The current TapScript has no unilateral recovery path.
- Encrypted secret storage, restore drills, chain reorganization handling, and multi-process adversarial tests remain incomplete.
- Historical key material and generated build blobs must be removed from every public Git ref.
- Independent protocol and implementation audits have not occurred.

## Methodology and limits

The review compared the baseline and changed code, traced direct callers, calculated practical blast radius, examined tests, and modeled unauthenticated clients, authenticated operators, malicious Holders, and malformed network input. It did not audit external dependency internals or prove the cryptographic constructions. Confidence is high for the seven resolved implementation findings and medium for the complete system because major distributed components do not exist yet.
