mod support;

use thunderbolt_protocol::{ChannelEvent, Digest, VerificationKind};
use thunderbolt_verifier::{StatementKind, VerifierError, VerifierErrorCode};

use support::{single_fixture, threshold_fixture, INVOICE_LEDGER_TIME, TRANSFER_LEDGER_TIME};

#[test]
fn single_committee_invoice_emits_only_required_evidence() {
    let fixture = single_fixture();
    let output = fixture
        .verifier
        .verify_invoice(&fixture.invoice_entry, &fixture.open_snapshot, INVOICE_LEDGER_TIME)
        .expect("single committee invoice verifies");

    let [evidence] = output.evidence() else {
        panic!("invoice must emit exactly one evidence record")
    };
    assert_eq!(evidence.kind, VerificationKind::InvoiceConsistencyProof);
    assert_ne!(evidence.statement_digest, Digest::ZERO);
    assert_eq!(evidence.verified_at_ms, INVOICE_LEDGER_TIME);
    assert_eq!(output.statement_digests().len(), 1);
    assert_eq!(output.statement_digests()[0].kind, StatementKind::Invoice);
    assert_eq!(output.statement_digests()[0].digest, evidence.statement_digest);
}

#[test]
fn threshold_invoice_verifies_recipient_and_exact_roster_package() {
    let fixture = threshold_fixture();
    let output = fixture
        .verifier
        .verify_invoice(&fixture.invoice_entry, &fixture.open_snapshot, INVOICE_LEDGER_TIME)
        .expect("threshold invoice verifies");

    let [evidence] = output.evidence() else {
        panic!("invoice must emit exactly one evidence record")
    };
    assert_eq!(evidence.kind, VerificationKind::InvoiceConsistencyProof);
    assert_eq!(output.statement_digests().len(), 3);
    assert_eq!(output.statement_digests()[0].kind, StatementKind::RecipientShare);
    assert_eq!(output.statement_digests()[1].kind, StatementKind::ThresholdRefresh);
    assert_eq!(
        output.statement_digests()[2].kind,
        StatementKind::ThresholdInvoicePackage
    );
    assert_eq!(evidence.statement_digest, output.statement_digests()[2].digest);
}

#[test]
fn transfer_reverifies_committed_invoice_and_both_required_checks() {
    let fixture = single_fixture();
    let output = fixture
        .verifier
        .verify_transfer(
            &fixture.transfer_entry,
            &fixture.invoice_snapshot,
            &fixture.committed_invoice,
            TRANSFER_LEDGER_TIME,
        )
        .expect("linked transfer verifies");

    assert_eq!(output.evidence().len(), 2);
    assert_eq!(output.evidence()[0].kind, VerificationKind::TransferConsistencyProof);
    assert_eq!(output.evidence()[1].kind, VerificationKind::AnchorTransition);
    assert_eq!(output.evidence()[0].verified_at_ms, TRANSFER_LEDGER_TIME);
    assert_eq!(output.evidence()[1].verified_at_ms, TRANSFER_LEDGER_TIME);
    assert_eq!(output.statement_digests()[0].kind, StatementKind::Transfer);
    assert_eq!(output.statement_digests()[1].kind, StatementKind::AnchorTransition);
}

#[test]
fn client_evidence_is_rejected_before_artifact_verification() {
    let fixture = single_fixture();
    let mut entry = fixture.invoice_entry.clone();
    let ChannelEvent::Invoice(event) = &mut entry.event else {
        panic!("fixture is an invoice")
    };
    event.verification = fixture.invoice_output.evidence().to_vec();

    let error = fixture
        .verifier
        .verify_invoice(&entry, &fixture.open_snapshot, INVOICE_LEDGER_TIME)
        .expect_err("client evidence must fail closed");
    assert!(matches!(error, VerifierError::ClientEvidence { .. }));
    assert_eq!(error.code(), VerifierErrorCode::ClientEvidence);
}

#[test]
fn transfer_rejects_a_different_committed_invoice_entry() {
    let fixture = single_fixture();
    let mut prior = fixture.committed_invoice.clone();
    prior.occurred_at_ms += 1;

    let error = fixture
        .verifier
        .verify_transfer(
            &fixture.transfer_entry,
            &fixture.invoice_snapshot,
            &prior,
            TRANSFER_LEDGER_TIME,
        )
        .expect_err("different immutable invoice head must fail");
    assert!(matches!(
        error,
        VerifierError::PriorInvoiceMismatch { field: "entry_hash" }
    ));
}
