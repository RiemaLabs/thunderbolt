mod common;

use std::error::Error;

use common::*;
use proptest::prelude::*;
use tempfile::TempDir;
use thunderbolt_ledger::AppHashV2;
use thunderbolt_ledger_app::{ApplicationOptions, BlockInputV2, LedgerApplication};
use thunderbolt_protocol::v2::{
    ExternalVerifierV2, FinalizeVerificationRequestV2, InvoiceVerificationRequestV2, OpenVerificationRequestV2,
    TransferVerificationRequestV2,
};

#[derive(Debug)]
struct AcceptAll;

impl ExternalVerifierV2 for AcceptAll {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_invoice(&self, _request: InvoiceVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_transfer(&self, _request: TransferVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_finalize(&self, _request: FinalizeVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn open(directory: &TempDir) -> Result<LedgerApplication, Box<dyn Error>> {
    Ok(LedgerApplication::open(
        directory.path().join("property.sqlite3"),
        chain_id(),
        ApplicationOptions::default(),
    )?)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn empty_block_execution_is_deterministic_across_restart(
        deltas in prop::collection::vec(0_u64..1000, 1..20),
        restart_at in 0_usize..20,
    ) {
        let first_dir = TempDir::new().expect("first tempdir");
        let second_dir = TempDir::new().expect("second tempdir");
        let first = open(&first_dir).expect("first app");
        let mut second = open(&second_dir).expect("second app");
        let mut first_hash = AppHashV2::zero();
        let mut second_hash = AppHashV2::zero();
        let mut time = 1_u64;
        for (index, delta) in deltas.iter().enumerate() {
            time = time.checked_add(*delta).expect("bounded generated time");
            let height = u64::try_from(index + 1).expect("bounded generated height");
            let first_outcome = first.apply_block(
                BlockInputV2::new(chain_id(), height, time, first_hash.clone(), Vec::new())
                    .expect("first block input"),
                &AcceptAll,
            ).expect("first execution");
            let second_outcome = second.apply_block(
                BlockInputV2::new(chain_id(), height, time, second_hash.clone(), Vec::new())
                    .expect("second block input"),
                &AcceptAll,
            ).expect("second execution");
            prop_assert_eq!(first_outcome.block(), second_outcome.block());
            first_hash = first_outcome.block().app_hash().clone();
            second_hash = second_outcome.block().app_hash().clone();
            if index == restart_at.min(deltas.len().saturating_sub(1)) {
                drop(second);
                second = open(&second_dir).expect("restart second app");
                let restarted_status = second.status().expect("restarted status");
                prop_assert_eq!(restarted_status.last_app_hash(), &second_hash);
            }
        }
        prop_assert_eq!(first.integrity_check().expect("first integrity").blocks, deltas.len());
        prop_assert_eq!(second.integrity_check().expect("second integrity").blocks, deltas.len());
    }
}
