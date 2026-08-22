use std::error::Error;
use std::fmt;
use std::sync::LazyLock;

use bitcoin::Network;
use libpaillier::{DecryptionKey, EncryptionKey};
use proptest::prelude::*;
use secp::Scalar;
use thunderbolt_core::paillier::{add_ciphertexts, encrypt_plaintext, random_nonce_in_group};
use thunderbolt_core::threshold::{create_threshold_refresh_distribution, ThresholdMemberPublicKey};
use thunderbolt_core::zkp::types::scalar_to_big_number;
use thunderbolt_core::zkp::{
    prove_share_encryption, prove_transfer, ShareEncryptionStatement, ShareEncryptionWitness, TransferStatement,
    TransferWitness,
};
use thunderbolt_protocol::EntryHash;
use thunderbolt_wire::{
    BindingContext, CanonicalDigest, PointHex, ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1,
};

use crate::insecure_regtest::dealer_bootstrap;
use crate::*;

static FIXTURE: LazyLock<std::result::Result<TestFixture, String>> =
    LazyLock::new(|| build_fixture().map_err(|error| error.to_string()));

struct TestFixture {
    descriptor: CommitteeDescriptor,
    secrets: Vec<MemberSecretBytes>,
    recipient_share: ShareEnvelopeV1,
    mismatched_recipient_share: ShareEnvelopeV1,
    threshold_refresh: ThresholdEnvelopeV1,
    transfer: TransferEnvelopeV1,
    commitment: CommittedTransfer,
}

struct MemberSecretBytes {
    member_id: CommitteeMemberId,
    decryption_key: Vec<u8>,
    share: [u8; 32],
}

#[derive(Debug)]
struct TestError(String);

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Error for TestError {}

struct StaticLedgerVerifier {
    commitment: CommittedTransfer,
}

impl LedgerCommitmentVerifier for StaticLedgerVerifier {
    type Receipt = ();
    type Error = TestError;

    fn verify_committed(&self, _receipt: &Self::Receipt) -> std::result::Result<CommittedTransfer, Self::Error> {
        Ok(self.commitment)
    }
}

#[derive(Default)]
struct MemoryVault {
    stored: Option<(u64, Vec<u8>)>,
    fail_after_revision: Option<u64>,
}

impl MemoryVault {
    fn with_failure(revision: u64) -> Self {
        Self {
            stored: None,
            fail_after_revision: Some(revision),
        }
    }

    fn clear_failure(&mut self) {
        self.fail_after_revision = None;
    }
}

impl CommitteeVault for MemoryVault {
    type Error = TestError;

    fn load(&mut self) -> std::result::Result<Option<VaultEntry>, Self::Error> {
        self.stored
            .as_ref()
            .map(|(revision, bytes)| {
                VaultPlaintext::from_secret_bytes(bytes.clone())
                    .map(|plaintext| VaultEntry::new(*revision, plaintext))
                    .map_err(|error| TestError(error.to_string()))
            })
            .transpose()
    }

    fn create(&mut self, entry: VaultEntry) -> std::result::Result<(), VaultStoreError<Self::Error>> {
        if self.stored.is_some() {
            return Err(VaultStoreError::Conflict {
                current_revision: self.stored.as_ref().map(|(revision, _)| *revision),
            });
        }
        self.stored = Some((entry.revision(), entry.plaintext().expose_secret().to_vec()));
        Ok(())
    }

    fn compare_and_swap(
        &mut self,
        expected_revision: u64,
        entry: VaultEntry,
    ) -> std::result::Result<(), VaultStoreError<Self::Error>> {
        let current_revision = self.stored.as_ref().map(|(revision, _)| *revision);
        if current_revision != Some(expected_revision) {
            return Err(VaultStoreError::Conflict { current_revision });
        }
        let next_revision = entry.revision();
        self.stored = Some((next_revision, entry.plaintext().expose_secret().to_vec()));
        if self.fail_after_revision == Some(next_revision) {
            return Err(VaultStoreError::Backend(TestError(
                "injected ambiguous post-commit failure".to_owned(),
            )));
        }
        Ok(())
    }
}

fn fixture() -> std::result::Result<&'static TestFixture, TestCaseError> {
    match FIXTURE.as_ref() {
        Ok(fixture) => Ok(fixture),
        Err(error) => Err(TestCaseError::fail(error.clone())),
    }
}

fn scalar(value: u8) -> std::result::Result<Scalar, TestError> {
    let mut bytes = [0_u8; 32];
    bytes[31] = value;
    Scalar::from_slice(&bytes).map_err(|_| TestError("invalid test scalar".to_owned()))
}

fn build_fixture() -> std::result::Result<TestFixture, Box<dyn Error + Send + Sync>> {
    let anchor_base = scalar(41)?.base_point_mul();
    let refresh = scalar(5)?;
    let dealer = dealer_bootstrap(
        Network::Regtest,
        b"committee-test",
        CommitteeEpoch::new(7),
        2,
        3,
        anchor_base,
        scalar(23)?,
    )?;
    let descriptor = dealer.descriptor().clone();
    let mut secrets = Vec::new();
    for package in dealer.into_packages() {
        secrets.push(MemberSecretBytes {
            member_id: package.member_id,
            decryption_key: serde_bare::to_vec(&package.decryption_key)?,
            share: *package.share.0,
        });
    }

    let invoice_binding = BindingContext::invoice(
        Network::Regtest,
        descriptor.deployment_id(),
        descriptor.epoch().get(),
        b"channel-42",
        b"invoice-9",
    )?;
    let recipients = descriptor
        .members()
        .iter()
        .map(|member| ThresholdMemberPublicKey {
            member_id: member.id().get(),
            encryption_key: member.encryption_key().clone(),
        })
        .collect::<Vec<_>>();
    let distribution = create_threshold_refresh_distribution(
        invoice_binding.proof_context()?,
        anchor_base,
        usize::try_from(descriptor.threshold())?,
        refresh,
        &recipients,
    )?;
    let threshold_refresh = ThresholdEnvelopeV1::from_core(invoice_binding.clone(), &distribution)?;

    let bob_secret_key = DecryptionKey::random().ok_or_else(|| TestError("Bob key generation failed".to_owned()))?;
    let bob_key = EncryptionKey::from(&bob_secret_key);
    let invoice_nonce = random_nonce_in_group(&bob_key);
    let invoice_ciphertext = encrypt_plaintext(&bob_key, &scalar_to_big_number(refresh), &invoice_nonce)?;
    let recipient_statement = ShareEncryptionStatement {
        context: invoice_binding.proof_context()?,
        anchor_base,
        recipient_key: bob_key.clone(),
        member_id: RECIPIENT_SHARE_MEMBER_ID,
        committed_point: distribution.delta,
        ciphertext: invoice_ciphertext.clone(),
    };
    let recipient_proof = prove_share_encryption(
        &recipient_statement,
        &ShareEncryptionWitness {
            secret: refresh,
            nonce: invoice_nonce,
        },
    )?;
    let recipient_share = ShareEnvelopeV1::from_core(invoice_binding.clone(), &recipient_statement, &recipient_proof)?;

    let wrong_refresh = scalar(6)?;
    let wrong_nonce = random_nonce_in_group(&bob_key);
    let wrong_ciphertext = encrypt_plaintext(&bob_key, &scalar_to_big_number(wrong_refresh), &wrong_nonce)?;
    let wrong_statement = ShareEncryptionStatement {
        context: invoice_binding.proof_context()?,
        anchor_base,
        recipient_key: bob_key.clone(),
        member_id: RECIPIENT_SHARE_MEMBER_ID,
        committed_point: anchor_base * wrong_refresh,
        ciphertext: wrong_ciphertext,
    };
    let wrong_proof = prove_share_encryption(
        &wrong_statement,
        &ShareEncryptionWitness {
            secret: wrong_refresh,
            nonce: wrong_nonce,
        },
    )?;
    let mismatched_recipient_share =
        ShareEnvelopeV1::from_core(invoice_binding.clone(), &wrong_statement, &wrong_proof)?;
    let holder_secret = scalar(11)?;
    let holder_nonce = random_nonce_in_group(&bob_key);
    let holder_component = encrypt_plaintext(&bob_key, &scalar_to_big_number(holder_secret), &holder_nonce)?;
    let next_holder_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_ciphertext)?;
    let current_anchor = anchor_base * holder_secret;
    let next_anchor = (current_anchor + distribution.delta)
        .into_option()
        .ok_or_else(|| TestError("test next anchor is infinite".to_owned()))?;
    let transfer_binding = BindingContext::transfer(
        Network::Regtest,
        descriptor.deployment_id(),
        descriptor.epoch().get(),
        b"channel-42",
        b"invoice-9",
        1,
    )?;
    let transfer_statement = TransferStatement {
        context: transfer_binding.proof_context()?,
        anchor_base,
        bob_key,
        current_anchor,
        invoice_ciphertext,
        next_holder_ciphertext,
    };
    let transfer_proof = prove_transfer(
        &transfer_statement,
        &TransferWitness {
            holder_secret,
            holder_nonce,
        },
    )?;
    let transfer = TransferEnvelopeV1::from_core(
        transfer_binding,
        &transfer_statement,
        &transfer_proof,
        &distribution.delta,
        &next_anchor,
    )?;
    let commitment = CommittedTransfer::new(
        recipient_share.canonical_digest()?,
        threshold_refresh.canonical_digest()?,
        transfer.canonical_digest()?,
        EntryHash::from_bytes([0xa1; 32]),
        EntryHash::from_bytes([0xb2; 32]),
        EntryHash::from_bytes([0xc3; 32]),
        12,
        1,
    )?;
    Ok(TestFixture {
        descriptor,
        secrets,
        recipient_share,
        mismatched_recipient_share,
        threshold_refresh,
        transfer,
        commitment,
    })
}

fn package_for(
    fixture: &TestFixture,
    index: usize,
    descriptor: CommitteeDescriptor,
) -> std::result::Result<ProvisionedMemberPackage, TestCaseError> {
    let secret = fixture
        .secrets
        .get(index)
        .ok_or_else(|| TestCaseError::fail("member index outside fixture"))?;
    let decryption_key =
        serde_bare::from_slice(&secret.decryption_key).map_err(|error| TestCaseError::fail(error.to_string()))?;
    let share = ShamirShare::from_bytes(secret.share).map_err(|error| TestCaseError::fail(error.to_string()))?;
    ProvisionedMemberPackage::new(descriptor, secret.member_id, decryption_key, share)
        .map_err(|error| TestCaseError::fail(error.to_string()))
}

fn engine_for(
    fixture: &TestFixture,
    index: usize,
    vault: MemoryVault,
) -> std::result::Result<CommitteeMemberEngine<MemoryVault>, TestCaseError> {
    let package = package_for(fixture, index, fixture.descriptor.clone())?;
    CommitteeMemberEngine::provision(vault, package).map_err(|error| TestCaseError::fail(error.to_string()))
}

fn apply_fixture(
    engine: &mut CommitteeMemberEngine<MemoryVault>,
    fixture: &TestFixture,
) -> Result<UpdateAcknowledgement> {
    engine.apply_committed_refresh(
        &fixture.recipient_share,
        &fixture.threshold_refresh,
        &fixture.transfer,
        &StaticLedgerVerifier {
            commitment: fixture.commitment,
        },
        &(),
    )
}

fn commitment_for(
    fixture: &TestFixture,
    recipient_share: &ShareEnvelopeV1,
    threshold_refresh: &ThresholdEnvelopeV1,
) -> std::result::Result<CommittedTransfer, TestCaseError> {
    CommittedTransfer::new(
        recipient_share
            .canonical_digest()
            .map_err(|error| TestCaseError::fail(error.to_string()))?,
        threshold_refresh
            .canonical_digest()
            .map_err(|error| TestCaseError::fail(error.to_string()))?,
        *fixture.commitment.transfer_digest(),
        fixture.commitment.invoice_entry_hash(),
        fixture.commitment.transfer_entry_hash(),
        fixture.commitment.committed_head_hash(),
        fixture.commitment.transfer_sequence(),
        fixture.commitment.transfer_step(),
    )
    .map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    // Each case verifies real 2048-bit Paillier proofs. Keep the CI suite
    // bounded; key generation itself is shared by the LazyLock fixture above.
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn member_selection_decrypts_exactly_the_selected_member(member_index in 0_usize..3) {
        let fixture = fixture()?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let acknowledgement = apply_fixture(&mut engine, fixture)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(acknowledgement.member_id(), fixture.secrets[member_index].member_id);
        prop_assert!(engine.pending_refresh().is_none());
        prop_assert_eq!(engine.durable_revision(), 2);
    }

    #[test]
    fn any_share_proof_tamper_is_rejected_before_pending_state(
        member_index in 0_usize..3,
        tampered_index in 0_usize..3,
        replacement in 70_u8..100,
    ) {
        let fixture = fixture()?;
        let mut threshold = fixture.threshold_refresh.clone();
        threshold.distribution.encrypted_shares[tampered_index].proof.a_point =
            PointHex::from_bytes("test.tampered_point", scalar(replacement)
                .map_err(|error| TestCaseError::fail(error.to_string()))?
                .base_point_mul()
                .serialize())
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let commitment = commitment_for(fixture, &fixture.recipient_share, &threshold)?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let result = engine.apply_committed_refresh(
            &fixture.recipient_share,
            &threshold,
            &fixture.transfer,
            &StaticLedgerVerifier { commitment },
            &(),
        );
        prop_assert!(result.is_err());
        prop_assert!(engine.pending_refresh().is_none());
        prop_assert_eq!(engine.durable_revision(), 0);
    }

    #[test]
    fn recipient_share_proof_tamper_is_rejected_even_when_receipt_binds_it(
        member_index in 0_usize..3,
        replacement in 100_u8..130,
    ) {
        let fixture = fixture()?;
        let mut recipient = fixture.recipient_share.clone();
        recipient.proof.a_point = PointHex::from_bytes(
            "test.tampered_recipient_point",
            scalar(replacement)
                .map_err(|error| TestCaseError::fail(error.to_string()))?
                .base_point_mul()
                .serialize(),
        ).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let commitment = commitment_for(fixture, &recipient, &fixture.threshold_refresh)?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let result = engine.apply_committed_refresh(
            &recipient,
            &fixture.threshold_refresh,
            &fixture.transfer,
            &StaticLedgerVerifier { commitment },
            &(),
        );
        prop_assert!(matches!(result, Err(CommitteeError::Wire(_))));
        prop_assert!(engine.pending_refresh().is_none());
        prop_assert_eq!(engine.durable_revision(), 0);
    }

    #[test]
    fn valid_but_mismatched_recipient_share_is_rejected(member_index in 0_usize..3) {
        let fixture = fixture()?;
        let recipient = &fixture.mismatched_recipient_share;
        let commitment = commitment_for(fixture, recipient, &fixture.threshold_refresh)?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let result = engine.apply_committed_refresh(
            recipient,
            &fixture.threshold_refresh,
            &fixture.transfer,
            &StaticLedgerVerifier { commitment },
            &(),
        );
        prop_assert!(matches!(result, Err(CommitteeError::RecipientDeltaMismatch)));
        prop_assert!(engine.pending_refresh().is_none());
        prop_assert_eq!(engine.durable_revision(), 0);
    }

    #[test]
    fn recipient_share_must_use_reserved_identifier(member_index in 0_usize..3, wrong_id in 1_u32..1000) {
        let fixture = fixture()?;
        let mut recipient = fixture.recipient_share.clone();
        recipient.statement.member_id = wrong_id;
        let commitment = commitment_for(fixture, &recipient, &fixture.threshold_refresh)?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let result = engine.apply_committed_refresh(
            &recipient,
            &fixture.threshold_refresh,
            &fixture.transfer,
            &StaticLedgerVerifier { commitment },
            &(),
        );
        prop_assert!(matches!(result, Err(CommitteeError::WrongRecipientShareId)));
        prop_assert_eq!(engine.durable_revision(), 0);
    }

    #[test]
    fn replay_is_idempotent_and_does_not_advance_revision(
        member_index in 0_usize..3,
        repeats in 1_usize..3,
    ) {
        let fixture = fixture()?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let first = apply_fixture(&mut engine, fixture)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        for _ in 0..repeats {
            let replay = apply_fixture(&mut engine, fixture)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(&replay, &first);
            prop_assert_eq!(engine.durable_revision(), 2);
        }
    }

    #[test]
    fn wrong_epoch_is_rejected_before_decryption(
        member_index in 0_usize..3,
        epoch_offset in 1_u64..100,
    ) {
        let fixture = fixture()?;
        let mut recipient = fixture.recipient_share.clone();
        let mut threshold = fixture.threshold_refresh.clone();
        let mut transfer = fixture.transfer.clone();
        recipient.binding.committee_epoch = recipient.binding.committee_epoch.saturating_add(epoch_offset);
        threshold.binding.committee_epoch = threshold.binding.committee_epoch.saturating_add(epoch_offset);
        transfer.binding.committee_epoch = transfer.binding.committee_epoch.saturating_add(epoch_offset);
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let result = engine.apply_committed_refresh(
            &recipient,
            &threshold,
            &transfer,
            &StaticLedgerVerifier { commitment: fixture.commitment },
            &(),
        );
        let is_wrong_epoch = matches!(result, Err(CommitteeError::WrongEpoch { .. }));
        prop_assert!(is_wrong_epoch);
        prop_assert_eq!(engine.durable_revision(), 0);
    }

    #[test]
    fn descriptor_threshold_mismatch_is_rejected(
        member_index in 0_usize..3,
        wrong_threshold in prop_oneof![Just(1_u32), Just(3_u32)],
    ) {
        let fixture = fixture()?;
        let descriptor = CommitteeDescriptor::new(
            fixture.descriptor.network(),
            fixture.descriptor.deployment_id(),
            fixture.descriptor.epoch(),
            wrong_threshold,
            fixture.descriptor.anchor_base(),
            fixture.descriptor.members().to_vec(),
        ).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let package = package_for(fixture, member_index, descriptor)?;
        let mut engine = CommitteeMemberEngine::provision(MemoryVault::default(), package)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let result = apply_fixture(&mut engine, fixture);
        let is_wrong_threshold = matches!(result, Err(CommitteeError::WrongThreshold { .. }));
        prop_assert!(is_wrong_threshold);
        prop_assert_eq!(engine.durable_revision(), 0);
    }

    #[test]
    fn crash_after_pending_or_applied_is_recoverable_and_idempotent(
        member_index in 0_usize..3,
        fail_after_applied in any::<bool>(),
    ) {
        let fixture = fixture()?;
        let failed_revision = if fail_after_applied { 2 } else { 1 };
        let mut engine = engine_for(fixture, member_index, MemoryVault::with_failure(failed_revision))?;
        let failed = apply_fixture(&mut engine, fixture);
        prop_assert!(failed.is_err());
        let mut vault = engine.into_vault();
        vault.clear_failure();
        let mut recovered = CommitteeMemberEngine::open(vault, fixture.descriptor.clone())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let acknowledgement = apply_fixture(&mut recovered, fixture)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(acknowledgement.durable_revision(), 2);
        let replay = apply_fixture(&mut recovered, fixture)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(replay, acknowledgement);
        prop_assert_eq!(recovered.durable_revision(), 2);
    }

    #[test]
    fn commitment_must_bind_exact_wire_digests(member_index in 0_usize..3, mutate_transfer in any::<bool>()) {
        let fixture = fixture()?;
        let mut threshold_digest = *fixture.commitment.threshold_refresh_digest();
        let mut transfer_digest = *fixture.commitment.transfer_digest();
        if mutate_transfer {
            transfer_digest[0] ^= 1;
        } else {
            threshold_digest[0] ^= 1;
        }
        let commitment = CommittedTransfer::new(
            *fixture.commitment.recipient_share_digest(),
            threshold_digest,
            transfer_digest,
            fixture.commitment.invoice_entry_hash(),
            fixture.commitment.transfer_entry_hash(),
            fixture.commitment.committed_head_hash(),
            fixture.commitment.transfer_sequence(),
            fixture.commitment.transfer_step(),
        ).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut engine = engine_for(fixture, member_index, MemoryVault::default())?;
        let result = engine.apply_committed_refresh(
            &fixture.recipient_share,
            &fixture.threshold_refresh,
            &fixture.transfer,
            &StaticLedgerVerifier { commitment },
            &(),
        );
        prop_assert!(matches!(result, Err(CommitteeError::LedgerCommitmentMismatch)));
        prop_assert_eq!(engine.durable_revision(), 0);
    }
}

#[derive(Default)]
struct CountingSigner {
    reserve_calls: usize,
    sign_calls: usize,
}

impl CommitteeSigner for CountingSigner {
    type SigningPackage = [u8; 32];
    type SignatureShare = [u8; 32];
    type Error = TestError;

    fn reserve_nonce(&mut self, _binding: &SignerSessionBinding) -> std::result::Result<NonceCommitment, Self::Error> {
        self.reserve_calls = self.reserve_calls.saturating_add(1);
        NonceCommitment::new(vec![0x42; 33]).map_err(|error| TestError(error.to_string()))
    }

    fn sign_share(
        &mut self,
        _binding: &SignerSessionBinding,
        _package: &Self::SigningPackage,
    ) -> std::result::Result<Self::SignatureShare, Self::Error> {
        self.sign_calls = self.sign_calls.saturating_add(1);
        Ok([0x51; 32])
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn signing_session_replay_never_reuses_a_nonce(replays in 1_usize..8) {
        let fixture = fixture()?;
        let mut engine = engine_for(fixture, 0, MemoryVault::default())?;
        let binding = SignerSessionBinding::new(
            fixture.descriptor.id(),
            fixture.descriptor.epoch(),
            fixture.secrets[0].member_id,
            [0xd4; 32],
            b"coordinator-session-1",
        ).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut signer = CountingSigner::default();
        let _commitment = engine.reserve_signing_nonce(&mut signer, &binding)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        for _ in 0..replays {
            prop_assert!(engine.reserve_signing_nonce(&mut signer, &binding).is_err());
        }
        let _share = engine.sign_share_once(&mut signer, &binding, &[0x61; 32])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        for _ in 0..replays {
            prop_assert!(engine.sign_share_once(&mut signer, &binding, &[0x61; 32]).is_err());
        }
        prop_assert_eq!(signer.reserve_calls, 1);
        prop_assert_eq!(signer.sign_calls, 1);
        let is_consumed = matches!(
            engine.signer_session_phase(binding.session_id()),
            Some(SignerSessionPhase::Consumed { .. })
        );
        prop_assert!(is_consumed);
    }
}
