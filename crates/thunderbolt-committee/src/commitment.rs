use std::error::Error;

use thunderbolt_protocol::EntryHash;

use crate::{CommitteeError, Result};

/// Ledger-confirmed identity of one consumed invoice and committed transfer.
///
/// A trusted [`LedgerCommitmentVerifier`] produces this value from its native
/// quorum/finality receipt. The two wire digests prove that the ledger entries
/// contain the exact threshold distribution and transfer that the member
/// verifies locally. The recipient-share digest binds the proof that the
/// recipient ciphertext encrypts the same refresh committed by the committee
/// distribution. `committed_head_hash` proves the transfer is an ancestor of
/// the accepted ledger head; it is receipt context, not the idempotency key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedTransfer {
    recipient_share_digest: [u8; 32],
    threshold_refresh_digest: [u8; 32],
    transfer_digest: [u8; 32],
    invoice_entry_hash: EntryHash,
    transfer_entry_hash: EntryHash,
    committed_head_hash: EntryHash,
    transfer_sequence: u64,
    transfer_step: u64,
}

impl CommittedTransfer {
    /// Constructs the result of a successful external ledger verification.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipient_share_digest: [u8; 32],
        threshold_refresh_digest: [u8; 32],
        transfer_digest: [u8; 32],
        invoice_entry_hash: EntryHash,
        transfer_entry_hash: EntryHash,
        committed_head_hash: EntryHash,
        transfer_sequence: u64,
        transfer_step: u64,
    ) -> Result<Self> {
        if invoice_entry_hash == EntryHash::ZERO
            || transfer_entry_hash == EntryHash::ZERO
            || committed_head_hash == EntryHash::ZERO
        {
            return Err(CommitteeError::LedgerCommitmentMismatch);
        }
        Ok(Self {
            recipient_share_digest,
            threshold_refresh_digest,
            transfer_digest,
            invoice_entry_hash,
            transfer_entry_hash,
            committed_head_hash,
            transfer_sequence,
            transfer_step,
        })
    }

    /// Returns the exact recipient-share canonical wire digest.
    #[must_use]
    pub const fn recipient_share_digest(&self) -> &[u8; 32] {
        &self.recipient_share_digest
    }

    /// Returns the exact threshold-refresh canonical wire digest.
    #[must_use]
    pub const fn threshold_refresh_digest(&self) -> &[u8; 32] {
        &self.threshold_refresh_digest
    }

    /// Returns the exact transfer canonical wire digest.
    #[must_use]
    pub const fn transfer_digest(&self) -> &[u8; 32] {
        &self.transfer_digest
    }

    /// Returns the committed invoice-entry hash.
    #[must_use]
    pub const fn invoice_entry_hash(&self) -> EntryHash {
        self.invoice_entry_hash
    }

    /// Returns the committed transfer-entry hash used for idempotency.
    #[must_use]
    pub const fn transfer_entry_hash(&self) -> EntryHash {
        self.transfer_entry_hash
    }

    /// Returns the ledger head under which ancestry/finality was verified.
    #[must_use]
    pub const fn committed_head_hash(&self) -> EntryHash {
        self.committed_head_hash
    }

    /// Returns the immutable ledger sequence of the transfer entry.
    #[must_use]
    pub const fn transfer_sequence(&self) -> u64 {
        self.transfer_sequence
    }

    /// Returns the protocol transfer step bound by the transfer proof.
    #[must_use]
    pub const fn transfer_step(&self) -> u64 {
        self.transfer_step
    }
}

/// Trust boundary that validates a ledger's native commitment/finality receipt.
///
/// The implementation must verify the ledger quorum or consensus certificate,
/// verify that `transfer_entry_hash` consumes `invoice_entry_hash`, verify both
/// entries are ancestors of `committed_head_hash`, and derive the recipient
/// share, threshold distribution, and transfer wire digests from the committed
/// entry artifacts. Returning caller-supplied fields without those checks is
/// unsafe.
pub trait LedgerCommitmentVerifier {
    /// Native signed/quorum receipt type.
    type Receipt;
    /// Backend-specific error that never formats secret material.
    type Error: Error + Send + Sync + 'static;

    /// Authenticates a receipt and returns its exact committed transfer fields.
    fn verify_committed(&self, receipt: &Self::Receipt) -> std::result::Result<CommittedTransfer, Self::Error>;
}
