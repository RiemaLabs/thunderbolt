//! Core zero-knowledge proofs from `CORE_ZKP.md`.
//!
//! This module intentionally implements only the two concrete proofs needed for
//! the invoice and transfer consistency checks:
//! - invoice consistency (`tb/invoice`)
//! - transfer consistency (`tb/xfer`)
//!
//! It does **not** yet implement the broader register / redeem proof family.

mod context;
#[cfg(feature = "insecure-regression")]
pub mod invoice;
pub mod production;
#[cfg(feature = "insecure-regression")]
pub mod share;
#[cfg(feature = "insecure-regression")]
pub(crate) mod transcript;
#[cfg(feature = "insecure-regression")]
pub mod transfer;
#[cfg(feature = "insecure-regression")]
pub mod types;

pub use context::{ProofContext, ProofTag, MAX_CONTEXT_ID_BYTES, MAX_INVOICE_ID_BYTES};
#[cfg(feature = "insecure-regression")]
pub use invoice::{
    prove_invoice, prove_invoice_with_profile, verify_invoice, verify_invoice_with_profile, InvoiceProof,
    InvoiceStatement, InvoiceWitness,
};
pub use production::{
    verify_anchor_transition_3072, verify_invoice_3072, verify_share_encryption_3072, verify_transfer_3072,
    CertifiedKeyIdentity3072, CertifiedKeyRegistration3072, CertifiedKeyRegistry3072, CertifiedKeyResolver3072,
    CertifiedKeyRole3072, CertifiedPublicKeyRecord3072, Ciphertext3072, ExpectedPublicKeyCertificate3072,
    InvoiceProof3072, InvoiceProver3072, InvoiceStatement3072, ProofNonce3072, ProofResponse3072, PublicKey3072,
    RawPublicKey3072, SecretScalar3072, ShareEncryptionProof3072, ShareEncryptionProver3072,
    ShareEncryptionStatement3072, TransferProof3072, TransferProver3072, TransferStatement3072,
    TrustedProvisioningAuthority3072, MAX_CERTIFIED_KEYS_PER_OPERATION, PROOF_RESPONSE_3072_BYTES,
};
#[cfg(feature = "insecure-regression")]
pub use share::{
    prove_share_encryption, prove_share_encryption_with_profile, verify_share_encryption,
    verify_share_encryption_with_profile, ShareEncryptionProof, ShareEncryptionStatement, ShareEncryptionWitness,
};
#[cfg(feature = "insecure-regression")]
pub use transfer::{
    prove_transfer, prove_transfer_with_profile, verify_anchor_transition, verify_transfer,
    verify_transfer_with_profile, TransferProof, TransferStatement, TransferWitness,
};
