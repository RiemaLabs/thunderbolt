//! Insecure single-process dealer used only by tests and isolated regtest.
//!
//! Enabling this module places the committee secret and every member secret in
//! one process. It must never be enabled in a production binary.

use bitcoin::key::rand::thread_rng;
use bitcoin::Network;
use libpaillier::{DecryptionKey, EncryptionKey};
use secp::{MaybeScalar, Point, Scalar};

use crate::{
    CommitteeDescriptor, CommitteeEpoch, CommitteeError, CommitteeMemberDescriptor, CommitteeMemberId,
    ProvisionedMemberPackage, Result, ShamirShare,
};

/// Output of the explicitly insecure single-process dealer.
///
/// The package vector intentionally implements neither `Clone` nor `Debug`.
pub struct DealerBootstrap {
    descriptor: CommitteeDescriptor,
    packages: Vec<ProvisionedMemberPackage>,
}

impl DealerBootstrap {
    /// Returns the public descriptor shared by every member process.
    #[must_use]
    pub const fn descriptor(&self) -> &CommitteeDescriptor {
        &self.descriptor
    }

    /// Consumes the dealer output into one independently distributable package
    /// per member.
    #[must_use]
    pub fn into_packages(self) -> Vec<ProvisionedMemberPackage> {
        self.packages
    }
}

/// Creates a complete committee in one process for tests or isolated regtest.
///
/// # Security
///
/// This helper knows the committee secret and every generated Paillier key. A
/// real deployment must replace it with an audited DKG/provisioning ceremony
/// and pass each process only one [`ProvisionedMemberPackage`].
#[allow(clippy::too_many_arguments)]
pub fn dealer_bootstrap(
    network: Network,
    deployment_id: impl AsRef<[u8]>,
    epoch: CommitteeEpoch,
    threshold: u32,
    committee_size: u32,
    anchor_base: Point,
    committee_secret: Scalar,
) -> Result<DealerBootstrap> {
    if threshold == 0
        || committee_size < threshold
        || usize::try_from(committee_size).map_or(true, |size| size > thunderbolt_wire::MAX_COMMITTEE_MEMBERS)
    {
        return Err(CommitteeError::InvalidDescriptor(
            "invalid insecure-regtest committee shape",
        ));
    }
    let member_ids = (1..=committee_size)
        .map(CommitteeMemberId::new)
        .collect::<Result<Vec<_>>>()?;
    let coefficients = sample_polynomial(committee_secret, threshold - 1, &member_ids)?;

    let mut secret_material = Vec::with_capacity(member_ids.len());
    let mut public_members = Vec::with_capacity(member_ids.len());
    for member_id in member_ids {
        let decryption_key =
            DecryptionKey::random().ok_or(CommitteeError::InvalidDescriptor("Paillier key generation failed"))?;
        let encryption_key = EncryptionKey::from(&decryption_key);
        let share_scalar = evaluate_polynomial(&coefficients, member_id)?;
        let share = ShamirShare::from_scalar(share_scalar);
        public_members.push(CommitteeMemberDescriptor::new(
            member_id,
            encryption_key,
            anchor_base * share_scalar,
        )?);
        secret_material.push((member_id, decryption_key, share));
    }
    let descriptor = CommitteeDescriptor::new(network, deployment_id, epoch, threshold, anchor_base, public_members)?;
    let mut packages = Vec::with_capacity(secret_material.len());
    for (member_id, decryption_key, share) in secret_material {
        packages.push(ProvisionedMemberPackage::new(
            descriptor.clone(),
            member_id,
            decryption_key,
            share,
        )?);
    }
    Ok(DealerBootstrap { descriptor, packages })
}

fn sample_polynomial(secret: Scalar, degree: u32, member_ids: &[CommitteeMemberId]) -> Result<Vec<Scalar>> {
    let mut rng = thread_rng();
    loop {
        let mut coefficients = Vec::with_capacity(
            usize::try_from(degree)
                .map_err(|_| CommitteeError::InvalidDescriptor("threshold does not fit usize"))?
                .saturating_add(1),
        );
        coefficients.push(secret);
        for _ in 0..degree {
            coefficients.push(Scalar::random(&mut rng));
        }
        if member_ids
            .iter()
            .all(|member_id| evaluate_polynomial(&coefficients, *member_id).is_ok())
        {
            return Ok(coefficients);
        }
    }
}

fn evaluate_polynomial(coefficients: &[Scalar], member_id: CommitteeMemberId) -> Result<Scalar> {
    let x = scalar_from_member_id(member_id)?;
    let mut accumulator = MaybeScalar::Zero;
    let mut power = MaybeScalar::one();
    for coefficient in coefficients {
        accumulator += *coefficient * power;
        power *= x;
    }
    accumulator
        .not_zero()
        .map_err(|_| CommitteeError::InvalidDescriptor("dealer sampled a zero Shamir share"))
}

fn scalar_from_member_id(member_id: CommitteeMemberId) -> Result<Scalar> {
    let mut bytes = [0_u8; 32];
    bytes[28..].copy_from_slice(&member_id.get().to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| CommitteeError::InvalidMemberId)
}
