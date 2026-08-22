use std::collections::BTreeSet;

#[cfg(any(test, feature = "insecure-regression"))]
use std::collections::BTreeMap;

use bitcoin::key::rand::thread_rng;
#[cfg(any(test, feature = "insecure-regression"))]
use libpaillier::DecryptionKey;
use libpaillier::{Ciphertext, EncryptionKey};
use rayon::prelude::*;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};

#[cfg(any(test, feature = "insecure-regression"))]
use crate::paillier::decrypt_to_big_number;
use crate::paillier::{encrypt_plaintext, random_nonce_in_group, validate_paillier_backend, PaillierModulusProfile};
#[cfg(any(test, feature = "insecure-regression"))]
use crate::zkp::types::{big_number_to_scalar, curve_order, scalar_to_big_number};
use crate::zkp::{
    prove_share_encryption, verify_share_encryption, ProofContext, ShareEncryptionProof, ShareEncryptionStatement,
    ShareEncryptionWitness,
};
use crate::{Result, ThunderboltError};

#[derive(Clone, Debug)]
pub struct ThresholdMemberPublicKey {
    pub member_id: u32,
    pub encryption_key: EncryptionKey,
}

#[derive(Clone, Debug)]
pub struct ThresholdEncryptedShare {
    pub member_id: u32,
    pub encryption_key: EncryptionKey,
    pub ciphertext: Ciphertext,
    pub proof: ShareEncryptionProof,
}

#[derive(Clone, Debug)]
pub struct ThresholdRefreshDistribution {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub threshold: usize,
    pub delta: Point,
    pub polynomial_commitments: Vec<Point>,
    pub encrypted_shares: Vec<ThresholdEncryptedShare>,
}

#[cfg(any(test, feature = "insecure-regression"))]
#[derive(Clone, Debug)]
pub struct ThresholdMemberUpdate {
    pub member_id: u32,
    pub refresh_share: Scalar,
    pub updated_share: Scalar,
}

#[cfg(any(test, feature = "insecure-regression"))]
#[derive(Debug)]
struct ThresholdCommitteeMember {
    member_id: u32,
    encryption_key: EncryptionKey,
    decryption_key: DecryptionKey,
    share: Scalar,
}

/// Single-process committee fixture for regression tests only.
///
/// This type intentionally disappears from normal builds because it owns all
/// member decryption keys and signing shares in one process.
#[cfg(any(test, feature = "insecure-regression"))]
#[derive(Debug)]
pub struct ThresholdCommittee {
    threshold: usize,
    anchor_base: Point,
    members: Vec<ThresholdCommitteeMember>,
}

fn scalar_from_u32(value: u32) -> Result<Scalar> {
    if value == 0 {
        return Err(ThunderboltError::InvalidParameter(
            "threshold committee member identifiers must be positive".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    bytes[28..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| {
        ThunderboltError::OutOfRange(format!(
            "committee member id {value} does not fit in secp256k1 scalar field"
        ))
    })
}

fn scalar_pow(base: Scalar, exponent: usize) -> MaybeScalar {
    let mut value = MaybeScalar::one();
    for _ in 0..exponent {
        value *= base;
    }
    value
}

fn evaluate_polynomial(coefficients: &[Scalar], x: Scalar) -> Result<Scalar> {
    let mut acc = MaybeScalar::Zero;
    for (power, coefficient) in coefficients.iter().enumerate() {
        acc += *coefficient * scalar_pow(x, power);
    }

    acc.not_zero().map_err(|_| {
        ThunderboltError::InvalidStateTransition(
            "Shamir polynomial evaluation produced a zero share; resample the sharing polynomial".to_string(),
        )
    })
}

fn evaluate_commitments(commitments: &[Point], member_id: u32) -> Result<Point> {
    let x = scalar_from_u32(member_id)?;
    let mut acc = MaybePoint::Infinity;
    for (power, commitment) in commitments.iter().enumerate() {
        acc += *commitment * scalar_pow(x, power);
    }

    acc.into_option().ok_or_else(|| {
        ThunderboltError::InvalidProof("polynomial commitments evaluated to the point at infinity".to_string())
    })
}

fn sample_polynomial(secret: Scalar, degree: usize, member_ids: &[u32]) -> Result<Vec<Scalar>> {
    let member_scalars = member_ids
        .iter()
        .copied()
        .map(scalar_from_u32)
        .collect::<Result<Vec<_>>>()?;
    if member_ids.iter().copied().collect::<BTreeSet<_>>().len() != member_ids.len() {
        return Err(ThunderboltError::InvalidParameter(
            "threshold committee member identifiers must be distinct".to_string(),
        ));
    }
    let mut rng = thread_rng();

    loop {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(secret);
        for _ in 0..degree {
            coefficients.push(Scalar::random(&mut rng));
        }

        let all_non_zero = member_scalars
            .iter()
            .all(|member_scalar| evaluate_polynomial(&coefficients, *member_scalar).is_ok());
        if all_non_zero {
            return Ok(coefficients);
        }
    }
}

#[cfg(any(test, feature = "insecure-regression"))]
fn lagrange_coefficient_at_zero(member_ids: &[u32], member_id: u32) -> Result<Scalar> {
    let x_i = scalar_from_u32(member_id)?;
    let mut numerator = Scalar::one();
    let mut denominator = Scalar::one();

    for other_id in member_ids {
        if *other_id == member_id {
            continue;
        }

        let x_j = scalar_from_u32(*other_id)?;
        numerator *= x_j;
        let delta = (x_j - x_i).not_zero().map_err(|_| {
            ThunderboltError::InvalidParameter("committee member identifiers must be distinct".to_string())
        })?;
        denominator *= delta;
    }

    let denominator_inverse = scalar_to_big_number(denominator).invert(curve_order()).ok_or_else(|| {
        ThunderboltError::InvalidParameter("committee member interpolation denominator was not invertible".to_string())
    })?;
    let denominator_inverse = big_number_to_scalar(&denominator_inverse)?;

    Ok(numerator * denominator_inverse)
}

fn verify_member_share(
    distribution: &ThresholdRefreshDistribution,
    encrypted_share: &ThresholdEncryptedShare,
) -> Result<Point> {
    let committed_point = evaluate_commitments(&distribution.polynomial_commitments, encrypted_share.member_id)?;
    let statement = ShareEncryptionStatement {
        context: distribution.context.clone(),
        anchor_base: distribution.anchor_base,
        recipient_key: encrypted_share.encryption_key.clone(),
        member_id: encrypted_share.member_id,
        committed_point,
        ciphertext: encrypted_share.ciphertext.clone(),
    };
    verify_share_encryption(&statement, &encrypted_share.proof)?;
    Ok(committed_point)
}

/// Creates a legacy RC/v1 2048-bit threshold refresh distribution.
pub fn create_threshold_refresh_distribution(
    context: ProofContext,
    anchor_base: Point,
    threshold: usize,
    refresh: Scalar,
    recipients: &[ThresholdMemberPublicKey],
) -> Result<ThresholdRefreshDistribution> {
    context.expect_invoice()?;
    if threshold == 0 {
        return Err(ThunderboltError::InvalidParameter(
            "threshold committee requires a positive threshold".to_string(),
        ));
    }
    if recipients.len() < threshold {
        return Err(ThunderboltError::ThresholdNotMet {
            required: threshold as u32,
            actual: recipients.len() as u32,
        });
    }

    for recipient in recipients {
        crate::paillier::validate_protocol_encryption_key(&recipient.encryption_key)?;
    }

    let member_ids = recipients.iter().map(|member| member.member_id).collect::<Vec<_>>();
    let coefficients = sample_polynomial(refresh, threshold - 1, &member_ids)?;
    let polynomial_commitments = coefficients
        .iter()
        .map(|coefficient| anchor_base * *coefficient)
        .collect::<Vec<_>>();

    // Bob generates one encrypted share + NIZK proof per committee member.
    // Each share is independent, so we parallelize across members.
    let encrypted_shares: Result<Vec<ThresholdEncryptedShare>> = recipients
        .par_iter()
        .map(|recipient| {
            let share = evaluate_polynomial(&coefficients, scalar_from_u32(recipient.member_id)?)?;
            let committed_point = evaluate_commitments(&polynomial_commitments, recipient.member_id)?;
            let nonce = random_nonce_in_group(&recipient.encryption_key);
            let ciphertext = encrypt_plaintext(
                &recipient.encryption_key,
                &crate::zkp::types::scalar_to_big_number(share),
                &nonce,
            )?;
            let statement = ShareEncryptionStatement {
                context: context.clone(),
                anchor_base,
                recipient_key: recipient.encryption_key.clone(),
                member_id: recipient.member_id,
                committed_point,
                ciphertext: ciphertext.clone(),
            };
            let proof = prove_share_encryption(&statement, &ShareEncryptionWitness { secret: share, nonce })?;
            Ok(ThresholdEncryptedShare {
                member_id: recipient.member_id,
                encryption_key: recipient.encryption_key.clone(),
                ciphertext,
                proof,
            })
        })
        .collect();
    let encrypted_shares = encrypted_shares?;

    Ok(ThresholdRefreshDistribution {
        context,
        anchor_base,
        threshold,
        delta: anchor_base * refresh,
        polynomial_commitments,
        encrypted_shares,
    })
}

/// Creates a threshold refresh distribution under an explicit Paillier profile.
pub fn create_threshold_refresh_distribution_with_profile(
    profile: PaillierModulusProfile,
    context: ProofContext,
    anchor_base: Point,
    threshold: usize,
    refresh: Scalar,
    recipients: &[ThresholdMemberPublicKey],
) -> Result<ThresholdRefreshDistribution> {
    validate_paillier_backend(profile)?;
    match profile {
        PaillierModulusProfile::LegacyRc2048V1 => {
            create_threshold_refresh_distribution(context, anchor_base, threshold, refresh, recipients)
        }
        PaillierModulusProfile::ProtocolV2Production3072 => Err(ThunderboltError::CryptographicError(
            "3072-bit threshold refresh generation requires an approved arbitrary-precision backend".to_string(),
        )),
    }
}

/// Verifies a legacy RC/v1 2048-bit threshold refresh distribution.
pub fn verify_threshold_refresh_distribution(distribution: &ThresholdRefreshDistribution) -> Result<()> {
    distribution.context.expect_invoice()?;
    if distribution.threshold == 0 {
        return Err(ThunderboltError::InvalidParameter(
            "threshold refresh distribution requires a positive threshold".to_string(),
        ));
    }
    if distribution.polynomial_commitments.len() != distribution.threshold {
        return Err(ThunderboltError::InvalidParameter(format!(
            "expected {} polynomial commitments, got {}",
            distribution.threshold,
            distribution.polynomial_commitments.len()
        )));
    }
    if distribution.encrypted_shares.len() < distribution.threshold {
        return Err(ThunderboltError::ThresholdNotMet {
            required: distribution.threshold as u32,
            actual: distribution.encrypted_shares.len() as u32,
        });
    }
    if distribution
        .polynomial_commitments
        .first()
        .ok_or_else(|| ThunderboltError::InvalidParameter("missing free-term commitment".to_string()))?
        != &distribution.delta
    {
        return Err(ThunderboltError::InvalidProof(
            "free-term polynomial commitment does not match the public delta".to_string(),
        ));
    }

    let mut seen_member_ids = BTreeSet::new();
    for encrypted_share in &distribution.encrypted_shares {
        if !seen_member_ids.insert(encrypted_share.member_id) {
            return Err(ThunderboltError::InvalidParameter(format!(
                "duplicate committee member id {} in threshold refresh distribution",
                encrypted_share.member_id
            )));
        }
        verify_member_share(distribution, encrypted_share)?;
    }

    Ok(())
}

/// Verifies a threshold refresh distribution under an explicit Paillier profile.
///
/// Profile/backend validation runs before distribution-controlled arithmetic.
pub fn verify_threshold_refresh_distribution_with_profile(
    profile: PaillierModulusProfile,
    distribution: &ThresholdRefreshDistribution,
) -> Result<()> {
    validate_paillier_backend(profile)?;
    match profile {
        PaillierModulusProfile::LegacyRc2048V1 => verify_threshold_refresh_distribution(distribution),
        PaillierModulusProfile::ProtocolV2Production3072 => Err(ThunderboltError::CryptographicError(
            "3072-bit threshold refresh verification requires an approved arbitrary-precision backend".to_string(),
        )),
    }
}

#[cfg(any(test, feature = "insecure-regression"))]
impl ThresholdCommittee {
    pub fn new(threshold: usize, committee_size: usize, anchor_base: Point, committee_secret: Scalar) -> Result<Self> {
        if threshold == 0 || committee_size < threshold {
            return Err(ThunderboltError::InvalidParameter(format!(
                "invalid threshold committee shape: threshold={threshold}, committee_size={committee_size}"
            )));
        }

        if committee_size > u32::MAX as usize {
            return Err(ThunderboltError::InvalidParameter(
                "committee size exceeds the member identifier space".to_string(),
            ));
        }

        let member_ids = (1..=committee_size as u32).collect::<Vec<_>>();
        let coefficients = sample_polynomial(committee_secret, threshold - 1, &member_ids)?;

        let mut members = Vec::with_capacity(committee_size);
        for member_id in member_ids {
            let decryption_key = DecryptionKey::random().ok_or_else(|| {
                ThunderboltError::CryptographicError("failed to generate Paillier decryption key".to_string())
            })?;
            let encryption_key = EncryptionKey::from(&decryption_key);
            let share = evaluate_polynomial(&coefficients, scalar_from_u32(member_id)?)?;
            members.push(ThresholdCommitteeMember {
                member_id,
                encryption_key,
                decryption_key,
                share,
            });
        }

        Ok(Self {
            threshold,
            anchor_base,
            members,
        })
    }

    /// Creates the regression-only committee under an explicit Paillier profile.
    pub fn new_with_profile(
        profile: PaillierModulusProfile,
        threshold: usize,
        committee_size: usize,
        anchor_base: Point,
        committee_secret: Scalar,
    ) -> Result<Self> {
        validate_paillier_backend(profile)?;
        match profile {
            PaillierModulusProfile::LegacyRc2048V1 => {
                Self::new(threshold, committee_size, anchor_base, committee_secret)
            }
            PaillierModulusProfile::ProtocolV2Production3072 => Err(ThunderboltError::CryptographicError(
                "3072-bit committee fixtures require an approved arbitrary-precision backend".to_string(),
            )),
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn committee_size(&self) -> usize {
        self.members.len()
    }

    pub fn member_public_keys(&self) -> Vec<ThresholdMemberPublicKey> {
        self.members
            .iter()
            .map(|member| ThresholdMemberPublicKey {
                member_id: member.member_id,
                encryption_key: member.encryption_key.clone(),
            })
            .collect()
    }

    pub fn member_ids(&self) -> Vec<u32> {
        self.members.iter().map(|member| member.member_id).collect()
    }

    pub fn apply_refresh_share(
        &mut self,
        distribution: &ThresholdRefreshDistribution,
        member_id: u32,
    ) -> Result<ThresholdMemberUpdate> {
        if distribution.threshold != self.threshold {
            return Err(ThunderboltError::InvalidParameter(format!(
                "distribution threshold {} does not match committee threshold {}",
                distribution.threshold, self.threshold
            )));
        }
        if distribution.anchor_base != self.anchor_base {
            return Err(ThunderboltError::InvalidParameter(
                "distribution anchor base does not match committee anchor base".to_string(),
            ));
        }

        let member = self
            .members
            .iter_mut()
            .find(|member| member.member_id == member_id)
            .ok_or_else(|| ThunderboltError::InvalidParameter(format!("unknown committee member id {member_id}")))?;
        let encrypted_share = distribution
            .encrypted_shares
            .iter()
            .find(|share| share.member_id == member_id)
            .ok_or_else(|| {
                ThunderboltError::InvalidParameter(format!(
                    "threshold refresh distribution does not contain a share for member {member_id}"
                ))
            })?;
        if encrypted_share.encryption_key.n() != member.encryption_key.n() {
            return Err(ThunderboltError::MaliciousBehavior {
                member_id,
                behavior: "refresh share was encrypted to an unexpected Paillier key".to_string(),
            });
        }

        let committed_point = verify_member_share(distribution, encrypted_share)?;
        let refresh_share = big_number_to_scalar(&decrypt_to_big_number(
            &member.decryption_key,
            &encrypted_share.ciphertext,
        )?)?;
        if self.anchor_base * refresh_share != committed_point {
            return Err(ThunderboltError::MaliciousBehavior {
                member_id,
                behavior: "decrypted refresh share does not match committed polynomial evaluation".to_string(),
            });
        }

        let updated_share = (member.share - refresh_share).not_zero().map_err(|_| {
            ThunderboltError::InvalidStateTransition(
                "committee share update wrapped to zero; refusing to leave scalar domain".to_string(),
            )
        })?;
        member.share = updated_share;

        Ok(ThresholdMemberUpdate {
            member_id,
            refresh_share,
            updated_share,
        })
    }

    /// Applies one refresh share under an explicit Paillier profile.
    pub fn apply_refresh_share_with_profile(
        &mut self,
        profile: PaillierModulusProfile,
        distribution: &ThresholdRefreshDistribution,
        member_id: u32,
    ) -> Result<ThresholdMemberUpdate> {
        validate_paillier_backend(profile)?;
        match profile {
            PaillierModulusProfile::LegacyRc2048V1 => self.apply_refresh_share(distribution, member_id),
            PaillierModulusProfile::ProtocolV2Production3072 => Err(ThunderboltError::CryptographicError(
                "3072-bit committee share application requires an approved arbitrary-precision backend".to_string(),
            )),
        }
    }

    pub fn reconstruct_secret(&self, member_ids: &[u32]) -> Result<Scalar> {
        if member_ids.len() < self.threshold {
            return Err(ThunderboltError::ThresholdNotMet {
                required: self.threshold as u32,
                actual: member_ids.len() as u32,
            });
        }

        let unique_member_ids = member_ids.iter().copied().collect::<BTreeSet<_>>();
        if unique_member_ids.len() < self.threshold {
            return Err(ThunderboltError::InvalidParameter(
                "threshold reconstruction requires distinct member identifiers".to_string(),
            ));
        }
        let subset = unique_member_ids.into_iter().take(self.threshold).collect::<Vec<_>>();

        let share_map = self
            .members
            .iter()
            .map(|member| (member.member_id, member.share))
            .collect::<BTreeMap<_, _>>();
        let mut secret = MaybeScalar::Zero;
        for member_id in &subset {
            let share = share_map.get(member_id).ok_or_else(|| {
                ThunderboltError::InvalidParameter(format!("committee member id {member_id} is not present"))
            })?;
            let lambda = lagrange_coefficient_at_zero(&subset, *member_id)?;
            secret += *share * lambda;
        }

        secret.not_zero().map_err(|_| {
            ThunderboltError::InvalidStateTransition(
                "threshold reconstruction produced the zero scalar; refusing to leave scalar domain".to_string(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_u8(value: u8) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        Scalar::from_slice(&bytes).unwrap()
    }

    #[test]
    fn threshold_refresh_distribution_round_trips_and_preserves_invariant() {
        let anchor_base = scalar_from_u8(17).base_point_mul();
        let holder_secret = scalar_from_u8(11);
        let committee_secret = scalar_from_u8(23);
        let refresh = scalar_from_u8(5);
        let mut committee = ThresholdCommittee::new(3, 5, anchor_base, committee_secret).unwrap();
        let recipients = committee.member_public_keys();
        let distribution = create_threshold_refresh_distribution(
            ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            3,
            refresh,
            &recipients,
        )
        .unwrap();

        verify_threshold_refresh_distribution(&distribution).unwrap();
        for member_id in committee.member_ids() {
            committee.apply_refresh_share(&distribution, member_id).unwrap();
        }

        let reconstructed = committee.reconstruct_secret(&[1, 2, 3]).unwrap();
        let expected_secret = (committee_secret - refresh).not_zero().unwrap();
        assert_eq!(reconstructed, expected_secret);

        let next_holder_secret = (holder_secret + refresh).not_zero().unwrap();
        let joint_before = anchor_base * (holder_secret + committee_secret).not_zero().unwrap();
        let joint_after = (anchor_base * next_holder_secret + anchor_base * reconstructed)
            .into_option()
            .unwrap();
        assert_eq!(joint_before, joint_after);
    }

    #[test]
    fn threshold_refresh_distribution_rejects_tampered_commitment() {
        let anchor_base = scalar_from_u8(19).base_point_mul();
        let committee = ThresholdCommittee::new(3, 5, anchor_base, scalar_from_u8(13)).unwrap();
        let mut distribution = create_threshold_refresh_distribution(
            ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            3,
            scalar_from_u8(7),
            &committee.member_public_keys(),
        )
        .unwrap();
        distribution.polynomial_commitments[0] = anchor_base * scalar_from_u8(8);

        assert!(verify_threshold_refresh_distribution(&distribution).is_err());
    }

    #[test]
    fn threshold_reconstruction_requires_enough_distinct_members() {
        let anchor_base = scalar_from_u8(23).base_point_mul();
        let committee = ThresholdCommittee::new(3, 5, anchor_base, scalar_from_u8(29)).unwrap();

        assert!(committee.reconstruct_secret(&[1, 2]).is_err());
        assert!(committee.reconstruct_secret(&[1, 1, 2]).is_err());
        assert!(committee.reconstruct_secret(&[1, 2, 3]).is_ok());
    }

    #[test]
    fn refresh_distribution_rejects_zero_and_duplicate_member_ids() {
        let anchor_base = scalar_from_u8(31).base_point_mul();
        let committee = ThresholdCommittee::new(2, 2, anchor_base, scalar_from_u8(37)).unwrap();
        let mut recipients = committee.member_public_keys();
        recipients[0].member_id = 0;
        assert!(create_threshold_refresh_distribution(
            ProofContext::invoice(b"ctx", b"zero-member"),
            anchor_base,
            2,
            scalar_from_u8(3),
            &recipients,
        )
        .is_err());

        let mut recipients = committee.member_public_keys();
        recipients[1].member_id = recipients[0].member_id;
        assert!(create_threshold_refresh_distribution(
            ProofContext::invoice(b"ctx", b"duplicate-member"),
            anchor_base,
            2,
            scalar_from_u8(5),
            &recipients,
        )
        .is_err());
    }
}
