use std::fmt;

use bitcoin::Network;
use libpaillier::{DecryptionKey, EncryptionKey};
use secp::{Point, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thunderbolt_core::paillier::validate_protocol_encryption_key;
use thunderbolt_wire::DeploymentId;
use zeroize::Zeroizing;

use crate::{CommitteeError, Result};

/// A positive, stable committee-member identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitteeMemberId(u32);

impl CommitteeMemberId {
    /// Creates a positive committee-member identifier distinct from the
    /// protocol-reserved recipient proof identifier.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 || value == crate::RECIPIENT_SHARE_MEMBER_ID {
            return Err(CommitteeError::InvalidMemberId);
        }
        Ok(Self(value))
    }

    /// Returns the canonical wire integer.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for CommitteeMemberId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Public committee membership epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitteeEpoch(u64);

impl CommitteeEpoch {
    /// Creates an epoch identifier.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the canonical epoch integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CommitteeEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

macro_rules! public_digest_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical 32-byte digest.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Returns lowercase hexadecimal suitable for logs and RPC output.
            #[must_use]
            pub fn to_hex(self) -> String {
                hex_encode(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }
    };
}

public_digest_type!(
    /// Canonical hash of one public committee descriptor.
    CommitteeId
);
public_digest_type!(
    /// Canonical hash of one complete threshold-refresh wire event.
    RefreshEventId
);

/// One public committee member entry.
#[derive(Clone, Debug)]
pub struct CommitteeMemberDescriptor {
    id: CommitteeMemberId,
    encryption_key: EncryptionKey,
    initial_share_commitment: Point,
}

impl CommitteeMemberDescriptor {
    /// Creates a validated public member entry.
    pub fn new(id: CommitteeMemberId, encryption_key: EncryptionKey, initial_share_commitment: Point) -> Result<Self> {
        validate_protocol_encryption_key(&encryption_key)?;
        Ok(Self {
            id,
            encryption_key,
            initial_share_commitment,
        })
    }

    /// Returns the stable member identifier.
    #[must_use]
    pub const fn id(&self) -> CommitteeMemberId {
        self.id
    }

    /// Returns the member's public Paillier encryption key.
    #[must_use]
    pub const fn encryption_key(&self) -> &EncryptionKey {
        &self.encryption_key
    }

    /// Returns the member's initial Feldman share commitment.
    #[must_use]
    pub const fn initial_share_commitment(&self) -> Point {
        self.initial_share_commitment
    }
}

/// Canonical public description of one committee epoch.
#[derive(Clone, Debug)]
pub struct CommitteeDescriptor {
    id: CommitteeId,
    network: Network,
    deployment_id: DeploymentId,
    epoch: CommitteeEpoch,
    threshold: u32,
    anchor_base: Point,
    members: Vec<CommitteeMemberDescriptor>,
}

impl CommitteeDescriptor {
    /// Creates a descriptor, sorting its members by identifier before hashing.
    pub fn new(
        network: Network,
        deployment_id: impl AsRef<[u8]>,
        epoch: CommitteeEpoch,
        threshold: u32,
        anchor_base: Point,
        mut members: Vec<CommitteeMemberDescriptor>,
    ) -> Result<Self> {
        let deployment_id = DeploymentId::from_bytes("committee.deployment_id", deployment_id)?;
        members.sort_by_key(CommitteeMemberDescriptor::id);
        let member_count =
            u32::try_from(members.len()).map_err(|_| CommitteeError::InvalidDescriptor("member count exceeds u32"))?;
        if threshold == 0 || member_count < threshold {
            return Err(CommitteeError::InvalidDescriptor(
                "threshold must be positive and no larger than the member count",
            ));
        }
        if members.len() > thunderbolt_wire::MAX_COMMITTEE_MEMBERS {
            return Err(CommitteeError::InvalidDescriptor(
                "member count exceeds the version 1 wire bound",
            ));
        }
        if members.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(CommitteeError::InvalidDescriptor("member identifiers must be distinct"));
        }
        let id = descriptor_digest(network, &deployment_id, epoch, threshold, anchor_base, &members);
        Ok(Self {
            id,
            network,
            deployment_id,
            epoch,
            threshold,
            anchor_base,
            members,
        })
    }

    /// Returns the descriptor's canonical identifier.
    #[must_use]
    pub const fn id(&self) -> CommitteeId {
        self.id
    }

    /// Returns the Bitcoin network bound to this committee.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the opaque deployment identifier.
    #[must_use]
    pub fn deployment_id(&self) -> &[u8] {
        self.deployment_id.as_bytes()
    }

    /// Returns the membership epoch.
    #[must_use]
    pub const fn epoch(&self) -> CommitteeEpoch {
        self.epoch
    }

    /// Returns the Shamir threshold.
    #[must_use]
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Returns the public Feldman commitment base.
    #[must_use]
    pub const fn anchor_base(&self) -> Point {
        self.anchor_base
    }

    /// Returns every public member entry in canonical identifier order.
    #[must_use]
    pub fn members(&self) -> &[CommitteeMemberDescriptor] {
        &self.members
    }

    /// Finds a public member entry by stable identifier.
    #[must_use]
    pub fn member(&self, id: CommitteeMemberId) -> Option<&CommitteeMemberDescriptor> {
        self.members
            .binary_search_by_key(&id, CommitteeMemberDescriptor::id)
            .ok()
            .and_then(|index| self.members.get(index))
    }
}

/// A non-zero Shamir share whose bytes are zeroized on drop.
///
/// This type intentionally implements neither `Clone` nor `Debug` and exposes
/// no secret-byte accessor. Use [`ShamirShare::public_commitment`] to inspect
/// only its public Feldman commitment.
pub struct ShamirShare(pub(crate) Zeroizing<[u8; 32]>);

impl ShamirShare {
    /// Parses a canonical, non-zero secp256k1 scalar share.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Scalar::from_slice(&bytes).map_err(|_| CommitteeError::ProvisioningMismatch)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn from_scalar(scalar: Scalar) -> Self {
        Self(Zeroizing::new(scalar.serialize()))
    }

    pub(crate) fn scalar(&self) -> Result<Scalar> {
        Scalar::from_slice(self.0.as_ref())
            .map_err(|_| CommitteeError::InvalidVaultRecord("stored Shamir share is not a non-zero scalar"))
    }

    /// Returns the public Feldman commitment without exposing the share.
    pub fn public_commitment(&self, anchor_base: Point) -> Result<Point> {
        Ok(anchor_base * self.scalar()?)
    }
}

/// Offline-provisioned secret material for exactly one committee process.
///
/// This package intentionally implements neither `Clone` nor `Debug`. A
/// production constructor consumes it; no production API accepts or
/// reconstructs the committee secret.
pub struct ProvisionedMemberPackage {
    pub(crate) descriptor: CommitteeDescriptor,
    pub(crate) member_id: CommitteeMemberId,
    pub(crate) decryption_key: DecryptionKey,
    pub(crate) share: ShamirShare,
}

impl ProvisionedMemberPackage {
    /// Validates one pre-provisioned decryption key and Shamir share against the
    /// public descriptor.
    pub fn new(
        descriptor: CommitteeDescriptor,
        member_id: CommitteeMemberId,
        decryption_key: DecryptionKey,
        share: ShamirShare,
    ) -> Result<Self> {
        let public = descriptor
            .member(member_id)
            .ok_or(CommitteeError::ProvisioningMismatch)?;
        let derived_key = EncryptionKey::from(&decryption_key);
        let key_matches = derived_key.n() == public.encryption_key().n();
        let share_matches = share.public_commitment(descriptor.anchor_base())? == public.initial_share_commitment();
        if !key_matches || !share_matches {
            return Err(CommitteeError::ProvisioningMismatch);
        }
        Ok(Self {
            descriptor,
            member_id,
            decryption_key,
            share,
        })
    }
}

/// Secret state held by one committee-member process.
///
/// The state contains exactly one Paillier decryption key and exactly one
/// zeroizing Shamir share. It intentionally implements neither `Clone` nor
/// `Debug`, and its secret fields have no public accessors.
pub struct CommitteeMemberState {
    pub(crate) descriptor_id: CommitteeId,
    pub(crate) epoch: CommitteeEpoch,
    pub(crate) member_id: CommitteeMemberId,
    pub(crate) decryption_key: DecryptionKey,
    pub(crate) share: ShamirShare,
}

impl CommitteeMemberState {
    pub(crate) fn from_package(package: ProvisionedMemberPackage) -> (CommitteeDescriptor, Self) {
        let descriptor_id = package.descriptor.id();
        let epoch = package.descriptor.epoch();
        let descriptor = package.descriptor;
        (
            descriptor,
            Self {
                descriptor_id,
                epoch,
                member_id: package.member_id,
                decryption_key: package.decryption_key,
                share: package.share,
            },
        )
    }

    /// Returns the public descriptor identifier.
    #[must_use]
    pub const fn descriptor_id(&self) -> CommitteeId {
        self.descriptor_id
    }

    /// Returns this process's public committee epoch.
    #[must_use]
    pub const fn epoch(&self) -> CommitteeEpoch {
        self.epoch
    }

    /// Returns this process's public member identifier.
    #[must_use]
    pub const fn member_id(&self) -> CommitteeMemberId {
        self.member_id
    }

    /// Returns the public commitment to the currently durable Shamir share.
    pub fn current_share_commitment(&self, anchor_base: Point) -> Result<Point> {
        self.share.public_commitment(anchor_base)
    }
}

fn descriptor_digest(
    network: Network,
    deployment_id: &DeploymentId,
    epoch: CommitteeEpoch,
    threshold: u32,
    anchor_base: Point,
    members: &[CommitteeMemberDescriptor],
) -> CommitteeId {
    let mut hasher = Sha256::new();
    append_bytes(&mut hasher, b"bitcoin-thunderbolt/committee-descriptor/v1");
    append_bytes(&mut hasher, &[network_code(network)]);
    append_bytes(&mut hasher, deployment_id.as_bytes());
    hasher.update(epoch.get().to_be_bytes());
    hasher.update(threshold.to_be_bytes());
    append_bytes(&mut hasher, &anchor_base.serialize());
    hasher.update(u64::try_from(members.len()).unwrap_or(u64::MAX).to_be_bytes());
    for member in members {
        hasher.update(member.id.get().to_be_bytes());
        append_bytes(&mut hasher, &member.encryption_key.to_bytes());
        append_bytes(&mut hasher, &member.initial_share_commitment.serialize());
    }
    CommitteeId::from_bytes(hasher.finalize().into())
}

pub(crate) fn append_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

pub(crate) const fn network_code(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Testnet4 => 2,
        Network::Signet => 3,
        Network::Regtest => 4,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
