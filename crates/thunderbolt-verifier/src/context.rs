use std::collections::BTreeMap;

use bitcoin::Network;
use thunderbolt_protocol::{ImplementationId, ParticipantId};
use thunderbolt_wire::{DeploymentId, PaillierPublicKeyHex, PointHex, MAX_COMMITTEE_MEMBERS, MAX_DEPLOYMENT_ID_BYTES};

pub use thunderbolt_wire::RECIPIENT_SHARE_MEMBER_ID;

use crate::{Result, VerifierError};

/// Exact public committee material trusted for one deployment epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitteeBinding {
    /// One committee Paillier key and ciphertext checked by an Invoice proof.
    Single {
        committee_id: ParticipantId,
        encryption_key: PaillierPublicKeyHex,
    },
    /// A fixed threshold and exact member-id-to-key roster.
    Threshold {
        committee_id: ParticipantId,
        threshold: u16,
        members: BTreeMap<u32, PaillierPublicKeyHex>,
    },
}

impl CommitteeBinding {
    /// Constructs a single-committee binding from a bounded public key.
    pub fn single(committee_id: ParticipantId, encryption_key: impl AsRef<[u8]>) -> Result<Self> {
        let encryption_key = PaillierPublicKeyHex::from_bytes("trusted committee encryption key", encryption_key)
            .map_err(|source| VerifierError::InvalidConfiguration {
                field: "committee.encryption_key",
                source,
            })?;
        Ok(Self::Single {
            committee_id,
            encryption_key,
        })
    }

    /// Constructs an exact threshold roster.
    pub fn threshold<I>(committee_id: ParticipantId, threshold: u16, members: I) -> Result<Self>
    where
        I: IntoIterator<Item = (u32, Vec<u8>)>,
    {
        let mut bounded = BTreeMap::new();
        for (member_id, encryption_key) in members {
            if member_id == 0 || member_id == RECIPIENT_SHARE_MEMBER_ID {
                return Err(VerifierError::InvalidConfigurationValue {
                    field: "committee.member_id",
                    reason: "member ids must be positive and must not use the reserved recipient id",
                });
            }
            let key = PaillierPublicKeyHex::from_bytes("trusted committee member encryption key", encryption_key)
                .map_err(|source| VerifierError::InvalidConfiguration {
                    field: "committee.member.encryption_key",
                    source,
                })?;
            if bounded.insert(member_id, key).is_some() {
                return Err(VerifierError::InvalidConfigurationValue {
                    field: "committee.members",
                    reason: "member ids must be unique",
                });
            }
        }

        let member_count = bounded.len();
        if member_count == 0 || member_count > MAX_COMMITTEE_MEMBERS {
            return Err(VerifierError::InvalidConfigurationValue {
                field: "committee.members",
                reason: "member count is outside the supported wire bound",
            });
        }
        if threshold == 0 || usize::from(threshold) > member_count {
            return Err(VerifierError::InvalidConfigurationValue {
                field: "committee.threshold",
                reason: "threshold must be between one and the member count",
            });
        }

        Ok(Self::Threshold {
            committee_id,
            threshold,
            members: bounded,
        })
    }

    /// Returns the committee identity committed by the channel snapshot.
    pub fn committee_id(&self) -> &ParticipantId {
        match self {
            Self::Single { committee_id, .. } | Self::Threshold { committee_id, .. } => committee_id,
        }
    }
}

/// Trusted, epoch-specific public deployment context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentContext {
    network: Network,
    deployment_id: DeploymentId,
    committee_epoch: u64,
    anchor_base: PointHex,
    committee: CommitteeBinding,
}

impl DeploymentContext {
    /// Validates and constructs a trusted public deployment context.
    pub fn new(
        network: Network,
        deployment_id: impl AsRef<[u8]>,
        committee_epoch: u64,
        anchor_base: impl AsRef<[u8]>,
        committee: CommitteeBinding,
    ) -> Result<Self> {
        let deployment_id = DeploymentId::from_bytes("trusted deployment id", deployment_id).map_err(|source| {
            VerifierError::InvalidConfiguration {
                field: "deployment_id",
                source,
            }
        })?;
        let anchor_base = PointHex::from_bytes("trusted anchor base", anchor_base).map_err(|source| {
            VerifierError::InvalidConfiguration {
                field: "anchor_base",
                source,
            }
        })?;
        Ok(Self {
            network,
            deployment_id,
            committee_epoch,
            anchor_base,
            committee,
        })
    }

    pub(crate) const fn network(&self) -> Network {
        self.network
    }

    pub(crate) fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    pub(crate) const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }

    pub(crate) fn anchor_base(&self) -> &PointHex {
        &self.anchor_base
    }

    pub(crate) fn committee(&self) -> &CommitteeBinding {
        &self.committee
    }

    /// Maximum deployment identifier width accepted by this context.
    pub const fn max_deployment_id_bytes() -> usize {
        MAX_DEPLOYMENT_ID_BYTES
    }
}

/// Identity recorded on node-produced verification evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierIdentity {
    participant_id: ParticipantId,
    implementation: ImplementationId,
}

impl VerifierIdentity {
    /// Constructs an identity from already validated protocol identifiers.
    pub fn new(participant_id: ParticipantId, implementation: ImplementationId) -> Self {
        Self {
            participant_id,
            implementation,
        }
    }

    pub(crate) fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    pub(crate) fn implementation(&self) -> &ImplementationId {
        &self.implementation
    }
}
