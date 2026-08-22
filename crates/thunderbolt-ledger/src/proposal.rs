use secp256k1::Secp256k1;
use serde::{Deserialize, Deserializer, Serialize};
use thunderbolt_wire::{CanonicalDigest as _, ChannelBindingV2, ValidateWire as _};

use crate::canonical::CanonicalTranscript;
use crate::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRequestIdV2, ActorRoleV2, ActorSignatureV2, CanonicalEventV2,
    ChannelContextIdV2, ClientRequestNonceV2, EntryHashV2, EventDigestV2, EventKindV2, LedgerChainIdV2,
    LedgerContractError, ParticipantIdV2, ProposalDigestV2, RequestDigestV2, Result, LEDGER_PROTOCOL_VERSION_V2,
};

/// Canonical protocol-v2 proposal body authenticated by one actor key.
///
/// All fields are private so a value can only enter the system through the
/// validating constructor or validating serde implementation. The stable
/// channel binding is signed through both its canonical digest and context id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalBodyV2 {
    protocol_version: u16,
    ledger_chain_id: LedgerChainIdV2,
    channel: ChannelBindingV2,
    sequence: u64,
    previous_entry_hash: EntryHashV2,
    request_id: ActorRequestIdV2,
    actor_key_algorithm: ActorKeyAlgorithmV2,
    actor_public_key: ActorPublicKeyV2,
    actor_role: ActorRoleV2,
    event_kind: EventKindV2,
    event: CanonicalEventV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalBodyInput {
    protocol_version: u16,
    ledger_chain_id: LedgerChainIdV2,
    channel: ChannelBindingV2,
    sequence: u64,
    previous_entry_hash: EntryHashV2,
    request_id: ActorRequestIdInput,
    actor_key_algorithm: ActorKeyAlgorithmV2,
    actor_public_key: ActorPublicKeyV2,
    actor_role: ActorRoleV2,
    event_kind: EventKindV2,
    event: CanonicalEventV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorRequestIdInput {
    nonce: ClientRequestNonceV2,
    digest: RequestDigestV2,
}

impl<'de> Deserialize<'de> for ProposalBodyV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ProposalBodyInput::deserialize(deserializer)?;
        if input.protocol_version != LEDGER_PROTOCOL_VERSION_V2 {
            return Err(serde::de::Error::custom(LedgerContractError::InvalidProposal {
                reason: "unsupported Ledger protocol version",
            }));
        }
        let supplied_request_digest = input.request_id.digest;
        let body = Self::new(
            input.ledger_chain_id,
            input.channel,
            input.sequence,
            input.previous_entry_hash,
            input.request_id.nonce,
            input.actor_key_algorithm,
            input.actor_public_key,
            input.actor_role,
            input.event_kind,
            input.event,
        )
        .map_err(serde::de::Error::custom)?;
        if body.request_id.digest() != &supplied_request_digest {
            return Err(serde::de::Error::custom(LedgerContractError::RequestBindingMismatch));
        }
        Ok(body)
    }
}

impl ProposalBodyV2 {
    /// Validates and constructs one proposal body without consulting a clock,
    /// filesystem, random-number generator, or external service.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        channel: ChannelBindingV2,
        sequence: u64,
        previous_entry_hash: EntryHashV2,
        request_nonce: ClientRequestNonceV2,
        actor_key_algorithm: ActorKeyAlgorithmV2,
        actor_public_key: ActorPublicKeyV2,
        actor_role: ActorRoleV2,
        event_kind: EventKindV2,
        event: CanonicalEventV2,
    ) -> Result<Self> {
        channel.validate_wire()?;
        validate_chain_shape(sequence, &previous_entry_hash, event_kind)?;
        let request_id = ActorRequestIdV2::derive(
            &ledger_chain_id,
            &channel,
            actor_key_algorithm,
            &actor_public_key,
            actor_role,
            request_nonce,
        )?;
        Ok(Self {
            protocol_version: LEDGER_PROTOCOL_VERSION_V2,
            ledger_chain_id,
            channel,
            sequence,
            previous_entry_hash,
            request_id,
            actor_key_algorithm,
            actor_public_key,
            actor_role,
            event_kind,
            event,
        })
    }

    /// Revalidates every cross-field proposal invariant.
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != LEDGER_PROTOCOL_VERSION_V2 {
            return Err(LedgerContractError::InvalidProposal {
                reason: "unsupported Ledger protocol version",
            });
        }
        self.channel.validate_wire()?;
        validate_chain_shape(self.sequence, &self.previous_entry_hash, self.event_kind)?;
        let expected = ActorRequestIdV2::derive(
            &self.ledger_chain_id,
            &self.channel,
            self.actor_key_algorithm,
            &self.actor_public_key,
            self.actor_role,
            self.request_id.nonce().clone(),
        )?;
        if expected.digest() != self.request_id.digest() {
            return Err(LedgerContractError::RequestBindingMismatch);
        }
        Ok(())
    }

    /// Returns the Ledger protocol version.
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the consensus Ledger chain id bound into all replay domains.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Rejects a proposal intended for another consensus Ledger cluster.
    pub fn validate_chain_id(&self, expected: &LedgerChainIdV2) -> Result<()> {
        if &self.ledger_chain_id != expected {
            return Err(LedgerContractError::InvalidProposal {
                reason: "Ledger chain id does not match the local consensus chain",
            });
        }
        Ok(())
    }

    /// Returns the complete stable channel binding.
    pub const fn channel(&self) -> &ChannelBindingV2 {
        &self.channel
    }

    /// Returns the per-channel sequence number.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the prior committed entry hash.
    pub const fn previous_entry_hash(&self) -> &EntryHashV2 {
        &self.previous_entry_hash
    }

    /// Returns the channel- and actor-bound retry identifier.
    pub const fn request_id(&self) -> &ActorRequestIdV2 {
        &self.request_id
    }

    /// Returns the explicit actor key algorithm profile.
    pub const fn actor_key_algorithm(&self) -> ActorKeyAlgorithmV2 {
        self.actor_key_algorithm
    }

    /// Returns the validated actor public key.
    pub const fn actor_public_key(&self) -> &ActorPublicKeyV2 {
        &self.actor_public_key
    }

    /// Returns the participant id derived from the authenticated actor key.
    pub fn participant_id(&self) -> Result<ParticipantIdV2> {
        self.actor_public_key.participant_id(self.actor_key_algorithm)
    }

    /// Returns the authenticated protocol role.
    pub const fn actor_role(&self) -> ActorRoleV2 {
        self.actor_role
    }

    /// Returns the permanent event discriminant.
    pub const fn event_kind(&self) -> EventKindV2 {
        self.event_kind
    }

    /// Borrows the bounded canonical event bytes.
    pub const fn event(&self) -> &CanonicalEventV2 {
        &self.event
    }

    /// Returns the exact domain-separated, length-prefixed signing bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let channel_digest = self.channel.canonical_digest()?;
        let channel_context_id = self.channel.context_id()?;
        let participant_id = self.participant_id()?;
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/ledger-proposal/v2")?;
        transcript.u16(b"ledger_protocol_version", self.protocol_version)?;
        transcript.item(b"ledger_chain_id", self.ledger_chain_id.as_bytes())?;
        transcript.item(b"channel_binding_digest", &channel_digest)?;
        transcript.item(b"channel_context_id", &channel_context_id)?;
        transcript.u64(b"sequence", self.sequence)?;
        transcript.item(b"previous_entry_hash", self.previous_entry_hash.as_bytes())?;
        transcript.item(b"client_request_nonce", self.request_id.nonce().as_bytes())?;
        transcript.item(b"actor_request_digest", self.request_id.digest().as_bytes())?;
        transcript.u8(b"actor_key_algorithm", self.actor_key_algorithm.tag())?;
        transcript.item(b"actor_public_key", self.actor_public_key.as_bytes())?;
        transcript.item(b"participant_id", participant_id.as_bytes())?;
        transcript.u8(b"actor_role", self.actor_role.tag())?;
        transcript.u8(b"event_kind", self.event_kind.tag())?;
        transcript.item(b"canonical_event", self.event.as_bytes())?;
        Ok(transcript.finish())
    }

    /// Computes the exact 32-byte message authenticated by BIP340-v1.
    pub fn proposal_digest(&self) -> Result<ProposalDigestV2> {
        self.validate()?;
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/ledger-proposal-digest/v2")?;
        transcript.item(b"canonical_proposal", &self.canonical_bytes()?)?;
        ProposalDigestV2::from_bytes(transcript.digest())
    }

    /// Computes the stable entry hash used by the per-channel predecessor chain.
    ///
    /// The signature bytes are intentionally excluded. A valid BIP340 signer
    /// may use different auxiliary randomness when retrying the same body; such
    /// retries remain one logical entry and one request id.
    pub fn entry_hash(&self) -> Result<EntryHashV2> {
        let proposal_digest = self.proposal_digest()?;
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/ledger-entry-hash/v2")?;
        transcript.item(b"ledger_chain_id", self.ledger_chain_id.as_bytes())?;
        transcript.item(b"proposal_digest", proposal_digest.as_bytes())?;
        EntryHashV2::from_bytes(transcript.digest())
    }

    /// Checks this proposal against the last committed metadata for its channel.
    pub fn validate_predecessor(&self, predecessor: Option<&CommittedEntryMetadataV2>) -> Result<()> {
        match predecessor {
            None if self.sequence == 0 && self.previous_entry_hash.is_zero() => Ok(()),
            None => Err(LedgerContractError::InvalidProposal {
                reason: "non-opening proposal requires committed predecessor metadata",
            }),
            Some(_) if self.sequence == 0 => Err(LedgerContractError::InvalidProposal {
                reason: "opening proposal must not have predecessor metadata",
            }),
            Some(predecessor) => {
                if predecessor.ledger_chain_id != self.ledger_chain_id {
                    return Err(LedgerContractError::InvalidProposal {
                        reason: "predecessor belongs to another Ledger chain",
                    });
                }
                let expected_sequence =
                    predecessor
                        .sequence
                        .checked_add(1)
                        .ok_or(LedgerContractError::InvalidProposal {
                            reason: "predecessor sequence overflow",
                        })?;
                if predecessor.channel_context_id.as_bytes() != &self.channel.context_id()? {
                    return Err(LedgerContractError::InvalidProposal {
                        reason: "predecessor belongs to another stable channel",
                    });
                }
                if self.sequence != expected_sequence || self.previous_entry_hash != predecessor.entry_hash {
                    return Err(LedgerContractError::InvalidProposal {
                        reason: "sequence or previous entry hash does not extend predecessor",
                    });
                }
                Ok(())
            }
        }
    }
}

/// A proposal carrying an actor's validated BIP340-v1 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProposalV2 {
    body: ProposalBodyV2,
    signature: ActorSignatureV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedProposalInput {
    body: ProposalBodyV2,
    signature: ActorSignatureV2,
}

impl<'de> Deserialize<'de> for SignedProposalV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = SignedProposalInput::deserialize(deserializer)?;
        Self::new(input.body, input.signature).map_err(serde::de::Error::custom)
    }
}

impl SignedProposalV2 {
    /// Attaches and verifies an externally produced BIP340-v1 signature.
    ///
    /// Secret keys stay in a keystore or external signer. This deterministic
    /// contract accepts only the resulting 64-byte signature.
    pub fn new(body: ProposalBodyV2, signature: ActorSignatureV2) -> Result<Self> {
        let proposal = Self { body, signature };
        proposal.verify()?;
        Ok(proposal)
    }

    /// Verifies the body invariants and BIP340 signature.
    pub fn verify(&self) -> Result<()> {
        self.body.validate()?;
        let digest = self.body.proposal_digest()?;
        let verifier = Secp256k1::verification_only();
        verifier
            .verify_schnorr(
                &self.signature.to_signature(),
                digest.as_bytes(),
                &self.body.actor_public_key.to_x_only_public_key()?,
            )
            .map_err(|_| LedgerContractError::InvalidActorSignature)
    }

    /// Returns the canonical binary envelope for deterministic transport hashes.
    ///
    /// The entry hash deliberately remains a function of the body alone so a
    /// retry signed with different BIP340 auxiliary randomness is still the
    /// same logical request. This envelope nevertheless gives storage and
    /// consensus adapters one unambiguous encoding of the supplied signature.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.verify()?;
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/signed-ledger-proposal/v2")?;
        transcript.item(b"canonical_proposal_body", &self.body.canonical_bytes()?)?;
        transcript.item(b"actor_signature", self.signature.as_bytes())?;
        Ok(transcript.finish())
    }

    /// Returns a signature-free capability view for a deterministic reducer.
    ///
    /// Verification is repeated before issuing the view, so reducer code never
    /// needs to parse a signature or trust a free participant-name string.
    pub fn verified_view(&self) -> Result<VerifiedProposalViewV2<'_>> {
        self.verify()?;
        Ok(VerifiedProposalViewV2 {
            ledger_chain_id: &self.body.ledger_chain_id,
            channel: &self.body.channel,
            sequence: self.body.sequence,
            previous_entry_hash: &self.body.previous_entry_hash,
            entry_hash: self.body.entry_hash()?,
            request_digest: self.body.request_id.digest(),
            participant_id: self.body.participant_id()?,
            actor_role: self.body.actor_role,
            event_kind: self.body.event_kind,
            event: &self.body.event,
        })
    }

    /// Returns the authenticated proposal body.
    pub const fn body(&self) -> &ProposalBodyV2 {
        &self.body
    }

    /// Returns the verified BIP340 signature bytes.
    pub const fn signature(&self) -> &ActorSignatureV2 {
        &self.signature
    }

    /// Consumes the signed proposal and returns its body.
    pub fn into_body(self) -> ProposalBodyV2 {
        self.body
    }
}

/// Signature-free authenticated proposal fields consumed by a reducer.
///
/// This capability can only be obtained by verifying a [`SignedProposalV2`].
/// Consensus block height and time remain properties of [`crate::PendingBlockV2`]
/// and [`crate::FinalizedBlockV2`], not actor-controlled proposal fields.
#[derive(Clone, Debug)]
pub struct VerifiedProposalViewV2<'a> {
    ledger_chain_id: &'a LedgerChainIdV2,
    channel: &'a ChannelBindingV2,
    sequence: u64,
    previous_entry_hash: &'a EntryHashV2,
    entry_hash: EntryHashV2,
    request_digest: &'a RequestDigestV2,
    participant_id: ParticipantIdV2,
    actor_role: ActorRoleV2,
    event_kind: EventKindV2,
    event: &'a CanonicalEventV2,
}

impl<'a> VerifiedProposalViewV2<'a> {
    /// Returns the consensus Ledger chain id authenticated by the actor.
    pub const fn ledger_chain_id(&self) -> &'a LedgerChainIdV2 {
        self.ledger_chain_id
    }

    /// Returns the complete stable channel binding authenticated by the actor.
    pub const fn channel(&self) -> &'a ChannelBindingV2 {
        self.channel
    }

    /// Returns the per-channel sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the authenticated prior entry hash.
    pub const fn previous_entry_hash(&self) -> &'a EntryHashV2 {
        self.previous_entry_hash
    }

    /// Returns the authenticated hash to persist as the new channel head.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the scoped idempotency digest.
    pub const fn request_digest(&self) -> &'a RequestDigestV2 {
        self.request_digest
    }

    /// Returns the participant identity derived from the actor key.
    pub const fn participant_id(&self) -> &ParticipantIdV2 {
        &self.participant_id
    }

    /// Returns the authenticated protocol role.
    pub const fn actor_role(&self) -> ActorRoleV2 {
        self.actor_role
    }

    /// Returns the permanent event discriminant.
    pub const fn event_kind(&self) -> EventKindV2 {
        self.event_kind
    }

    /// Returns the bounded canonical public event bytes.
    pub const fn event(&self) -> &'a CanonicalEventV2 {
        self.event
    }
}

/// Deterministic, query-friendly metadata for one committed entry.
///
/// Every field is derived from a verified proposal and its exact block
/// position. Deserialization recomputes and compares the complete value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEntryMetadataV2 {
    block_height: u64,
    block_time_ms: u64,
    block_index: u32,
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
    sequence: u64,
    previous_entry_hash: EntryHashV2,
    proposal_digest: ProposalDigestV2,
    entry_hash: EntryHashV2,
    request_digest: RequestDigestV2,
    participant_id: ParticipantIdV2,
    actor_role: ActorRoleV2,
    event_kind: EventKindV2,
    event_digest: EventDigestV2,
}

impl CommittedEntryMetadataV2 {
    pub(crate) fn derive(
        block_height: u64,
        block_time_ms: u64,
        block_index: u32,
        proposal: &SignedProposalV2,
    ) -> Result<Self> {
        if block_height == 0 {
            return Err(LedgerContractError::InvalidBlock {
                reason: "block height must be positive",
            });
        }
        if block_time_ms == 0 {
            return Err(LedgerContractError::InvalidBlock {
                reason: "consensus block time must be positive",
            });
        }
        proposal.verify()?;
        let body = proposal.body();
        Ok(Self {
            block_height,
            block_time_ms,
            block_index,
            ledger_chain_id: body.ledger_chain_id.clone(),
            channel_context_id: ChannelContextIdV2::from_bytes(body.channel.context_id()?)?,
            sequence: body.sequence,
            previous_entry_hash: body.previous_entry_hash.clone(),
            proposal_digest: body.proposal_digest()?,
            entry_hash: body.entry_hash()?,
            request_digest: body.request_id.digest().clone(),
            participant_id: body.participant_id()?,
            actor_role: body.actor_role,
            event_kind: body.event_kind,
            event_digest: body.event.digest()?,
        })
    }

    /// Returns the finalized block height.
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Returns the trusted consensus block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }

    /// Returns the zero-based entry position within the block.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }

    /// Returns the consensus Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the stable channel context id.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the per-channel sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the prior committed channel entry hash.
    pub const fn previous_entry_hash(&self) -> &EntryHashV2 {
        &self.previous_entry_hash
    }

    /// Returns the BIP340 message digest.
    pub const fn proposal_digest(&self) -> &ProposalDigestV2 {
        &self.proposal_digest
    }

    /// Returns the stable hash used by the channel predecessor chain.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the channel- and actor-bound idempotency digest.
    pub const fn request_digest(&self) -> &RequestDigestV2 {
        &self.request_digest
    }

    /// Returns the participant id derived from the authenticated actor key.
    pub const fn participant_id(&self) -> &ParticipantIdV2 {
        &self.participant_id
    }

    /// Returns the authenticated role.
    pub const fn actor_role(&self) -> ActorRoleV2 {
        self.actor_role
    }

    /// Returns the event discriminant.
    pub const fn event_kind(&self) -> EventKindV2 {
        self.event_kind
    }

    /// Returns the digest of canonical event bytes.
    pub const fn event_digest(&self) -> &EventDigestV2 {
        &self.event_digest
    }
}

/// A verified signed proposal paired with recomputable committed metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedEntryV2 {
    proposal: SignedProposalV2,
    metadata: CommittedEntryMetadataV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedEntryInput {
    proposal: SignedProposalV2,
    metadata: CommittedEntryMetadataV2Input,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedEntryMetadataV2Input {
    block_height: u64,
    block_time_ms: u64,
    block_index: u32,
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
    sequence: u64,
    previous_entry_hash: EntryHashV2,
    proposal_digest: ProposalDigestV2,
    entry_hash: EntryHashV2,
    request_digest: RequestDigestV2,
    participant_id: ParticipantIdV2,
    actor_role: ActorRoleV2,
    event_kind: EventKindV2,
    event_digest: EventDigestV2,
}

impl CommittedEntryMetadataV2Input {
    fn into_metadata(self) -> CommittedEntryMetadataV2 {
        CommittedEntryMetadataV2 {
            block_height: self.block_height,
            block_time_ms: self.block_time_ms,
            block_index: self.block_index,
            ledger_chain_id: self.ledger_chain_id,
            channel_context_id: self.channel_context_id,
            sequence: self.sequence,
            previous_entry_hash: self.previous_entry_hash,
            proposal_digest: self.proposal_digest,
            entry_hash: self.entry_hash,
            request_digest: self.request_digest,
            participant_id: self.participant_id,
            actor_role: self.actor_role,
            event_kind: self.event_kind,
            event_digest: self.event_digest,
        }
    }
}

impl<'de> Deserialize<'de> for CommittedEntryV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = CommittedEntryInput::deserialize(deserializer)?;
        let supplied_metadata = input.metadata.into_metadata();
        let entry = Self::derive(
            supplied_metadata.block_height,
            supplied_metadata.block_time_ms,
            supplied_metadata.block_index,
            input.proposal,
        )
        .map_err(serde::de::Error::custom)?;
        if entry.metadata != supplied_metadata {
            return Err(serde::de::Error::custom(LedgerContractError::InvalidBlock {
                reason: "committed entry metadata does not match proposal",
            }));
        }
        Ok(entry)
    }
}

impl CommittedEntryV2 {
    pub(crate) fn derive(
        block_height: u64,
        block_time_ms: u64,
        block_index: u32,
        proposal: SignedProposalV2,
    ) -> Result<Self> {
        let metadata = CommittedEntryMetadataV2::derive(block_height, block_time_ms, block_index, &proposal)?;
        Ok(Self { proposal, metadata })
    }

    /// Returns the verified signed proposal.
    pub const fn proposal(&self) -> &SignedProposalV2 {
        &self.proposal
    }

    /// Returns deterministic committed metadata.
    pub const fn metadata(&self) -> &CommittedEntryMetadataV2 {
        &self.metadata
    }
}

fn validate_chain_shape(sequence: u64, previous_entry_hash: &EntryHashV2, event_kind: EventKindV2) -> Result<()> {
    if sequence == 0 {
        if !previous_entry_hash.is_zero() {
            return Err(LedgerContractError::InvalidProposal {
                reason: "sequence zero requires the zero previous-entry hash",
            });
        }
        if event_kind != EventKindV2::Open {
            return Err(LedgerContractError::InvalidProposal {
                reason: "sequence zero must carry an Open event",
            });
        }
    } else {
        if previous_entry_hash.is_zero() {
            return Err(LedgerContractError::InvalidProposal {
                reason: "nonzero sequence requires a nonzero previous-entry hash",
            });
        }
        if event_kind == EventKindV2::Open {
            return Err(LedgerContractError::InvalidProposal {
                reason: "Open event is only valid at sequence zero",
            });
        }
    }
    Ok(())
}
