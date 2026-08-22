use std::error::Error;

use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, FloorReadRequest, VaultCheckpoint, VaultIdentity};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultRevision, VaultRole,
    VaultStateDigest,
};

const READ_CANONICAL_HEX: &str = concat!(
    "0000000000000021626974636f696e2d7468756e646572626f6c742f666c6f6f722f726561642f7631",
    "00000000000000187468756e646572626f6c742d666c6f6f722d676f6c64656e",
    "0201",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "0000000000000009",
    "3333333333333333333333333333333333333333333333333333333333333333"
);
const READ_DIGEST_HEX: &str = "70580c9af3ea51378b2fa49e4e7c875cc58778385aa5d73f3df3d29eaf341d21";
const CAS_CANONICAL_HEX: &str = concat!(
    "0000000000000020626974636f696e2d7468756e646572626f6c742f666c6f6f722f6361732f7631",
    "00000000000000187468756e646572626f6c742d666c6f6f722d676f6c64656e",
    "0201",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "0000000000000009",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "01",
    "0000000000000004",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "0000000000000005",
    "5555555555555555555555555555555555555555555555555555555555555555"
);
const CAS_DIGEST_HEX: &str = "1499f99b96b9a2fcdc2fec3896e2c11a0ccc729579fe88e09908bc36065b1e2e";

fn identity() -> Result<VaultIdentity, Box<dyn Error>> {
    Ok(VaultIdentity::new(
        Network::Signet,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x22; 32])?,
            9,
            CommitteeDescriptorDigest::new([0x33; 32])?,
        )?,
    ))
}

fn chain_id() -> Result<FloorLedgerChainId, Box<dyn Error>> {
    Ok(FloorLedgerChainId::new(b"thunderbolt-floor-golden".to_vec())?)
}

#[test]
fn read_request_matches_golden_vector() -> Result<(), Box<dyn Error>> {
    let request = FloorReadRequest::new(&chain_id()?, identity()?);
    assert_eq!(request.canonical_bytes(), hex::decode(READ_CANONICAL_HEX)?);
    assert_eq!(request.digest().as_bytes().as_slice(), hex::decode(READ_DIGEST_HEX)?);
    Ok(())
}

#[test]
fn cas_request_matches_golden_vector() -> Result<(), Box<dyn Error>> {
    let expected = VaultCheckpoint::new(VaultRevision::new(4), VaultStateDigest::new([0x44; 32]));
    let next = VaultCheckpoint::new(VaultRevision::new(5), VaultStateDigest::new([0x55; 32]));
    let request = FloorCasRequest::new(&chain_id()?, identity()?, Some(expected), next)?;
    assert_eq!(request.canonical_bytes(), hex::decode(CAS_CANONICAL_HEX)?);
    assert_eq!(request.digest().as_bytes().as_slice(), hex::decode(CAS_DIGEST_HEX)?);
    Ok(())
}
