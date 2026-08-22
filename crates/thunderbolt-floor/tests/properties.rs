use proptest::prelude::*;
use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, FloorReadRequest, VaultCheckpoint, VaultIdentity};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultRevision, VaultRole,
    VaultStateDigest,
};

fn make_identity(node: [u8; 32], deployment: [u8; 32], epoch: u64, descriptor: [u8; 32]) -> VaultIdentity {
    VaultIdentity::new(
        Network::Signet,
        VaultRole::CommitteeMember,
        NodeId::new(node),
        DeploymentBinding::new(
            DeploymentId::new(deployment).expect("generated deployment is nonzero"),
            epoch,
            CommitteeDescriptorDigest::new(descriptor).expect("generated descriptor is nonzero"),
        )
        .expect("generated epoch is positive"),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn canonical_requests_are_deterministic_and_identity_bound(
        node_byte in 1_u8..=255,
        deployment_byte in 1_u8..=255,
        descriptor_byte in 1_u8..=255,
        epoch in 1_u64..=u64::MAX,
    ) {
        let identity = make_identity(
            [node_byte; 32],
            [deployment_byte; 32],
            epoch,
            [descriptor_byte; 32],
        );
        let chain_id = FloorLedgerChainId::new(b"floor-property-chain".to_vec()).expect("chain id");
        let first = FloorReadRequest::new(&chain_id, identity);
        let second = FloorReadRequest::new(&chain_id, identity);
        prop_assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        prop_assert_eq!(first.digest(), second.digest());

        let changed_node = FloorReadRequest::new(&chain_id, make_identity(
            [node_byte.wrapping_add(1); 32],
            [deployment_byte; 32],
            epoch,
            [descriptor_byte; 32],
        ));
        prop_assert_ne!(first.digest(), changed_node.digest());
        let other_chain = FloorLedgerChainId::new(b"floor-property-other".to_vec()).expect("chain id");
        prop_assert_ne!(first.digest(), FloorReadRequest::new(&other_chain, identity).digest());
    }

    #[test]
    fn exact_next_transition_is_accepted_and_forks_are_distinct(
        revision in 0_u64..u64::MAX,
        previous_byte in 0_u8..=255,
        next_byte in 0_u8..=255,
    ) {
        let identity = make_identity([1; 32], [2; 32], 1, [3; 32]);
        let chain_id = FloorLedgerChainId::new(b"floor-property-chain".to_vec()).expect("chain id");
        let previous = VaultCheckpoint::new(
            VaultRevision::new(revision),
            VaultStateDigest::new([previous_byte; 32]),
        );
        let distinct_byte = if next_byte == previous_byte { next_byte ^ 1 } else { next_byte };
        let next = VaultCheckpoint::new(
            VaultRevision::new(revision + 1),
            VaultStateDigest::new([distinct_byte; 32]),
        );
        let request = FloorCasRequest::new(&chain_id, identity, Some(previous), next)?;
        let mut fork_byte = previous_byte.wrapping_add(1);
        if fork_byte == distinct_byte {
            fork_byte = fork_byte.wrapping_add(1);
        }
        let fork = VaultCheckpoint::new(
            VaultRevision::new(revision + 1),
            VaultStateDigest::new([fork_byte; 32]),
        );
        let fork_request = FloorCasRequest::new(&chain_id, identity, Some(previous), fork)?;
        prop_assert_ne!(request.digest(), fork_request.digest());

        let same_revision = VaultCheckpoint::new(
            VaultRevision::new(revision),
            VaultStateDigest::new([distinct_byte; 32]),
        );
        prop_assert!(FloorCasRequest::new(&chain_id, identity, Some(previous), same_revision).is_err());
    }
}
