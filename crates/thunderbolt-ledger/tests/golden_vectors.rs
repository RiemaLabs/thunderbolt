mod common;

use thunderbolt_ledger::{ActorRoleV2, AppHashV2, PendingBlockV2};

use common::signed_open;

#[test]
fn protocol_v2_hash_and_signature_golden_vectors() {
    let first = signed_open(
        "thunderbolt-regtest-1",
        [0x44; 32],
        7,
        9,
        3,
        ActorRoleV2::Holder,
        vec![0x55; 16],
        vec![0x00, 0x01, 0x02, 0x03, 0xfe, 0xff],
    );
    let second = signed_open(
        "thunderbolt-regtest-1",
        [0x45; 32],
        8,
        9,
        4,
        ActorRoleV2::Recipient,
        vec![0x66; 16],
        vec![0x10, 0x20, 0x30, 0x40],
    );

    let participant_id = first.body().participant_id().expect("participant id");
    let request_digest = first.body().request_id().digest();
    let proposal_digest = first.body().proposal_digest().expect("proposal digest");
    let entry_hash = first.body().entry_hash().expect("entry hash");

    let mut block = PendingBlockV2::new(
        first.body().ledger_chain_id().clone(),
        1,
        1_720_000_000_123,
        AppHashV2::zero(),
    )
    .expect("pending block");
    block.push(first.clone()).expect("first entry");
    block.push(second).expect("second entry");
    let finalized = block.finalize().expect("finalized block");

    assert_eq!(
        participant_id.to_hex(),
        "d02f4de9dbe52df83035fbc844e875ede246629fca3f7e8a7af0343d18226763"
    );
    assert_eq!(
        request_digest.to_hex(),
        "10a6aeda1b3f3f415aa3afdf904c3c1ed4687e8b13399b687f2a0dff7a124fc7"
    );
    assert_eq!(
        proposal_digest.to_hex(),
        "e95b9ae7e69c38a42d10482881dfeab8135e78b0079d57ab1d4e81822437482e"
    );
    assert_eq!(
        entry_hash.to_hex(),
        "573979a30e182778b886ce48eafb59ac6fa2db75ff8b7740c9baca35a4a73662"
    );
    assert_eq!(
        first.signature().to_hex(),
        "241594032a5953f52b4abed9b21b8087babd235476786f5b7cf86ca1f4b8594d\
         c322e86ab94834e763c0b4c35c48a11ea43507fe2c84d771584f9e098751af3b"
    );
    assert_eq!(
        finalized.entry_merkle_root().to_hex(),
        "28dd4cbbb0bf642481521aa1484dac363e396bfb594fe8639afec2310555b307"
    );
    assert_eq!(
        finalized.app_hash().to_hex(),
        "f54854c14b6dcc935a51d5d453066e31c21decea1c8350a295c0179a751aa5d1"
    );
}
