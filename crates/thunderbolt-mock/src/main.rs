pub mod mock_committee;
pub mod mock_users;

use std::str::FromStr;

use bitcoin::{Amount, Network, Txid, XOnlyPublicKey};
use bitcoin_utils::types::Utxo;
use mock_committee::{MockCommittee, COMMITTEE};
use mock_users::{MockUser, ALICE, BOB, ZETA};
use thunderbolt_core::tx_constructor::BitcoinTxConstructor;

fn main() {
    let mut alice = MockUser::new(ALICE.clone());
    let mut bob = MockUser::new(BOB.clone());
    let mut zeta = MockUser::new(ZETA.clone());

    let mut committee = MockCommittee::new(COMMITTEE.clone());

    // Prepare.

    let (alice_nonce_index, alice_p_pub_nonce) = alice.gen_nonce();
    let (committee_nonce_index, committee_p_pub_nonce) = committee.gen_nonce(alice.get_pubkey(), alice_nonce_index);

    let alice_p_pub_nonce = XOnlyPublicKey::from_slice(&alice_p_pub_nonce.serialize_uncompressed()[1..]).unwrap();
    let committee_p_pub_nonce =
        XOnlyPublicKey::from_slice(&committee_p_pub_nonce.serialize_uncompressed()[1..]).unwrap();

    let tx_constructor = BitcoinTxConstructor::new(
        alice.get_pubkey(),
        committee.get_pubkey(),
        alice_p_pub_nonce,
        committee_p_pub_nonce,
        Network::Testnet,
    );

    let prev_address = alice.account.p2tr_address(Network::Testnet);
    let prev_outputs = vec![Utxo {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
        vout: 0,
        value: Amount::from_sat(1100000),
    }];
    let prev_outputs_tx = None;
    let sats_per_vbytes = 10;
    let fixed_amount = 1000000;

    let prepare_tx = tx_constructor.construct_unsigned_prepare(
        &prev_address,
        prev_outputs,
        prev_outputs_tx,
        sats_per_vbytes,
        fixed_amount,
    );
}
