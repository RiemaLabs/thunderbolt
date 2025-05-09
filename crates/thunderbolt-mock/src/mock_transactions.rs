use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network, Psbt, Transaction, XOnlyPublicKey};
use bitcoin_utils::types::Utxo;
use thunderbolt_core::tx_constructor::BitcoinTxConstructor;
use thunderbolt_core::utils::schnorr_verify;

use crate::mock_committee::MockCommittee;
use crate::mock_users::MockUser;

pub fn prepare_redeem(
    mut user: MockUser,
    mut committee: MockCommittee,
    prev_address: Address,
    prev_outputs: Vec<Utxo>,
    prev_outputs_tx: Option<Transaction>,
    sats_per_vbytes: u64,
    fixed_amount: u64,
) -> (Transaction, Transaction) {
    let (user_nonce_index, user_p_pub_nonce) = user.gen_nonce();

    let (committee_nonce_index, committee_p_pub_nonce) =
        committee.gen_nonce(user.get_tweaked_x_pubkey(), user_nonce_index);

    let user_p_pub_nonce = XOnlyPublicKey::from_slice(&user_p_pub_nonce.serialize_xonly()).unwrap();
    let committee_p_pub_nonce = XOnlyPublicKey::from_slice(&committee_p_pub_nonce.serialize_xonly()).unwrap();

    let tx_constructor = BitcoinTxConstructor::new(
        user.get_tweaked_x_pubkey(),
        committee.get_x_pubkey(),
        user_p_pub_nonce,
        committee_p_pub_nonce,
        Network::Testnet,
    );

    println!("user tweaked x pubkey: {}", user.get_tweaked_x_pubkey());

    let mut prepare_tx = tx_constructor
        .construct_unsigned_prepare(
            &prev_address,
            prev_outputs,
            prev_outputs_tx,
            sats_per_vbytes,
            fixed_amount,
        )
        .unwrap();

    let secp = Secp256k1::new();

    let signed_prepare_tx = tx_constructor
        .sign_prepare(
            &user.get_pubkey(),
            &prev_address,
            &mut prepare_tx,
            &secp,
            &user.get_xpriv(),
        )
        .unwrap();

    let redeem_psbt = tx_constructor
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, vec![])
        .unwrap();

    let (redeem_message, _) = tx_constructor.extract_message(&redeem_psbt).unwrap();

    let committee_signature = tx_constructor
        .sign(
            &redeem_psbt,
            committee.get_nonce(committee_nonce_index),
            committee.get_secret(),
        )
        .unwrap();

    let user_signature = tx_constructor
        .sign(
            &redeem_psbt,
            user.get_nonce(user_nonce_index),
            user.get_tweaked_secret(),
        )
        .unwrap();

    let outputs = tx_constructor.default_outputs(fixed_amount, prev_address, sats_per_vbytes);

    let mut unsigned_redeem_tx = tx_constructor
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, outputs)
        .unwrap();

    let committee_signed_redeem_tx = tx_constructor
        .committee_sign_redeem(
            &mut unsigned_redeem_tx,
            committee.get_x_pubkey(),
            &secp,
            &committee.get_xpriv(),
        )
        .unwrap();

    let match_result = tx_constructor.p_pubkey_user == user.get_tweaked_secret().base_point_mul();

    assert!(match_result);

    let veri_result_0 = schnorr_verify(
        tx_constructor.p_pubkey_comm,
        (
            tx_constructor.p_pub_nonce_comm,
            secp::MaybeScalar::Valid(committee_signature),
        ),
        redeem_message.as_ref(),
    );

    assert!(veri_result_0);

    let veri_result_1 = schnorr_verify(
        tx_constructor.p_pubkey_user,
        (
            tx_constructor.p_pub_nonce_user,
            secp::MaybeScalar::Valid(user_signature),
        ),
        redeem_message.as_ref(),
    );

    assert!(veri_result_1);

    let final_signature = user_signature + committee_signature;

    let final_redeem_tx = tx_constructor
        .user_combine_redeem(committee_signed_redeem_tx, final_signature.unwrap())
        .unwrap();

    (signed_prepare_tx, final_redeem_tx)
}
