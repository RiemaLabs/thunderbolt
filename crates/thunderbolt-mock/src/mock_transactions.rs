use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network, Transaction, XOnlyPublicKey};
use bitcoin_utils::types::Utxo;
use thunderbolt_core::protocol::{SigningContext, TxContext};
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
    let secp = Secp256k1::new();

    // [Off-chain] Step 1: Pubkey Generation

    let tx_ctx = TxContext::new(
        user.account.get_tweaked_x_pubkey().0,
        committee.account.get_tweaked_x_pubkey().0,
        Network::Testnet,
    );

    // [On-chain] Step 2: Nonce Generation

    let (user_nonce_index, user_p_pub_nonce) = user.gen_nonce();

    let (c_nonce_index, c_p_pub_nonce) = committee.gen_nonce(user.account.get_tweaked_x_pubkey().0, user_nonce_index);

    let user_p_pub_nonce = XOnlyPublicKey::from_slice(&user_p_pub_nonce.serialize_xonly()).unwrap();
    let committee_p_pub_nonce = XOnlyPublicKey::from_slice(&c_p_pub_nonce.serialize_xonly()).unwrap();

    let sign_ctx = SigningContext::new(user_p_pub_nonce, committee_p_pub_nonce, tx_ctx.p_pubkey);

    let mut prepare_tx = tx_ctx
        .construct_unsigned_prepare(
            &prev_address,
            prev_outputs,
            prev_outputs_tx,
            sats_per_vbytes,
            fixed_amount,
        )
        .unwrap();

    let signed_prepare_tx = tx_ctx
        .sign_prepare(
            &user.account.get_pubkey(),
            &prev_address,
            &mut prepare_tx,
            &secp,
            &user.account.xpriv,
        )
        .unwrap();

    let redeem_psbt = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, vec![])
        .unwrap();

    let (redeem_message, _) = tx_ctx.extract_message(&redeem_psbt).unwrap();

    let c_signature = sign_ctx.sign(
        committee.account.get_tweaked_secret(),
        committee.get_nonce(c_nonce_index),
        &redeem_message,
    );

    let user_signature = sign_ctx.sign(
        user.account.get_tweaked_secret(),
        user.get_nonce(user_nonce_index),
        &redeem_message,
    );

    let outputs = tx_ctx.default_outputs(fixed_amount, prev_address, sats_per_vbytes);

    let mut unsigned_redeem_tx = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, outputs)
        .unwrap();

    let c_signed_redeem_tx = tx_ctx
        .committee_sign_redeem(
            &mut unsigned_redeem_tx,
            committee.account.get_tweaked_x_pubkey().0,
            &secp,
            &committee.account.xpriv,
        )
        .unwrap();

    let final_signature = user_signature.1 + c_signature.1;

    let veri_result = schnorr_verify(
        tx_ctx.x_pubkey.serialize(),
        redeem_message.as_ref(),
        (sign_ctx.x_pubnonce.serialize(), final_signature),
    );
    assert!(veri_result);

    let final_redeem_tx = sign_ctx
        .user_combine_redeem(c_signed_redeem_tx, final_signature.unwrap())
        .unwrap();

    (signed_prepare_tx, final_redeem_tx)
}
