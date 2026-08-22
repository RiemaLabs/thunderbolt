use bitcoin::key::Secp256k1;
use bitcoin::taproot::Signature;
use bitcoin::{Address, Network, Transaction};
use bitcoin_utils::types::Utxo;
use secp::Scalar;
use thunderbolt_core::bitcoin_account::BitcoinAccountLocal;
use thunderbolt_core::bitcoin_tx::{PrepareTxInfo, TxContext};
use thunderbolt_core::tweak::Tweaker;

use crate::mock_committee::MockCommittee;
use crate::mock_users::MockUser;

fn prepare_context(
    user: &MockUser,
    committee: &MockCommittee,
    prev_address: Address,
    prev_outputs: Vec<Utxo>,
    prev_outputs_tx: Option<Transaction>,
    sats_per_vbytes: u64,
    fixed_amount: u64,
) -> (TxContext, Transaction) {
    let user_account = BitcoinAccountLocal::new(user.account.clone(), Network::Testnet);
    let committee_account = BitcoinAccountLocal::new(committee.account.clone(), Network::Testnet);
    let prepare_info = PrepareTxInfo {
        prev_address,
        prev_outputs,
        prev_outputs_tx,
        sats_per_vbytes,
        fixed_amount,
    };
    let tx_ctx = TxContext::initialize(&user_account, &committee_account, Network::Testnet, &prepare_info)
        .expect("mock transaction fixture must construct");
    let signed_prepare_tx = tx_ctx.get_signed_prepare().clone();
    (tx_ctx, signed_prepare_tx)
}

fn redeem_signatures(
    tx_ctx: &TxContext,
    fixed_amount: u64,
    redeem_psbt: &bitcoin::Psbt,
    committee: &MockCommittee,
    user: &MockUser,
) -> (Signature, Signature) {
    let secp = Secp256k1::new();

    let c_signature = tx_ctx
        .sign_redeem_script_path(fixed_amount, redeem_psbt, &secp, &committee.account.get_keypair())
        .unwrap();
    let user_signature = tx_ctx
        .sign_redeem_script_path(fixed_amount, redeem_psbt, &secp, &user.account.get_keypair())
        .unwrap();

    (c_signature, user_signature)
}

fn scalar_from_sig(signature: &Signature) -> Scalar {
    let bytes = signature.signature.serialize();
    Scalar::from_slice(&bytes[32..64]).unwrap()
}

fn tweak_signature(signature: &Signature, tweaked_s: Scalar) -> Signature {
    let mut out = [0u8; 64];
    let bytes = signature.signature.serialize();
    out[0..32].copy_from_slice(&bytes[0..32]);
    out[32..64].copy_from_slice(&tweaked_s.serialize());
    Signature {
        signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&out).unwrap(),
        sighash_type: signature.sighash_type,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_redeem(
    user: MockUser,
    committee: MockCommittee,
    prev_address: Address,
    prev_outputs: Vec<Utxo>,
    prev_outputs_tx: Option<Transaction>,
    sats_per_vbytes: u64,
    receipient_address: Address,
    fixed_amount: u64,
) -> (Transaction, Transaction) {
    let (tx_ctx, signed_prepare_tx) = prepare_context(
        &user,
        &committee,
        prev_address,
        prev_outputs,
        prev_outputs_tx,
        sats_per_vbytes,
        fixed_amount,
    );

    let outputs = tx_ctx
        .default_redeem_outputs(fixed_amount, receipient_address, sats_per_vbytes)
        .expect("mock redeem output must be standard");
    let mut redeem_psbt = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, outputs)
        .unwrap();

    let (c_signature, user_signature) = redeem_signatures(&tx_ctx, fixed_amount, &redeem_psbt, &committee, &user);

    let final_redeem_tx = tx_ctx
        .aggregate_redeem(&mut redeem_psbt, user_signature, c_signature)
        .unwrap();

    (signed_prepare_tx, final_redeem_tx)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_transfer_reassign_redeem(
    user_a: MockUser,
    user_b: MockUser,
    user_c: MockUser,
    committee: MockCommittee,
    prev_address: Address,
    prev_outputs: Vec<Utxo>,
    prev_outputs_tx: Option<Transaction>,
    sats_per_vbytes: u64,
    receipient_address: Address,
    fixed_amount: u64,
) -> (Transaction, Transaction) {
    let (tx_ctx, signed_prepare_tx) = prepare_context(
        &user_a,
        &committee,
        prev_address,
        prev_outputs,
        prev_outputs_tx,
        sats_per_vbytes,
        fixed_amount,
    );

    let outputs = tx_ctx
        .default_redeem_outputs(fixed_amount, receipient_address, sats_per_vbytes)
        .expect("mock redeem output must be standard");
    let mut redeem_psbt = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, outputs)
        .unwrap();

    let (c_signature, user_signature) = redeem_signatures(&tx_ctx, fixed_amount, &redeem_psbt, &committee, &user_a);

    let c_sig_aux_scalar = scalar_from_sig(&c_signature);
    let u_sig_aux_scalar = scalar_from_sig(&user_signature);

    let tweaker_ab = Tweaker::new(
        user_a.account.get_tweaked_secret(),
        user_b.account.get_tweaked_p_pubkey(),
    );
    let tweaker_ba = Tweaker::new(
        user_b.account.get_tweaked_secret(),
        user_a.account.get_tweaked_p_pubkey(),
    );
    let tweaker_bc = Tweaker::new(
        user_b.account.get_tweaked_secret(),
        user_c.account.get_tweaked_p_pubkey(),
    );
    let tweaker_cb = Tweaker::new(
        user_c.account.get_tweaked_secret(),
        user_b.account.get_tweaked_p_pubkey(),
    );
    let tweaker_comm_c = Tweaker::new(
        committee.account.get_tweaked_secret(),
        user_c.account.get_tweaked_p_pubkey(),
    );
    let tweaker_c_comm = Tweaker::new(
        user_c.account.get_tweaked_secret(),
        committee.account.get_tweaked_p_pubkey(),
    );

    let tweaked_user_signature = u_sig_aux_scalar + tweaker_ab.compute_shared_secret().expect("mock tweak must derive")
        - tweaker_ba.compute_shared_secret().expect("mock tweak must derive")
        + tweaker_bc.compute_shared_secret().expect("mock tweak must derive")
        - tweaker_cb.compute_shared_secret().expect("mock tweak must derive");
    let tweaked_c_signature = c_sig_aux_scalar
        + tweaker_comm_c.compute_shared_secret().expect("mock tweak must derive")
        - tweaker_c_comm.compute_shared_secret().expect("mock tweak must derive");

    let final_tweaked_user_signature = tweak_signature(&user_signature, tweaked_user_signature.unwrap());
    let final_tweaked_c_signature = tweak_signature(&c_signature, tweaked_c_signature.unwrap());

    let final_redeem_tx = tx_ctx
        .aggregate_redeem(
            &mut redeem_psbt,
            final_tweaked_user_signature,
            final_tweaked_c_signature,
        )
        .unwrap();

    (signed_prepare_tx, final_redeem_tx)
}
