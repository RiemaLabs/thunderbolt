
use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network, Transaction, XOnlyPublicKey};
use bitcoin_utils::types::Utxo;
use thunderbolt_core::protocol::TxContext;
use thunderbolt_core::tweak::Tweaker;
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
    receipient_address: Address,
    fixed_amount: u64,
) -> (Transaction, Transaction) {
    let secp = Secp256k1::new();

    // Step 1: Generate Tx Context
    let tx_ctx = TxContext::new(
        user.account.get_tweaked_x_pubkey().0,
        committee.account.get_tweaked_x_pubkey().0,
        Network::Testnet,
    );

    // Step 2: Construct Prepare Transaction

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

    // Step 3: Sign
    let c_signature = tx_ctx
        .sign_redeem_funding_utxo(
            fixed_amount,
            &mut redeem_psbt.clone(),
            &secp,
            &committee.account.get_tweaked_keypair(),
        )
        .unwrap();

    let user_signature = tx_ctx
        .sign_redeem_funding_utxo(
            fixed_amount,
            &mut redeem_psbt.clone(),
            &secp,
            &user.account.get_tweaked_keypair(),
        )
        .unwrap();

  

    let outputs = tx_ctx.default_redeem_outputs(fixed_amount, receipient_address, sats_per_vbytes);

    let mut unsigned_redeem_tx = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, outputs)
        .unwrap();

    let c_signed_redeem_tx = tx_ctx
        .sign_redeem_dummy_utxo(&mut unsigned_redeem_tx, &secp, &committee.account.get_tweaked_keypair())
        .unwrap();

    // [On-chain] Step 4: Redeem Transaction

    let final_redeem_tx = tx_ctx
        .aggregate_redeem(c_signed_redeem_tx, user_signature, c_signature)
        .unwrap();

    (signed_prepare_tx, final_redeem_tx)
}



pub fn prepare_transfer_reassign_redeem(
    mut user_a: MockUser,
    user_b: MockUser,
    user_c: MockUser,
    mut committee: MockCommittee,
    prev_address: Address,
    prev_outputs: Vec<Utxo>,
    prev_outputs_tx: Option<Transaction>,
    sats_per_vbytes: u64,
    receipient_address: Address,
    fixed_amount: u64,
) -> (Transaction, Transaction) {
    let secp = Secp256k1::new();

    // [Off-chain] Step 1: Pubkey Generation

    let tx_ctx = TxContext::new(
        user_a.account.get_tweaked_x_pubkey().0,
        committee.account.get_tweaked_x_pubkey().0,
        Network::Testnet,
    );




    // [On-chain] Step 3: Prepare Transaction

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
            &user_a.account.get_pubkey(),
            &prev_address,
            &mut prepare_tx,
            &secp,
            &user_a.account.xpriv,
        )
        .unwrap();

    let redeem_psbt = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, vec![])
        .unwrap();

    // generate c_signature and user_signature

    let c_signature = tx_ctx
        .sign_redeem_funding_utxo(
            fixed_amount,
            &mut redeem_psbt.clone(),
            &secp,
            &committee.account.get_tweaked_keypair(),
        )
        .unwrap();

    let user_signature = tx_ctx
        .sign_redeem_funding_utxo(
            fixed_amount,
            &mut redeem_psbt.clone(),
            &secp,
            &user_a.account.get_tweaked_keypair(),
        )
        .unwrap();

       

 

    // [On-chain] Step 3.1: Tweak Signature

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

    let tweaking_ab = tweaker_ab.compute_shared_secret();
    let tweaking_ba = tweaker_ba.compute_shared_secret();
    let tweaking_bc = tweaker_bc.compute_shared_secret();
    let tweaking_cb = tweaker_cb.compute_shared_secret();

    let tweaking_comm_c = tweaker_comm_c.compute_shared_secret();
    let tweaking_c_comm = tweaker_c_comm.compute_shared_secret();
    
    

    //let tweaked_user_signature = user_signature.1 + tweaking_ab - tweaking_ba + tweaking_bc - tweaking_cb;
    //let tweaked_c_signature = c_signature.1 + tweaking_comm_c - tweaking_c_comm;

   

    let outputs = tx_ctx.default_redeem_outputs(fixed_amount, receipient_address, sats_per_vbytes);

    let mut unsigned_redeem_tx = tx_ctx
        .construct_unsigned_redeem(signed_prepare_tx.compute_txid(), fixed_amount, outputs)
        .unwrap();

    let c_signed_redeem_tx = tx_ctx
        .sign_redeem_dummy_utxo(&mut unsigned_redeem_tx, &secp, &committee.account.get_tweaked_keypair())
        .unwrap();

    // [On-chain] Step 4: Redeem Transaction

    //use tweaked_user_signature and tweaked_c_signature to siagn the redeem transaction

    let final_redeem_tx = tx_ctx
        .aggregate_redeem(
            c_signed_redeem_tx,
           user_signature,
            c_signature,
        )
        .unwrap();

    (signed_prepare_tx, final_redeem_tx)
}
