use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Network, Txid};
use bitcoin_utils::types::Utxo;
use thunderbolt_mock::mock_committee::{committee_account, MockCommittee};
use thunderbolt_mock::mock_transactions::prepare_redeem;
use thunderbolt_mock::mock_users::{alice_account, bob_account, MockUser};

fn consensus_utxo(output: &bitcoin::TxOut) -> bitcoinconsensus::Utxo {
    bitcoinconsensus::Utxo {
        script_pubkey: output.script_pubkey.as_bytes().as_ptr(),
        script_pubkey_len: output.script_pubkey.len() as u32,
        value: output.value.to_sat() as i64,
    }
}

#[test]
fn prepare_and_redeem_witnesses_pass_bitcoin_consensus() {
    let alice = MockUser::new(alice_account());
    let committee = MockCommittee::new(committee_account());
    let previous_address = alice.account.p2tr_address(Network::Regtest);
    let previous_script = previous_address.script_pubkey();
    let previous_value = Amount::from_sat(200_000);
    let recipient = bob_account().p2tr_address(Network::Regtest);
    let previous_output = bitcoin::TxOut {
        value: previous_value,
        script_pubkey: previous_script.clone(),
    };
    let utxo = Utxo {
        txid: Txid::from_byte_array([0x42; 32]),
        vout: 0,
        value: previous_value,
    };

    let (prepare, redeem) = prepare_redeem(
        alice,
        committee,
        previous_address,
        vec![utxo],
        None,
        1,
        recipient,
        100_000,
    );

    let previous_consensus = [consensus_utxo(&previous_output)];
    bitcoinconsensus::verify(
        previous_script.as_bytes(),
        previous_value.to_sat(),
        &serialize(&prepare),
        Some(&previous_consensus),
        0,
    )
    .expect("prepare witness must satisfy the funding output");

    let locked_output = &prepare.output[0];
    let locked_consensus = [consensus_utxo(locked_output)];
    bitcoinconsensus::verify(
        locked_output.script_pubkey.as_bytes(),
        locked_output.value.to_sat(),
        &serialize(&redeem),
        Some(&locked_consensus),
        0,
    )
    .expect("redeem witness must satisfy the Thunderbolt TapScript");

    let witness_items = redeem.input[0].witness.iter().collect::<Vec<_>>();
    assert_eq!(witness_items[0].len(), 65, "SIGHASH_ALL must be encoded");
    assert_eq!(witness_items[1].len(), 65, "SIGHASH_ALL must be encoded");
}
