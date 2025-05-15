use std::str::FromStr;

use bitcoin::hex::DisplayHex;
use bitcoin::{consensus, Amount, Network, Txid};
use bitcoin_clients::client::{BitcoinClient, BitcoinClientEnum};
use bitcoin_clients::faucet::{init_nubit_client, prepare_utxo};
use bitcoin_utils::types::Utxo;
use thunderbolt_mock::mock_committee::{MockCommittee, COMMITTEE};
use thunderbolt_mock::mock_transactions::prepare_redeem;
use thunderbolt_mock::mock_users::{MockUser, ALICE, BOB, ZETA};

#[tokio::test]
async fn test_prepare_redeem() {
    let alice = MockUser::new(ALICE.clone());
    let bob = MockUser::new(BOB.clone());
    let committee = MockCommittee::new(COMMITTEE.clone());
    let client = BitcoinClientEnum::Electrs(init_nubit_client().await);
    let fixed_amount = 1000000;
    let funding_amount = Amount::from_sat(fixed_amount + 1000);
    let sender_address = alice.account.p2tr_address(Network::Testnet);
    let receipient_address = bob.account.p2tr_address(Network::Testnet);
    let utxo_info = prepare_utxo(&client, &sender_address, funding_amount).await.unwrap();

    let utxo = Utxo {
        txid: Txid::from_str(&utxo_info.txid).unwrap(),
        vout: utxo_info.vout,
        value: Amount::from_sat(utxo_info.value),
    };

    let sats_per_vbytes = 1;

    let (prepare_tx, redeem_tx) = prepare_redeem(
        alice,
        committee,
        sender_address,
        vec![utxo],
        None,
        sats_per_vbytes,
        receipient_address,
        fixed_amount,
    );

    let prepare_txid = prepare_tx.compute_txid();
    let redeem_txid = redeem_tx.compute_txid();

    println!("prepare_txid: {}", prepare_txid);
    println!("redeem_txid: {}", redeem_txid);

    println!(
        "redeem_tx_hex: {}",
        consensus::serialize(&redeem_tx).to_lower_hex_string()
    );

    _ = client.broadcast_transaction(&prepare_tx).await.unwrap();
    let mut prepare_confirmed = false;

    while !prepare_confirmed {
        let prepare_tx_info = client.get_tx_status(&prepare_txid).await.unwrap();
        prepare_confirmed = prepare_tx_info.confirmed;
    }

    let result = client.broadcast_transaction(&redeem_tx).await.unwrap();
    assert_eq!(result, redeem_txid);
}

// #[tokio::test]
// async fn test_prepare_transfer_reassign_redeem() {
//     let alice = MockUser::new(ALICE.clone());
//     let bob = MockUser::new(BOB.clone());
//     let zeta = MockUser::new(ZETA.clone());
//     let committee = MockCommittee::new(COMMITTEE.clone());
//     let client = BitcoinClientEnum::Electrs(init_nubit_client().await);

//     let fixed_amount = 1000000;
//     let funding_amount = Amount::from_sat(fixed_amount + 1000);
//     let sender_address = alice.account.p2tr_address(Network::Testnet);
//     let receipient_address = bob.account.p2tr_address(Network::Testnet);
//     let utxo_info = prepare_utxo(&client, &sender_address, funding_amount).await.unwrap();

//     let utxo = Utxo {
//         txid: Txid::from_str(&utxo_info.txid).unwrap(),
//         vout: utxo_info.vout,
//         value: Amount::from_sat(utxo_info.value),
//     };

//     let sats_per_vbytes = 1;

//     let (prepare_tx, redeem_tx) = prepare_transfer_reassign_redeem(
//         alice,
//         bob,
//         zeta,
//         committee,
//         sender_address,
//         vec![utxo],
//         None,
//         sats_per_vbytes,
//         receipient_address,
//         fixed_amount,
//     );

//     let prepare_txid = prepare_tx.compute_txid();
//     let redeem_txid = redeem_tx.compute_txid();

//     println!("prepare_txid: {}", prepare_txid);
//     println!("redeem_txid: {}", redeem_txid);

//     _ = client.broadcast_transaction(&prepare_tx).await.unwrap();
//     let mut prepare_confirmed = false;

//     while !prepare_confirmed {
//         let prepare_tx_info = client.get_tx_status(&prepare_txid).await.unwrap();
//         prepare_confirmed = prepare_tx_info.confirmed;
//     }

//     let result = client.broadcast_transaction(&redeem_tx).await.unwrap();
//     assert_eq!(result, redeem_txid);
// }
