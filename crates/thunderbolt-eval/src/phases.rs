use bitcoin::{Address, Network, Transaction};
use bitcoin_utils::types::Utxo;

use thunderbolt_core::bitcoin_tx::{PrepareTxInfo, TxContext};
use thunderbolt_core::user::{User, UserLocal};

use crate::mock_committee::MockCommittee;
use crate::mock_transactions;
use crate::mock_users::MockUser;

pub async fn do_prepare(
    user: &UserLocal,
    committee: &impl User,
    network: Network,
    prepare_tx_info: &PrepareTxInfo,
) -> thunderbolt_core::Result<()> {
    let _tx_ctx = TxContext::initialize(
        user.get_bitcoin_account_local(),
        committee.get_bitcoin_account(),
        network,
        prepare_tx_info,
    )?;
    Ok(())
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
    mock_transactions::prepare_transfer_reassign_redeem(
        user_a,
        user_b,
        user_c,
        committee,
        prev_address,
        prev_outputs,
        prev_outputs_tx,
        sats_per_vbytes,
        receipient_address,
        fixed_amount,
    )
}
