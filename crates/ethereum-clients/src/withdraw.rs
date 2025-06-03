use alloy::primitives::{Address as EthAddress, U256};
use alloy::rpc::types::{Filter, Log};
use alloy::sol;
use alloy::transports::{RpcError, TransportErrorKind};
use serde::{Deserialize, Serialize};

use ethereum_utils::types::EthTxIdentifier;

use super::client::EthereumClient;

sol!(
    #[allow(missing_docs)]
    event WithdrawRequest(address indexed sender, string btcAddress, uint256 amount);
);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParsedWithdrawRequestEvent {
    pub sender: EthAddress,
    pub btc_address: String,
    pub amount: U256,
    pub tx_idt: EthTxIdentifier,
}

impl ParsedWithdrawRequestEvent {
    pub fn new(sender: EthAddress, btc_address: String, amount: U256, tx_idt: EthTxIdentifier) -> Self {
        Self {
            sender,
            btc_address,
            amount,
            tx_idt,
        }
    }
}

pub async fn extract_withdraw_events(
    eth_client: &EthereumClient,
    start_block: u64,
    end_block: u64,
    bridge_address: EthAddress,
) -> Result<Vec<ParsedWithdrawRequestEvent>, RpcError<TransportErrorKind>> {
    let mut events: Vec<ParsedWithdrawRequestEvent> = vec![];

    // Filter is inclusive on both ends, so it gets events from [start_block, end_block]
    let filter = Filter::new()
        .address(bridge_address)
        .from_block(start_block)
        .to_block(end_block);

    let logs: Vec<Log> = eth_client.provider().get_logs(&filter).await?;

    for log in logs {
        let event = log.log_decode::<WithdrawRequest>();
        if event.is_err() {
            continue;
        }
        let event = event.unwrap();
        let parsed_event = ParsedWithdrawRequestEvent::new(
            event.data().sender,
            event.data().btcAddress.clone(),
            event.data().amount,
            EthTxIdentifier::new(
                log.transaction_hash.unwrap(),
                log.transaction_index.unwrap(),
                log.block_hash.unwrap(),
                log.block_number.unwrap(),
                // There is a missing timestamp in the nubit thuderbolt testnet and mainnet.
                log.block_timestamp.unwrap_or(0),
            ),
        );
        events.push(parsed_event);
    }

    Ok(events)
}
