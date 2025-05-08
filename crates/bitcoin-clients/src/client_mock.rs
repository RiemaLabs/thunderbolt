use std::collections::HashMap;

use anyhow::Result;
use bitcoin::{Address, Transaction, Txid};

use super::client::{BitcoinClient, TxStatus, UtxoInfo};

pub struct BitcoinClientMock {
    pub addr2utxos: HashMap<Address, Vec<UtxoInfo>>,
    pub txid2status: HashMap<Txid, TxStatus>,
    pub height: u64,
    pub sats_per_vbytes: u64,
}

impl BitcoinClientMock {
    pub fn new() -> Self {
        Self {
            addr2utxos: HashMap::new(),
            txid2status: HashMap::new(),
            height: 0,
            sats_per_vbytes: 1,
        }
    }
}

#[async_trait::async_trait]
impl BitcoinClient for BitcoinClientMock {
    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoInfo>> {
        Ok(self.addr2utxos.get(address).unwrap_or(&vec![]).clone())
    }

    async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus> {
        Ok(self
            .txid2status
            .get(txid)
            .unwrap_or(&TxStatus { confirmed: false, block_height: None })
            .clone())
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid> {
        Ok(tx.compute_txid())
    }

    async fn get_minimum_fee(&self) -> Result<u64> {
        Ok(self.sats_per_vbytes)
    }

    async fn get_block_height(&self) -> Result<u64> {
        Ok(self.height)
    }
}
