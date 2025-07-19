use cosmrs::{proto::cosmos::tx::v1beta1::TxRaw, Any, ErrorReport, Tx};

use crate::{client_mock::MockTxBuilder, pubkey::ThunderboltPublicKey, TxBuilder};

#[derive(Debug, Clone)]
pub enum TxBuilderEnum {
    Real(TxBuilder),
    Mock(MockTxBuilder),
}

impl TxBuilderEnum {
    pub fn address(&self) -> String {
        match self {
            TxBuilderEnum::Real(builder) => builder.address(),
            TxBuilderEnum::Mock(builder) => builder.address(),
        }
    }

    pub fn signer_pubkey(&self) -> ThunderboltPublicKey {
        match self {
            TxBuilderEnum::Real(builder) => builder.signer_pubkey(),
            TxBuilderEnum::Mock(builder) => builder.signer_pubkey(),
        }
    }

    pub fn build_tx_default(&self, msg: Any, gas_limit: u64, sequence: u64) -> Tx {
        match self {
            TxBuilderEnum::Real(builder) => builder.build_tx_default(msg, gas_limit, sequence),
            TxBuilderEnum::Mock(builder) => builder.build_tx_default(msg, gas_limit, sequence),
        }
    }

    pub fn sign_tx(&self, unsigned_tx: Tx, account_number: u64) -> Result<TxRaw, ErrorReport> {
        match self {
            TxBuilderEnum::Real(builder) => builder.sign_tx(unsigned_tx, account_number),
            TxBuilderEnum::Mock(builder) => builder.sign_tx(unsigned_tx, account_number),
        }
    }
}
