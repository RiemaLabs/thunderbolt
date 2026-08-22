use bitcoin::{Amount, BlockHash, Network, ScriptBuf};

/// Hard ceiling for the `sendrawtransaction` max-fee-rate argument (1 BTC/kvB).
pub const MAX_FEE_RATE_SAT_PER_KVB: u64 = 100_000_000;

/// Validated subset of Bitcoin Core's `getblockchaininfo` response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockchainInfo {
    /// Network selected by local configuration and verified against Core.
    pub network: Network,
    /// Current validated-chain height.
    pub blocks: u64,
    /// Best known header height.
    pub headers: u64,
    /// Current best-block hash.
    pub best_block_hash: BlockHash,
    /// Whether Core is still in initial block download.
    pub initial_block_download: bool,
    /// Whether block pruning is enabled.
    pub pruned: bool,
}

/// An unspent output returned by `gettxout`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutInfo {
    /// Best block used for the query.
    pub best_block: BlockHash,
    /// Number of confirmations, or zero for a mempool output.
    pub confirmations: u64,
    /// Exact output amount.
    pub value: Amount,
    /// Exact output script.
    pub script_pubkey: ScriptBuf,
    /// Whether the creating transaction is a coinbase transaction.
    pub coinbase: bool,
}

/// A conservative smart-fee estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeEstimate {
    /// Estimated fee in satoshis per 1,000 virtual bytes.
    pub sat_per_kvb: u64,
    /// Target Core actually used for the estimate.
    pub blocks: u16,
}
