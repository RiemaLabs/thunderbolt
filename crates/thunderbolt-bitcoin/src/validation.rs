use bitcoin::constants::COINBASE_MATURITY;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};

use crate::{TxOutInfo, ValidationError};

const MAX_OUTPUT_RULES: usize = 64;
const MAX_OUTPUT_COUNT: u16 = 64;

/// Protocol-authorized funding output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingExpectation {
    /// Exact funding outpoint.
    outpoint: OutPoint,
    /// Exact funding script.
    script_pubkey: ScriptBuf,
    /// Exact funding amount.
    amount: Amount,
    /// Minimum accepted confirmation count.
    min_confirmations: u64,
}

impl FundingExpectation {
    /// Creates a funding policy that cannot accept an unconfirmed output.
    pub fn new(
        outpoint: OutPoint,
        script_pubkey: ScriptBuf,
        amount: Amount,
        min_confirmations: u64,
    ) -> std::result::Result<Self, ValidationError> {
        if min_confirmations == 0 {
            return Err(ValidationError::InvalidFundingExpectation(
                "minimum confirmations must be at least one",
            ));
        }
        Ok(Self {
            outpoint,
            script_pubkey,
            amount,
            min_confirmations,
        })
    }

    /// Exact funding outpoint.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Exact funding output script.
    #[must_use]
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }

    /// Exact funding amount.
    #[must_use]
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// Minimum accepted confirmation count for a non-coinbase output.
    #[must_use]
    pub const fn min_confirmations(&self) -> u64 {
        self.min_confirmations
    }
}

/// Bitcoin-observed state of an outpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FundingState {
    /// Core reports the output as unspent.
    Unspent(TxOutInfo),
    /// `gettxout` returned null, which cannot distinguish spent from unknown.
    SpentOrMissing,
}

/// A funding observation bound to the outpoint that was queried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingObservation {
    /// Queried outpoint.
    pub outpoint: OutPoint,
    /// Current state returned by Bitcoin Core.
    pub state: FundingState,
}

impl FundingObservation {
    /// Converts a `gettxout` result into an explicit spent-or-missing state.
    #[must_use]
    pub fn from_get_tx_out(outpoint: OutPoint, result: Option<TxOutInfo>) -> Self {
        let state = result.map_or(FundingState::SpentOrMissing, FundingState::Unspent);
        Self { outpoint, state }
    }
}

/// Validates the outpoint, spent state, script, amount, and confirmations.
pub fn validate_funding_outpoint(
    expected: &FundingExpectation,
    observed: &FundingObservation,
) -> std::result::Result<(), ValidationError> {
    if observed.outpoint != expected.outpoint {
        return Err(ValidationError::FundingOutpointMismatch);
    }
    let FundingState::Unspent(output) = &observed.state else {
        return Err(ValidationError::FundingSpentOrMissing);
    };
    if output.script_pubkey != expected.script_pubkey {
        return Err(ValidationError::FundingScriptMismatch);
    }
    if output.value != expected.amount {
        return Err(ValidationError::FundingAmountMismatch);
    }
    let coinbase_maturity = u64::from(COINBASE_MATURITY);
    let required_confirmations = if output.coinbase {
        expected.min_confirmations.max(coinbase_maturity)
    } else {
        expected.min_confirmations
    };
    if output.confirmations < required_confirmations {
        return Err(ValidationError::FundingConfirmations {
            actual: output.confirmations,
            required: required_confirmations,
        });
    }
    Ok(())
}

/// An allowlisted closing-output script, amount range, and occurrence range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedOutput {
    script_pubkey: ScriptBuf,
    min_amount: Amount,
    max_amount: Amount,
    min_count: u16,
    max_count: u16,
}

impl AllowedOutput {
    /// Creates a bounded output rule. Amount and count ranges are inclusive.
    pub fn new(
        script_pubkey: ScriptBuf,
        min_amount: Amount,
        max_amount: Amount,
        min_count: u16,
        max_count: u16,
    ) -> std::result::Result<Self, ValidationError> {
        if min_amount > max_amount {
            return Err(ValidationError::InvalidClosingPolicy("output amount range is inverted"));
        }
        if min_count > max_count || max_count == 0 || max_count > MAX_OUTPUT_COUNT {
            return Err(ValidationError::InvalidClosingPolicy("output count range is invalid"));
        }
        Ok(Self {
            script_pubkey,
            min_amount,
            max_amount,
            min_count,
            max_count,
        })
    }

    /// Allowed output script.
    #[must_use]
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }

    /// Inclusive minimum output amount.
    #[must_use]
    pub const fn min_amount(&self) -> Amount {
        self.min_amount
    }

    /// Inclusive maximum output amount.
    #[must_use]
    pub const fn max_amount(&self) -> Amount {
        self.max_amount
    }

    /// Inclusive minimum occurrence count.
    #[must_use]
    pub const fn min_count(&self) -> u16 {
        self.min_count
    }

    /// Inclusive maximum occurrence count.
    #[must_use]
    pub const fn max_count(&self) -> u16 {
        self.max_count
    }
}

/// Complete fail-closed policy for one closing transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingPolicy {
    funding_outpoint: OutPoint,
    funding_amount: Amount,
    expected_txid: Txid,
    allowed_outputs: Vec<AllowedOutput>,
    min_fee: Amount,
    max_fee: Amount,
}

impl ClosingPolicy {
    /// Creates a policy after checking internal amount, fee, and allowlist bounds.
    pub fn new(
        funding_outpoint: OutPoint,
        funding_amount: Amount,
        expected_txid: Txid,
        allowed_outputs: Vec<AllowedOutput>,
        min_fee: Amount,
        max_fee: Amount,
    ) -> std::result::Result<Self, ValidationError> {
        if allowed_outputs.is_empty() || allowed_outputs.len() > MAX_OUTPUT_RULES {
            return Err(ValidationError::InvalidClosingPolicy("output rule count is invalid"));
        }
        if min_fee > max_fee || max_fee > funding_amount {
            return Err(ValidationError::InvalidClosingPolicy("fee range is invalid"));
        }
        for (index, rule) in allowed_outputs.iter().enumerate() {
            if allowed_outputs
                .iter()
                .take(index)
                .any(|earlier| earlier.script_pubkey == rule.script_pubkey)
            {
                return Err(ValidationError::InvalidClosingPolicy("output scripts must be unique"));
            }
        }

        let minimum_outputs = allowed_outputs.iter().try_fold(0_u64, |total, rule| {
            let rule_minimum = rule
                .min_amount
                .to_sat()
                .checked_mul(u64::from(rule.min_count))
                .ok_or(ValidationError::InvalidClosingPolicy("minimum output amount overflows"))?;
            total
                .checked_add(rule_minimum)
                .ok_or(ValidationError::InvalidClosingPolicy("minimum output amount overflows"))
        })?;
        let minimum_total =
            minimum_outputs
                .checked_add(min_fee.to_sat())
                .ok_or(ValidationError::InvalidClosingPolicy(
                    "minimum transaction amount overflows",
                ))?;
        if minimum_total > funding_amount.to_sat() {
            return Err(ValidationError::InvalidClosingPolicy(
                "required outputs and minimum fee exceed funding",
            ));
        }

        Ok(Self {
            funding_outpoint,
            funding_amount,
            expected_txid,
            allowed_outputs,
            min_fee,
            max_fee,
        })
    }

    /// Authorized funding outpoint.
    #[must_use]
    pub const fn funding_outpoint(&self) -> OutPoint {
        self.funding_outpoint
    }

    /// Known value of the sole funding input.
    #[must_use]
    pub const fn funding_amount(&self) -> Amount {
        self.funding_amount
    }

    /// Authorized closing txid.
    #[must_use]
    pub const fn expected_txid(&self) -> Txid {
        self.expected_txid
    }

    /// Output allowlist.
    #[must_use]
    pub fn allowed_outputs(&self) -> &[AllowedOutput] {
        &self.allowed_outputs
    }

    /// Inclusive minimum fee.
    #[must_use]
    pub const fn min_fee(&self) -> Amount {
        self.min_fee
    }

    /// Inclusive maximum fee.
    #[must_use]
    pub const fn max_fee(&self) -> Amount {
        self.max_fee
    }
}

/// Values established by successful closing-transaction validation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClosingValidation {
    /// Validated transaction identifier.
    pub txid: Txid,
    /// Sum of all validated outputs.
    pub output_amount: Amount,
    /// Exact fee derived from the sole known input.
    pub fee: Amount,
}

/// Validates the exact input, output allowlist, fee, and txid of a closing transaction.
pub fn validate_closing_transaction(
    transaction: &Transaction,
    policy: &ClosingPolicy,
) -> std::result::Result<ClosingValidation, ValidationError> {
    if transaction.input.len() != 1
        || transaction.input.first().map(|input| input.previous_output) != Some(policy.funding_outpoint)
    {
        return Err(ValidationError::ClosingInputs);
    }

    let mut counts = vec![0_u16; policy.allowed_outputs.len()];
    let mut output_sats = 0_u64;
    for output in &transaction.output {
        let Some((index, rule)) = policy
            .allowed_outputs
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.script_pubkey == output.script_pubkey)
        else {
            return Err(ValidationError::ClosingOutputScript);
        };
        if output.value < rule.min_amount || output.value > rule.max_amount {
            return Err(ValidationError::ClosingOutputAmount);
        }
        let count = counts
            .get_mut(index)
            .ok_or(ValidationError::InvalidClosingPolicy("output rule index is invalid"))?;
        *count = count.checked_add(1).ok_or(ValidationError::ClosingOutputCount)?;
        if *count > rule.max_count {
            return Err(ValidationError::ClosingOutputCount);
        }
        output_sats = output_sats
            .checked_add(output.value.to_sat())
            .ok_or(ValidationError::ClosingAmountOverflow)?;
    }

    if counts
        .iter()
        .zip(&policy.allowed_outputs)
        .any(|(count, rule)| *count < rule.min_count || *count > rule.max_count)
    {
        return Err(ValidationError::ClosingOutputCount);
    }

    let fee_sats = policy
        .funding_amount
        .to_sat()
        .checked_sub(output_sats)
        .ok_or(ValidationError::ClosingOutputsExceedFunding)?;
    let fee = Amount::from_sat(fee_sats);
    if fee < policy.min_fee || fee > policy.max_fee {
        return Err(ValidationError::ClosingFee);
    }

    let txid = transaction.compute_txid();
    if txid != policy.expected_txid {
        return Err(ValidationError::ClosingTxid);
    }

    Ok(ClosingValidation {
        txid,
        output_amount: Amount::from_sat(output_sats),
        fee,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{BlockHash, Sequence, TxIn, TxOut, Witness};
    use proptest::prelude::*;

    use super::*;

    fn outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 1,
        }
    }

    fn script(tag: u8) -> ScriptBuf {
        ScriptBuf::from_bytes(vec![1, tag])
    }

    fn closing_transaction(funding: OutPoint, amount: u64, output_script: ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: output_script,
            }],
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn exact_amount_and_fee_invariants_hold(
            funding in 1_u64..2_100_000_000_000_000_u64,
            fee_seed in any::<u64>(),
            lower_seed in any::<u64>(),
            upper_seed in any::<u64>(),
        ) {
            let fee = fee_seed % funding;
            let output = funding - fee;
            let tx = closing_transaction(outpoint(), output, script(1));
            let rule = AllowedOutput::new(
                script(1),
                Amount::ZERO,
                Amount::from_sat(funding),
                1,
                1,
            )?;
            let lower = lower_seed % funding;
            let upper = lower.saturating_add(upper_seed % (funding - lower + 1)).min(funding);
            let policy = ClosingPolicy::new(
                outpoint(),
                Amount::from_sat(funding),
                tx.compute_txid(),
                vec![rule],
                Amount::from_sat(lower),
                Amount::from_sat(upper),
            )?;
            let result = validate_closing_transaction(&tx, &policy);
            prop_assert_eq!(result.is_ok(), (lower..=upper).contains(&fee));
            if let Ok(validated) = result {
                prop_assert_eq!(validated.fee.to_sat(), fee);
                prop_assert_eq!(validated.output_amount.to_sat() + validated.fee.to_sat(), funding);
            }
        }

        #[test]
        fn funding_validator_rejects_any_amount_delta(
            amount in 1_u64..2_100_000_000_000_000_u64,
            delta in 1_u64..1_000_000_u64,
            confirmations in 1_u64..1_000_u64,
        ) {
            let expected = FundingExpectation::new(
                outpoint(),
                script(2),
                Amount::from_sat(amount),
                confirmations,
            )?;
            let wrong_amount = amount.saturating_add(delta);
            let observation = FundingObservation {
                outpoint: outpoint(),
                state: FundingState::Unspent(TxOutInfo {
                    best_block: BlockHash::all_zeros(),
                    confirmations,
                    value: Amount::from_sat(wrong_amount),
                    script_pubkey: script(2),
                    coinbase: false,
                }),
            };
            prop_assert_eq!(
                validate_funding_outpoint(&expected, &observation),
                Err(ValidationError::FundingAmountMismatch)
            );
        }

        #[test]
        fn funding_validator_rejects_every_different_outpoint(
            candidate_vout in any::<u32>(),
            amount in 1_u64..2_100_000_000_000_000_u64,
        ) {
            let expected = FundingExpectation::new(outpoint(), script(4), Amount::from_sat(amount), 1)?;
            let different_vout = if candidate_vout == expected.outpoint().vout {
                candidate_vout.wrapping_add(1)
            } else {
                candidate_vout
            };
            let observation = FundingObservation {
                outpoint: OutPoint {
                    txid: expected.outpoint().txid,
                    vout: different_vout,
                },
                state: FundingState::Unspent(TxOutInfo {
                    best_block: BlockHash::all_zeros(),
                    confirmations: 1,
                    value: expected.amount(),
                    script_pubkey: expected.script_pubkey().clone(),
                    coinbase: false,
                }),
            };
            prop_assert_eq!(
                validate_funding_outpoint(&expected, &observation),
                Err(ValidationError::FundingOutpointMismatch)
            );
        }
    }

    #[test]
    fn funding_expectation_rejects_zero_confirmations() {
        assert_eq!(
            FundingExpectation::new(outpoint(), script(3), Amount::from_sat(50_000), 0),
            Err(ValidationError::InvalidFundingExpectation(
                "minimum confirmations must be at least one"
            ))
        );
    }

    #[test]
    fn coinbase_maturity_boundary_is_exact() -> std::result::Result<(), ValidationError> {
        let expected = FundingExpectation::new(outpoint(), script(3), Amount::from_sat(50_000), 1)?;
        let observation = |confirmations| FundingObservation {
            outpoint: outpoint(),
            state: FundingState::Unspent(TxOutInfo {
                best_block: BlockHash::all_zeros(),
                confirmations,
                value: expected.amount(),
                script_pubkey: expected.script_pubkey().clone(),
                coinbase: true,
            }),
        };
        let maturity = u64::from(COINBASE_MATURITY);
        assert_eq!(
            validate_funding_outpoint(&expected, &observation(maturity - 1)),
            Err(ValidationError::FundingConfirmations {
                actual: maturity - 1,
                required: maturity,
            })
        );
        assert_eq!(validate_funding_outpoint(&expected, &observation(maturity)), Ok(()));
        Ok(())
    }

    #[test]
    fn spent_funding_is_rejected() -> std::result::Result<(), ValidationError> {
        let expected = FundingExpectation::new(outpoint(), script(3), Amount::from_sat(50_000), 1)?;
        let observation = FundingObservation {
            outpoint: outpoint(),
            state: FundingState::SpentOrMissing,
        };
        assert_eq!(
            validate_funding_outpoint(&expected, &observation),
            Err(ValidationError::FundingSpentOrMissing)
        );
        Ok(())
    }
}
