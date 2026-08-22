use bitcoin::bip32::Xpriv;
use bitcoin::key::Keypair;
use bitcoin::key::TweakedPublicKey;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, Signature as TaprootSignature, TaprootSpendInfo};
use bitcoin::Txid;
use bitcoin::{
    absolute,
    secp256k1::{All, Secp256k1},
    transaction, Address, Amount, Network, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use bitcoin_utils::constants::{OVERHEAD, SAFETY_INPUT_VBYTES, TAPROOT_OUTPUT_VBYTES};

use bitcoin_utils::errors::ConstructionError;
use bitcoin_utils::types::Utxo;
use bitcoin_utils::utils::{
    generate_bip32_derivation, generate_p2pkh_script_sig_script, generate_p2sh_script_sig_script,
    generate_p2tr_tweaked_address, generate_redeem_script, generate_tap_key_origins,
};

use crate::bitcoin_account::{BitcoinAccount, BitcoinAccountLocal};
use crate::bitcoin_scripts::gen_prepare_taproot;

#[derive(Debug, Clone)]
pub struct PrepareTxInfo {
    pub prev_address: Address,
    pub prev_outputs: Vec<Utxo>,
    pub prev_outputs_tx: Option<Transaction>,
    pub sats_per_vbytes: u64,
    pub fixed_amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxRef {
    txid: Txid,
    vout: usize,
    amount: u64,
}

pub struct TxContext {
    multi_sig_address: Address,
    committee_address: Address,

    network: Network,

    // The prepare tx provides the funds to be transferred in the Thunderbolt layer.
    prepare_tx: Transaction,

    // Prepare tx's first output is locked by the user and the committee.
    // It holds the funds.
    locked_utxo_idx: usize,
    locked_utxo_taproot_spend_info: TaprootSpendInfo,
    locked_utxo_script: ScriptBuf,
    locked_utxo_control_block: ControlBlock,
}

impl TxContext {
    pub fn initialize(
        user: &BitcoinAccountLocal,
        committee: &impl BitcoinAccount,
        network: Network,
        prepare_tx_info: &PrepareTxInfo,
    ) -> crate::Result<Self> {
        let secp = Secp256k1::new();
        let mut tx_ctx = TxContext::new(user.get_x_pubkey().0, committee.get_x_pubkey().0, network);

        let mut prepare_tx = tx_ctx
            .construct_unsigned_prepare(prepare_tx_info)
            .map_err(|error| crate::ThunderboltError::InvalidParameter(error.to_string()))?;

        let signed_prepare_tx = tx_ctx
            .sign_prepare(
                &user.get_pubkey(),
                &prepare_tx_info.prev_address,
                &mut prepare_tx,
                &secp,
                user.get_xpriv()?,
            )
            .map_err(|error| crate::ThunderboltError::InvalidParameter(error.to_string()))?;

        tx_ctx.set_signed_prepare(signed_prepare_tx);

        Ok(tx_ctx)
    }

    pub fn new(x_pubkey_user: XOnlyPublicKey, x_pubkey_comm: XOnlyPublicKey, network: Network) -> Self {
        let (locked_utxo_taproot_spend_info, locked_utxo_script, locked_utxo_control_block) =
            gen_prepare_taproot(&x_pubkey_user, &x_pubkey_comm);

        let locked_utxo_script_pubkey = locked_utxo_taproot_spend_info.output_key();

        let multi_sig_address = generate_p2tr_tweaked_address(network, locked_utxo_script_pubkey);

        let committee_address =
            generate_p2tr_tweaked_address(network, TweakedPublicKey::dangerous_assume_tweaked(x_pubkey_comm));

        let default_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        Self {
            multi_sig_address,
            committee_address,
            network,
            prepare_tx: default_tx,
            locked_utxo_idx: 0,
            locked_utxo_taproot_spend_info,
            locked_utxo_script,
            locked_utxo_control_block,
        }
    }

    pub fn estimate_input_amount(
        &self,
        inputs_count: usize,
        fixed_amount: u64,
        sats_per_vbytes: u64,
    ) -> Result<u64, ConstructionError> {
        let inputs_count =
            u64::try_from(inputs_count).map_err(|_| ConstructionError::ArithmeticOverflow("input count"))?;
        let input_vb = inputs_count
            .checked_mul(SAFETY_INPUT_VBYTES)
            .ok_or(ConstructionError::ArithmeticOverflow("input virtual bytes"))?;
        let total_vb = input_vb
            .checked_add(OVERHEAD)
            .and_then(|value| value.checked_add(TAPROOT_OUTPUT_VBYTES))
            .and_then(|value| value.checked_add(TAPROOT_OUTPUT_VBYTES))
            .ok_or(ConstructionError::ArithmeticOverflow("transaction virtual bytes"))?;
        let fee = total_vb
            .checked_mul(sats_per_vbytes)
            .ok_or(ConstructionError::ArithmeticOverflow("transaction fee"))?;
        fee.checked_add(fixed_amount)
            .ok_or(ConstructionError::ArithmeticOverflow("required input amount"))
    }

    pub fn estimate_output_amount(
        &self,
        outputs_count: usize,
        fixed_amount: u64,
        sats_per_vbytes: u64,
    ) -> Result<u64, ConstructionError> {
        let outputs_count =
            u64::try_from(outputs_count).map_err(|_| ConstructionError::ArithmeticOverflow("output count"))?;
        let output_vb = outputs_count
            .checked_mul(TAPROOT_OUTPUT_VBYTES)
            .ok_or(ConstructionError::ArithmeticOverflow("output virtual bytes"))?;
        let total_vb = SAFETY_INPUT_VBYTES
            .checked_add(OVERHEAD)
            .and_then(|value| value.checked_add(output_vb))
            .ok_or(ConstructionError::ArithmeticOverflow("transaction virtual bytes"))?;
        let fee = total_vb
            .checked_mul(sats_per_vbytes)
            .ok_or(ConstructionError::ArithmeticOverflow("transaction fee"))?;
        fixed_amount
            .checked_sub(fee)
            .ok_or(ConstructionError::InsufficientFunds(None, fee, fixed_amount))
    }

    pub fn prepare_output(&self, fixed_amount: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(fixed_amount),
            script_pubkey: self.multi_sig_address.script_pubkey(),
        }
    }

    pub fn construct_unsigned_prepare(&self, prepare_tx_info: &PrepareTxInfo) -> Result<Psbt, ConstructionError> {
        let PrepareTxInfo {
            prev_address,
            prev_outputs,
            prev_outputs_tx,
            sats_per_vbytes,
            fixed_amount,
        } = prepare_tx_info;
        let input_fee = prev_outputs.iter().try_fold(0u64, |total, utxo| {
            total
                .checked_add(utxo.value.to_sat())
                .ok_or(ConstructionError::ArithmeticOverflow("input amount"))
        })?;
        let required_fee = self.estimate_input_amount(prev_outputs.len(), *fixed_amount, *sats_per_vbytes)?;

        if input_fee < required_fee {
            return Err(ConstructionError::InsufficientFunds(None, required_fee, input_fee));
        }

        let mut input = Vec::new();
        for out in prev_outputs {
            let previous_output = OutPoint {
                txid: out.txid,
                vout: out.vout,
            };
            let txin = TxIn {
                previous_output,
                script_sig: ScriptBuf::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            };
            input.push(txin);
        }

        let output0 = self.prepare_output(*fixed_amount);
        let minimum_lock_value = output0.script_pubkey.minimal_non_dust().to_sat();
        if *fixed_amount < minimum_lock_value {
            return Err(ConstructionError::DustOutput {
                actual: *fixed_amount,
                minimum: minimum_lock_value,
            });
        }
        let change = input_fee - required_fee;
        let change_script = prev_address.script_pubkey();
        let mut output = vec![output0];
        if change >= change_script.minimal_non_dust().to_sat() {
            output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script,
            });
        }

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        match prev_address.address_type() {
            Some(bitcoin::AddressType::P2pkh) => {
                let Some(tx) = prev_outputs_tx.as_ref() else {
                    return Err(ConstructionError::ParseError(
                        None,
                        "prev_outputs_tx should not be None with p2pkh address type".to_string(),
                    ));
                };
                for (i, _) in prev_outputs.iter().enumerate() {
                    psbt.inputs[i].non_witness_utxo = Some(tx.clone());
                }
            }
            _ => {
                for (i, utxo) in prev_outputs.iter().enumerate() {
                    let input_txout = TxOut {
                        value: utxo.value,
                        script_pubkey: prev_address.script_pubkey(),
                    };
                    psbt.inputs[i].witness_utxo = Some(input_txout);
                }
            }
        }

        Ok(psbt)
    }

    pub fn sign_prepare(
        &self,
        prev_pubkey: &PublicKey,
        prev_address: &Address,
        psbt: &mut Psbt,
        secp: &Secp256k1<All>,
        xpriv: &Xpriv,
    ) -> Result<Transaction, ConstructionError> {
        let address_type = prev_address
            .address_type()
            .ok_or_else(|| ConstructionError::ParseError(None, "unknown previous address type".to_string()))?;
        for input in &mut psbt.inputs {
            match address_type {
                bitcoin::AddressType::P2pkh => {
                    input.sighash_type = Some(PsbtSighashType::from_u32(1));
                    input.bip32_derivation = generate_bip32_derivation(secp, xpriv, prev_pubkey);
                }
                bitcoin::AddressType::P2sh => {
                    input.sighash_type = Some(PsbtSighashType::from_u32(1));
                    input.bip32_derivation = generate_bip32_derivation(secp, xpriv, prev_pubkey);
                    let network = self.network;
                    let redeem_script = generate_redeem_script(network, prev_pubkey)?;
                    input.redeem_script = Some(redeem_script);
                }
                bitcoin::AddressType::P2wpkh => {
                    input.sighash_type = Some(PsbtSighashType::from_u32(1));
                    input.bip32_derivation = generate_bip32_derivation(secp, xpriv, prev_pubkey);
                }
                bitcoin::AddressType::P2wsh => {
                    return Err(ConstructionError::ParseError(
                        None,
                        "P2WSH funding inputs are not supported".to_string(),
                    ));
                }
                bitcoin::AddressType::P2tr => {
                    input.sighash_type = Some(PsbtSighashType::from_u32(0));
                    let x_pubkey = XOnlyPublicKey::from(*prev_pubkey);
                    input.tap_key_origins = generate_tap_key_origins(secp, xpriv, &x_pubkey, Vec::new());
                    input.tap_internal_key = Some(x_pubkey);
                }
                _ => {
                    return Err(ConstructionError::ParseError(
                        None,
                        format!("invalid address {:}", prev_address),
                    ))
                }
            }
        }

        psbt.sign(xpriv, secp)
            .map_err(|(_, errors)| ConstructionError::ParseError(None, format!("PSBT signing failed: {errors:?}")))?;
        let mut signed_prepare = psbt.clone().extract_tx()?;

        for (i, input) in psbt.inputs.iter().enumerate() {
            match address_type {
                bitcoin::AddressType::P2pkh => {
                    if let Some(sig) = input.partial_sigs.get(prev_pubkey) {
                        let script_sig = generate_p2pkh_script_sig_script(sig, prev_pubkey);
                        signed_prepare.input[i].script_sig = script_sig;
                    } else {
                        return Err(ConstructionError::ParseError(
                            None,
                            format!("missing signature in partial_sigs for input {}", i),
                        ));
                    }
                }
                bitcoin::AddressType::P2sh => {
                    if let Some(sig) = input.partial_sigs.get(prev_pubkey) {
                        let mut witness = Witness::new();
                        witness.push(sig.to_vec());
                        witness.push(prev_pubkey.to_bytes());
                        signed_prepare.input[i].witness = witness;
                        let script_sig = generate_p2sh_script_sig_script(self.network, prev_pubkey)?;
                        signed_prepare.input[i].script_sig = script_sig;
                    } else {
                        return Err(ConstructionError::ParseError(
                            None,
                            format!("missing signature in partial_sigs for input {}", i),
                        ));
                    }
                }
                bitcoin::AddressType::P2wpkh => {
                    if let Some(sig) = input.partial_sigs.get(prev_pubkey) {
                        let mut witness = Witness::new();
                        witness.push(sig.to_vec());
                        witness.push(prev_pubkey.to_bytes());
                        signed_prepare.input[i].witness = witness;
                    } else {
                        return Err(ConstructionError::ParseError(
                            None,
                            format!("missing signature in partial_sigs for input {}", i),
                        ));
                    }
                }
                bitcoin::AddressType::P2wsh => {
                    return Err(ConstructionError::ParseError(
                        None,
                        "P2WSH funding inputs are not supported".to_string(),
                    ));
                }
                bitcoin::AddressType::P2tr => {
                    if input.tap_key_sig.is_none() {
                        return Err(ConstructionError::ParseError(
                            None,
                            format!("missing tap_key_sig in input {}", i),
                        ));
                    }
                    let mut witness = Witness::new();
                    if let Some(signature) = input.tap_key_sig.as_ref() {
                        witness.push(signature.to_vec());
                    }
                    signed_prepare.input[i].witness = witness;
                }
                _ => {
                    return Err(ConstructionError::ParseError(
                        None,
                        format!("invalid address {:}", prev_address),
                    ))
                }
            }
        }
        Ok(signed_prepare)
    }

    pub fn set_signed_prepare(&mut self, signed_prepare: Transaction) {
        self.prepare_tx = signed_prepare;
    }

    pub fn get_signed_prepare(&self) -> &Transaction {
        &self.prepare_tx
    }

    pub fn locked_address(&self) -> &Address {
        &self.multi_sig_address
    }

    pub fn committee_address(&self) -> &Address {
        &self.committee_address
    }

    pub fn locked_spend_info(&self) -> &TaprootSpendInfo {
        &self.locked_utxo_taproot_spend_info
    }

    pub fn construct_unsigned_redeem(
        &self,
        signed_prepare_txid: Txid,
        fixed_amount: u64,
        outputs: Vec<TxOut>,
    ) -> Result<Psbt, ConstructionError> {
        if outputs.is_empty() {
            return Err(ConstructionError::InvalidOutputCount(None, 1, 0));
        }
        let output_total = outputs.iter().try_fold(0_u64, |total, output| {
            let minimum = output.script_pubkey.minimal_non_dust().to_sat();
            if output.value.to_sat() < minimum {
                return Err(ConstructionError::DustOutput {
                    actual: output.value.to_sat(),
                    minimum,
                });
            }
            total
                .checked_add(output.value.to_sat())
                .ok_or(ConstructionError::ArithmeticOverflow("redeem output amount"))
        })?;
        if output_total > fixed_amount {
            return Err(ConstructionError::InsufficientFunds(None, output_total, fixed_amount));
        }
        let input0 = TxIn {
            previous_output: OutPoint {
                txid: signed_prepare_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        let input = vec![input0];

        let output = outputs;

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        let input_txout0 = TxOut {
            value: Amount::from_sat(fixed_amount),
            script_pubkey: self.multi_sig_address.script_pubkey(),
        };

        psbt.inputs[0].witness_utxo = Some(input_txout0);

        Ok(psbt)
    }

    pub fn sign_redeem_script_path(
        &self,
        fixed_amount: u64,
        psbt: &Psbt,
        secp: &Secp256k1<All>,
        keypair: &Keypair,
    ) -> Result<TaprootSignature, ConstructionError> {
        self.validate_redeem_psbt(psbt, Some(fixed_amount))?;
        let prevout = TxOut {
            value: Amount::from_sat(fixed_amount),
            script_pubkey: self.multi_sig_address.script_pubkey(),
        };
        let leaf_hash = self.locked_utxo_script.tapscript_leaf_hash();
        let sighash = SighashCache::new(&psbt.unsigned_tx).taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::All,
        )?;
        let message = Message::from(sighash);
        Ok(TaprootSignature {
            signature: secp.sign_schnorr(&message, keypair),
            sighash_type: TapSighashType::All,
        })
    }

    pub fn aggregate_redeem(
        &self,
        psbt: &mut Psbt,
        user_signature: TaprootSignature,
        committee_signature: TaprootSignature,
    ) -> Result<Transaction, ConstructionError> {
        self.validate_redeem_psbt(psbt, None)?;
        let mut unsigned_redeem = psbt.clone().extract_tx()?;

        let mut witness = Witness::new();
        witness.push(committee_signature.to_vec());
        witness.push(user_signature.to_vec());
        witness.push(self.locked_utxo_script.clone());
        witness.push(self.locked_utxo_control_block.serialize());
        unsigned_redeem.input[0].witness = witness;
        Ok(unsigned_redeem)
    }

    fn validate_redeem_psbt(&self, psbt: &Psbt, expected_amount: Option<u64>) -> Result<(), ConstructionError> {
        if psbt.unsigned_tx.input.len() != 1 || psbt.inputs.len() != 1 {
            return Err(ConstructionError::InvalidInputCount(
                Some(psbt.unsigned_tx.compute_txid()),
                1,
                psbt.unsigned_tx.input.len(),
            ));
        }
        let locked_output = self.prepare_tx.output.get(self.locked_utxo_idx).ok_or_else(|| {
            ConstructionError::ParseError(
                Some(self.prepare_tx.compute_txid()),
                "prepare transaction does not contain the locked output".to_owned(),
            )
        })?;
        let expected_outpoint = OutPoint {
            txid: self.prepare_tx.compute_txid(),
            vout: u32::try_from(self.locked_utxo_idx).map_err(|_| {
                ConstructionError::ParseError(
                    Some(self.prepare_tx.compute_txid()),
                    "locked output index does not fit a Bitcoin outpoint".to_owned(),
                )
            })?,
        };
        if psbt.unsigned_tx.input[0].previous_output != expected_outpoint {
            return Err(ConstructionError::ParseError(
                Some(psbt.unsigned_tx.compute_txid()),
                "redeem transaction spends a different outpoint".to_owned(),
            ));
        }
        let witness_utxo = psbt.inputs[0].witness_utxo.as_ref().ok_or_else(|| {
            ConstructionError::ParseError(
                Some(psbt.unsigned_tx.compute_txid()),
                "redeem PSBT is missing witness_utxo".to_owned(),
            )
        })?;
        if witness_utxo != locked_output || expected_amount.is_some_and(|amount| amount != witness_utxo.value.to_sat())
        {
            return Err(ConstructionError::ParseError(
                Some(psbt.unsigned_tx.compute_txid()),
                "redeem PSBT locked output does not match the channel".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn default_redeem_outputs(
        &self,
        fixed_amount: u64,
        recipient: Address,
        sats_per_vbytes: u64,
    ) -> Result<Vec<TxOut>, ConstructionError> {
        let value = self.estimate_output_amount(1, fixed_amount, sats_per_vbytes)?;
        let script_pubkey = recipient.script_pubkey();
        let minimum = script_pubkey.minimal_non_dust().to_sat();
        if value < minimum {
            return Err(ConstructionError::DustOutput { actual: value, minimum });
        }
        Ok(vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }])
    }

    pub fn as_tx_ref(&self) -> crate::Result<TxRef> {
        let output = self.prepare_tx.output.get(self.locked_utxo_idx).ok_or_else(|| {
            crate::ThunderboltError::InvalidStateTransition(
                "prepare transaction does not contain the locked output".to_string(),
            )
        })?;
        Ok(TxRef {
            txid: self.prepare_tx.compute_txid(),
            vout: self.locked_utxo_idx,
            amount: output.value.to_sat(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    #[test]
    fn malformed_redeem_psbt_is_rejected_without_indexing_inputs() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1_u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public_key, _) = keypair.x_only_public_key();
        let context = TxContext::new(public_key, public_key, Network::Regtest);
        let transaction = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let psbt = Psbt::from_unsigned_tx(transaction).unwrap();

        assert!(matches!(
            context.validate_redeem_psbt(&psbt, None),
            Err(ConstructionError::InvalidInputCount(_, 1, 0))
        ));
    }
}
