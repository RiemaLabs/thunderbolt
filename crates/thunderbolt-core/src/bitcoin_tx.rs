use bitcoin::bip32::Xpriv;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::key::TweakedPublicKey;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::taproot::{ControlBlock, TaprootSpendInfo};
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
    ) -> Self {
        let secp = Secp256k1::new();
        let mut tx_ctx = TxContext::new(user.get_x_pubkey().0, committee.get_x_pubkey().0, network);

        let mut prepare_tx = tx_ctx.construct_unsigned_prepare(&prepare_tx_info).unwrap();

        let signed_prepare_tx = tx_ctx
            .sign_prepare(
                &user.get_pubkey(),
                &prepare_tx_info.prev_address,
                &mut prepare_tx,
                &secp,
                &user.get_xpriv(),
            )
            .unwrap();

        tx_ctx.set_signed_prepare(signed_prepare_tx);

        tx_ctx
    }

    fn new(x_pubkey_user: XOnlyPublicKey, x_pubkey_comm: XOnlyPublicKey, network: Network) -> Self {
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

    pub fn estimate_input_amount(&self, inputs_count: usize, fixed_amount: u64, sats_per_vbytes: u64) -> u64 {
        let input_vb = (inputs_count as u64) * SAFETY_INPUT_VBYTES;
        let overhead = OVERHEAD;
        let out0_vb = TAPROOT_OUTPUT_VBYTES;
        let out1_vb = TAPROOT_OUTPUT_VBYTES;
        let total_vb = input_vb + overhead + out0_vb + out1_vb;
        let fee = total_vb * sats_per_vbytes;
        let out0_sats = fixed_amount;
        // The output to collect the remaining fee.
        let out1_sats = 0;
        fee + out0_sats + out1_sats
    }

    pub fn estimate_output_amount(&self, outputs_count: usize, fixed_amount: u64, sats_per_vbytes: u64) -> u64 {
        let inputs_count = 1;
        let input_vb = (inputs_count as u64) * SAFETY_INPUT_VBYTES;
        let overhead = OVERHEAD;
        let output_vb = (outputs_count as u64) * TAPROOT_OUTPUT_VBYTES;
        let total_vb = input_vb + overhead + output_vb;
        let fee = total_vb * sats_per_vbytes;
        fixed_amount - fee
    }

    pub fn prepare_output(&self, fixed_amount: u64) -> TxOut {
        let txout = TxOut {
            value: Amount::from_sat(fixed_amount),
            script_pubkey: self.multi_sig_address.script_pubkey(),
        };
        txout
    }

    pub fn construct_unsigned_prepare(&self, prepare_tx_info: &PrepareTxInfo) -> Result<Psbt, ConstructionError> {
        let PrepareTxInfo {
            prev_address,
            prev_outputs,
            prev_outputs_tx,
            sats_per_vbytes,
            fixed_amount,
        } = prepare_tx_info;
        let input_fee = prev_outputs.iter().map(|u| u.value).sum::<Amount>().to_sat();
        let required_fee =
            self.estimate_input_amount(prev_outputs.len(), fixed_amount.clone(), sats_per_vbytes.clone());

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
                sequence: Sequence::MAX,
                witness: Witness::default(),
            };
            input.push(txin);
        }

        let output0 = self.prepare_output(fixed_amount.clone());
        let remaining_fee = input_fee - required_fee;
        // send back the remaining fee to the user.
        let output1 = TxOut {
            value: Amount::from_sat(remaining_fee),
            script_pubkey: prev_address.script_pubkey(),
        };

        let output = vec![output0, output1];

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        match prev_address.address_type() {
            Some(bitcoin::AddressType::P2pkh) => {
                if prev_outputs_tx.is_none() {
                    return Err(ConstructionError::ParseError(
                        None,
                        "prev_outputs_tx should not be None with p2pkh address type".to_string(),
                    ))?;
                }
                let tx = prev_outputs_tx.as_ref().unwrap();
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
        for input in &mut psbt.inputs {
            match prev_address.address_type() {
                Some(addr_type) => match addr_type {
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
                    bitcoin::AddressType::P2wsh => todo!(),
                    bitcoin::AddressType::P2tr => {
                        input.sighash_type = Some(PsbtSighashType::from_u32(0));
                        let x_pubkey = XOnlyPublicKey::from(prev_pubkey.clone());
                        input.tap_key_origins = generate_tap_key_origins(secp, xpriv, &x_pubkey, Vec::new());
                        input.tap_internal_key = Some(x_pubkey);
                    }
                    _ => Err(ConstructionError::ParseError(
                        None,
                        format!("invalid address {:}", prev_address),
                    ))?,
                },
                None => Err(ConstructionError::ParseError(None, "empty address".to_string()))?,
            }
        }

        _ = psbt.sign(xpriv, &secp).unwrap();
        let mut signed_prepare = psbt.clone().extract_tx().unwrap();

        for (i, input) in psbt.inputs.iter().enumerate() {
            match prev_address.address_type().unwrap() {
                bitcoin::AddressType::P2pkh => {
                    if let Some(sig) = input.partial_sigs.get(&prev_pubkey) {
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
                    if let Some(sig) = input.partial_sigs.get(&prev_pubkey) {
                        let mut witness = Witness::new();
                        witness.push(sig.to_vec());
                        witness.push(prev_pubkey.to_bytes().to_vec());
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
                    if let Some(sig) = input.partial_sigs.get(&prev_pubkey) {
                        let mut witness = Witness::new();
                        witness.push(sig.to_vec());
                        witness.push(prev_pubkey.to_bytes().to_vec());
                        signed_prepare.input[i].witness = witness;
                    } else {
                        return Err(ConstructionError::ParseError(
                            None,
                            format!("missing signature in partial_sigs for input {}", i),
                        ));
                    }
                }
                bitcoin::AddressType::P2wsh => todo!(),
                bitcoin::AddressType::P2tr => {
                    if input.tap_key_sig.is_none() {
                        return Err(ConstructionError::ParseError(
                            None,
                            format!("missing tap_key_sig in input {}", i),
                        ));
                    }
                    let mut witness = Witness::new();
                    witness.push(input.tap_key_sig.unwrap().to_vec());
                    signed_prepare.input[i].witness = witness;
                }
                _ => Err(ConstructionError::ParseError(
                    None,
                    format!("invalid address {:}", prev_address),
                ))?,
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

    pub fn construct_unsigned_redeem(
        &self,
        signed_prepare_txid: Txid,
        fixed_amount: u64,
        outputs: Vec<TxOut>,
    ) -> Result<Psbt, ConstructionError> {
        let input0 = TxIn {
            previous_output: OutPoint {
                txid: signed_prepare_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
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

    pub fn aggregate_redeem(
        &self,
        psbt: &mut Psbt,
        user_signature: Signature,
        committee_signature: Signature,
    ) -> Result<Transaction, ConstructionError> {
        let mut unsigned_redeem = psbt.clone().extract_tx().unwrap();
        let mut u_sig = Vec::with_capacity(SCHNORR_SIGNATURE_SIZE);
        u_sig.extend_from_slice(&user_signature.serialize());

        let mut c_sig = Vec::with_capacity(SCHNORR_SIGNATURE_SIZE);
        c_sig.extend_from_slice(&committee_signature.serialize());

        let mut witness = Witness::new();
        witness.push(c_sig);
        witness.push(u_sig);
        witness.push(self.locked_utxo_script.clone());
        witness.push(self.locked_utxo_control_block.serialize());
        unsigned_redeem.input[0].witness = witness;
        Ok(unsigned_redeem)
    }

    pub fn default_redeem_outputs(&self, fixed_amount: u64, recipient: Address, sats_per_vbytes: u64) -> Vec<TxOut> {
        vec![TxOut {
            value: Amount::from_sat(self.estimate_output_amount(1, fixed_amount, sats_per_vbytes)),
            script_pubkey: recipient.script_pubkey(),
        }]
    }

    pub fn as_tx_ref(&self) -> TxRef {
        TxRef {
            txid: self.prepare_tx.compute_txid(),
            vout: self.locked_utxo_idx,
            amount: self.prepare_tx.output[self.locked_utxo_idx].value.to_sat(),
        }
    }
}
