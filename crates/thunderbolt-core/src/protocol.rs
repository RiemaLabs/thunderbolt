use std::collections::BTreeMap;

use bitcoin::bip32::Xpriv;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::key::{Keypair, TweakedPublicKey};
use bitcoin::psbt::PsbtSighashType;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootSpendInfo};
use bitcoin::{
    absolute,
    secp256k1::{All, Message, Secp256k1},
    transaction, Address, Amount, Network, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use bitcoin::{TapLeafHash, Txid};
use bitcoin_utils::constants::{DUST_SATS, OVERHEAD, SAFETY_INPUT_VBYTES, TAPROOT_OUTPUT_VBYTES};

use bitcoin_utils::errors::ConstructionError;
use bitcoin_utils::types::Utxo;
use bitcoin_utils::utils::{
    generate_bip32_derivation, generate_p2pkh_script_sig_script, generate_p2sh_script_sig_script,
    generate_p2tr_tweaked_address, generate_redeem_script, generate_tap_key_origins,
};

use crate::scripts::{gen_prepare_taproot};

pub struct TxContext {
    multi_sig_address: Address,
    committee_address: Address,

    network: Network,

    // The first output is controlled by the user and the committee.
    // It holds the funds.
    funding_utxo_idx: usize,
    funding_utxo_taproot_spend_info: TaprootSpendInfo,
    funding_utxo_script: ScriptBuf,
    funding_utxo_control_block: ControlBlock,

    // The second output is controlled by the committee.
    // It is used to lock the outputs to prevent front-run of the SIGHASH_NONE signature.
    dummy_utxo_idx: usize,
}

impl TxContext {
    pub fn new(x_pubkey_user: XOnlyPublicKey, x_pubkey_comm: XOnlyPublicKey, network: Network) -> Self {
        let (funding_utxo_taproot_spend_info, funding_utxo_script, funding_utxo_control_block) =
            gen_prepare_taproot(&x_pubkey_user, &x_pubkey_comm);

        let funding_utxo_script_pubkey = funding_utxo_taproot_spend_info.output_key();

        let multi_sig_address = generate_p2tr_tweaked_address(network, funding_utxo_script_pubkey);

        let committee_address =
            generate_p2tr_tweaked_address(network, TweakedPublicKey::dangerous_assume_tweaked(x_pubkey_comm));

        Self {
            multi_sig_address,
            committee_address,
            network,
            funding_utxo_idx: 0,
            funding_utxo_taproot_spend_info,
            funding_utxo_script,
            funding_utxo_control_block,
            dummy_utxo_idx: 1,
        }
    }

    pub fn estimate_input_amount(&self, inputs_count: usize, fixed_amount: u64, sats_per_vbytes: u64) -> u64 {
        let input_vb = (inputs_count as u64) * SAFETY_INPUT_VBYTES;
        let overhead = OVERHEAD;
        let out0_vb = TAPROOT_OUTPUT_VBYTES;
        let out1_vb = TAPROOT_OUTPUT_VBYTES;
        let out2_vb = TAPROOT_OUTPUT_VBYTES;
        let total_vb = input_vb + overhead + out0_vb + out1_vb + out2_vb;
        let fee = total_vb * sats_per_vbytes;
        let out0_sats = fixed_amount;
        let out1_sats = DUST_SATS;
        // The output to collect the remaining fee.
        let out2_sats = 0;
        fee + out0_sats + out1_sats + out2_sats
    }

    pub fn estimate_output_amount(&self, outputs_count: usize, fixed_amount: u64, sats_per_vbytes: u64) -> u64 {
        let inputs_count = 2;
        let input_vb = (inputs_count as u64) * SAFETY_INPUT_VBYTES;
        let overhead = OVERHEAD;
        let output_vb = (outputs_count as u64) * TAPROOT_OUTPUT_VBYTES;
        let total_vb = input_vb + overhead + output_vb;
        let fee = total_vb * sats_per_vbytes;
        fixed_amount - fee
    }

    pub fn first_prepare_output(&self, fixed_amount: u64) -> TxOut {
        let txout = TxOut {
            value: Amount::from_sat(fixed_amount),
            script_pubkey: self.multi_sig_address.script_pubkey(),
        };
        txout
    }

    pub fn second_prepare_output(&self) -> TxOut {
        let txout = TxOut {
            value: Amount::from_sat(DUST_SATS),
            script_pubkey: self.committee_address.script_pubkey(),
        };
        txout
    }

    pub fn construct_unsigned_prepare(
        &self,
        prev_address: &Address,
        prev_outputs: Vec<Utxo>,
        prev_outputs_tx: Option<Transaction>,
        sats_per_vbytes: u64,
        fixed_amount: u64,
    ) -> Result<Psbt, ConstructionError> {
        let input_fee = prev_outputs.iter().map(|u| u.value).sum::<Amount>().to_sat();
        let required_fee = self.estimate_input_amount(prev_outputs.len(), fixed_amount, sats_per_vbytes);

        if input_fee < required_fee {
            return Err(ConstructionError::InsufficientFunds(None, required_fee, input_fee));
        }

        let mut input = Vec::new();
        for out in &prev_outputs {
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

        let output0 = self.first_prepare_output(fixed_amount);
        let output1 = self.second_prepare_output();
        let remaining_fee = input_fee - required_fee;
        let output2 = TxOut {
            value: Amount::from_sat(remaining_fee),
            script_pubkey: prev_address.script_pubkey(),
        };

        let output = vec![output0, output1, output2];

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
                let tx = prev_outputs_tx.unwrap();
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
        let input1 = TxIn {
            previous_output: OutPoint {
                txid: signed_prepare_txid,
                vout: 1,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let input = vec![input0, input1];

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

        let input_txout1 = TxOut {
            value: Amount::from_sat(DUST_SATS),
            script_pubkey: self.committee_address.script_pubkey(),
        };
        psbt.inputs[0].witness_utxo = Some(input_txout0);
        psbt.inputs[1].witness_utxo = Some(input_txout1);

        Ok(psbt)
    }

    pub fn sign_redeem_funding_utxo(
        &self,
        fixed_amount: u64,
        psbt: &mut Psbt,
        secp: &Secp256k1<All>,
        keypair: &Keypair,
    ) -> Result<Signature, ConstructionError> {
        // TODO: Add a verification function for the committee to confirm.

        let input_utxo = self.first_prepare_output(fixed_amount);
        let unlock_leaf_hash = TapLeafHash::from_script(&self.funding_utxo_script, LeafVersion::TapScript);
        let unlock_script = self.funding_utxo_script.clone();
        let unlock_control_block = self.funding_utxo_control_block.clone();

        psbt.inputs[self.funding_utxo_idx].witness_utxo = Some(input_utxo);
        psbt.inputs[self.funding_utxo_idx].tap_scripts =
            BTreeMap::from([(unlock_control_block, (unlock_script, LeafVersion::TapScript))]);

        let tx = psbt.clone().extract_tx().unwrap();
        let mut cache = SighashCache::new(&tx);

        let prevouts = &[
            psbt.inputs[self.funding_utxo_idx].witness_utxo.as_ref().unwrap(),
            psbt.inputs[self.dummy_utxo_idx].witness_utxo.as_ref().unwrap(),
        ];

        let prevouts = Prevouts::All(prevouts);
        let sighash_type = bitcoin::TapSighashType::None;

        let tap_sighash = cache.taproot_script_spend_signature_hash(
            self.funding_utxo_idx,
            &prevouts,
            unlock_leaf_hash,
            sighash_type,
        )?;
        let msg = Message::from(tap_sighash);
        Ok(secp.sign_schnorr(&msg, keypair))
    }

    pub fn sign_redeem_dummy_utxo(
        &self,
        psbt: &mut Psbt,
        secp: &Secp256k1<All>,
        keypair: &Keypair,
    ) -> Result<Transaction, ConstructionError> {
        // TODO: Add the verification part. The committee shall verify the outputs provided by the user.
        // The dummy UTXO in the whitepaper shall be signed by the committee.
        let mut tx = psbt.clone().extract_tx().unwrap();
        let mut cache = SighashCache::new(&tx);

        let prevouts = &[
            psbt.inputs[self.funding_utxo_idx].witness_utxo.as_ref().unwrap(),
            psbt.inputs[self.dummy_utxo_idx].witness_utxo.as_ref().unwrap(),
        ];

        let prevouts = Prevouts::All(prevouts);
        let sighash_type = bitcoin::TapSighashType::Default;

        let tap_sighash = cache.taproot_key_spend_signature_hash(self.dummy_utxo_idx, &prevouts, sighash_type)?;
        let msg = Message::from(tap_sighash);
        let sig = secp.sign_schnorr(&msg, keypair);
        let mut witness = Witness::new();
        witness.push(sig.serialize());
        tx.input[self.dummy_utxo_idx].witness = witness;
        Ok(tx)
    }

    pub fn aggregate_redeem(
        &self,
        mut signed_redeem: Transaction,
        user_signature: Signature,
        committee_signature: Signature,
    ) -> Result<Transaction, ConstructionError> {
        let mut u_sig = Vec::with_capacity(SCHNORR_SIGNATURE_SIZE + 1);
        u_sig.extend_from_slice(&user_signature.serialize());
        u_sig.push(bitcoin::TapSighashType::None as u8);

        let mut c_sig = Vec::with_capacity(SCHNORR_SIGNATURE_SIZE + 1);
        c_sig.extend_from_slice(&committee_signature.serialize());
        c_sig.push(bitcoin::TapSighashType::None as u8);

        let mut witness = Witness::new();
        witness.push(c_sig);
        witness.push(u_sig);
        witness.push(self.funding_utxo_script.clone());
        witness.push(self.funding_utxo_control_block.serialize());
        signed_redeem.input[0].witness = witness;
        Ok(signed_redeem)
    }

    pub fn default_redeem_outputs(&self, fixed_amount: u64, recipient: Address, sats_per_vbytes: u64) -> Vec<TxOut> {
        vec![TxOut {
            value: Amount::from_sat(self.estimate_output_amount(1, fixed_amount, sats_per_vbytes)),
            script_pubkey: recipient.script_pubkey(),
        }]
    }
}
