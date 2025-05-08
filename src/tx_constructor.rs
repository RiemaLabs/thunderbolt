use std::ops::Add;

use bitcoin::bip32::Xpriv;
use bitcoin::key::TweakedPublicKey;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    absolute,
    secp256k1::{All, Message, Secp256k1},
    transaction, Address, Amount, Network, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use bitcoin::{TapSighash, Txid};
use bitcoin_utils::constants::{DUST_SATS, OVERHEAD, SAFETY_INPUT_VBYTES, TAPROOT_OUTPUT_VBYTES};

use bitcoin_utils::errors::ConstructionError;
use bitcoin_utils::types::Utxo;
use bitcoin_utils::utils::{
    generate_bip32_derivation, generate_p2pkh_script_sig_script, generate_p2sh_script_sig_script,
    generate_p2tr_address, generate_p2tr_tweaked_address, generate_redeem_script,
    generate_tap_key_origins,
};
use secp::{MaybePoint, MaybeScalar, Point, Scalar};
use sha2::{Digest, Sha256};

struct BitcoinTxConstructor {
    // P_a.x
    x_pubkey_user: XOnlyPublicKey,

    // P_a
    p_pubkey_user: Point,

    // P_c.x
    x_pubkey_comm: XOnlyPublicKey,

    // P_c
    p_pubkey_comm: Point,

    // P_a.x + P_c.x
    x_pubkey: TweakedPublicKey,

    // P_a + P_c
    p_pubkey: Point,

    multi_sig_address: Address,
    committee_address: Address,

    p_pub_nonce_user: Point,
    p_pub_nonce_comm: Point,
    p_pub_nonce: Point,

    network: Network,
}

impl BitcoinTxConstructor {
    pub fn new(
        x_pubkey_user: XOnlyPublicKey,
        x_pubkey_comm: XOnlyPublicKey,
        x_pub_nonce_user: XOnlyPublicKey,
        x_pub_nonce_comm: XOnlyPublicKey,
        network: Network,
    ) -> Self {
        let x_pubkey_bytes = x_pubkey_user.serialize();
        let p_pubkey_user = Point::lift_x(&x_pubkey_bytes).unwrap();

        let x_pubkey_bytes = x_pubkey_comm.serialize();
        let p_pubkey_comm = Point::lift_x(&x_pubkey_bytes).unwrap();

        let x_pubkey_bytes = x_pub_nonce_user.serialize();
        let p_pub_nonce_user = Point::lift_x(&x_pubkey_bytes).unwrap();

        let x_pubkey_bytes = x_pub_nonce_comm.serialize();
        let p_pub_nonce_comm = Point::lift_x(&x_pubkey_bytes).unwrap();

        let maybe_p_pubkey = p_pubkey_user.add(p_pubkey_comm);
        let (x_pubkey, p_pubkey) = match maybe_p_pubkey {
            MaybePoint::Valid(p_pubkey) => {
                let x_pubkey_bytes = p_pubkey.serialize_xonly();
                (
                    TweakedPublicKey::dangerous_assume_tweaked(
                        XOnlyPublicKey::from_slice(&x_pubkey_bytes).unwrap(),
                    ),
                    p_pubkey,
                )
            }
            MaybePoint::Infinity => {
                panic!("Failed to verify p_pubkey");
            }
        };

        let maybe_p_pub_nonce = p_pub_nonce_user.add(p_pub_nonce_comm);
        let (_, p_pub_nonce) = match maybe_p_pub_nonce {
            MaybePoint::Valid(p_pub_nonce) => {
                let x_pub_nonce_bytes = p_pub_nonce.serialize_xonly();
                (
                    XOnlyPublicKey::from_slice(&x_pub_nonce_bytes).unwrap(),
                    p_pub_nonce,
                )
            }
            MaybePoint::Infinity => {
                panic!("Failed to verify p_pub_nonce");
            }
        };

        let multi_sig_address = generate_p2tr_tweaked_address(network, x_pubkey);

        let committee_address = generate_p2tr_address(network, &x_pubkey_comm);

        Self {
            x_pubkey_user,
            p_pubkey_user,
            x_pubkey_comm,
            p_pubkey_comm,
            x_pubkey,
            p_pubkey,
            p_pub_nonce_user,
            p_pub_nonce_comm,
            p_pub_nonce,
            multi_sig_address,
            committee_address,
            network,
        }
    }

    pub fn estimate_fee(
        &self,
        inputs_count: usize,
        fixed_amount: u64,
        sats_per_vbytes: u64,
    ) -> Result<u64, ConstructionError> {
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
        Ok(fee + out0_sats + out1_sats + out2_sats)
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
        let input_fee = prev_outputs
            .iter()
            .map(|u| u.value)
            .sum::<Amount>()
            .to_sat();
        let required_fee = self.estimate_fee(prev_outputs.len(), fixed_amount, sats_per_vbytes)?;

        if input_fee < required_fee {
            return Err(ConstructionError::InsufficientFunds(
                None,
                required_fee,
                input_fee,
            ));
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
                        input.bip32_derivation =
                            generate_bip32_derivation(secp, xpriv, prev_pubkey);
                    }
                    bitcoin::AddressType::P2sh => {
                        input.sighash_type = Some(PsbtSighashType::from_u32(1));
                        input.bip32_derivation =
                            generate_bip32_derivation(secp, xpriv, prev_pubkey);
                        let network = self.network;
                        let redeem_script = generate_redeem_script(network, prev_pubkey)?;
                        input.redeem_script = Some(redeem_script);
                    }
                    bitcoin::AddressType::P2wpkh => {
                        input.sighash_type = Some(PsbtSighashType::from_u32(1));
                        input.bip32_derivation =
                            generate_bip32_derivation(secp, xpriv, prev_pubkey);
                    }
                    bitcoin::AddressType::P2wsh => todo!(),
                    bitcoin::AddressType::P2tr => {
                        input.sighash_type = Some(PsbtSighashType::from_u32(0));
                        let x_pubkey = XOnlyPublicKey::from(prev_pubkey.clone());
                        input.tap_key_origins =
                            generate_tap_key_origins(secp, xpriv, &x_pubkey, Vec::new());
                        input.tap_internal_key = Some(x_pubkey);
                    }
                    _ => Err(ConstructionError::ParseError(
                        None,
                        format!("invalid address {:}", prev_address),
                    ))?,
                },
                None => Err(ConstructionError::ParseError(
                    None,
                    "empty address".to_string(),
                ))?,
            }
        }

        _ = psbt.sign(xpriv, &secp).unwrap();
        let mut signed_inscribe = psbt.clone().extract_tx().unwrap();

        for (i, input) in psbt.inputs.iter().enumerate() {
            match prev_address.address_type().unwrap() {
                bitcoin::AddressType::P2pkh => {
                    if let Some(sig) = input.partial_sigs.get(&prev_pubkey) {
                        let script_sig = generate_p2pkh_script_sig_script(sig, prev_pubkey);
                        signed_inscribe.input[i].script_sig = script_sig;
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
                        signed_inscribe.input[i].witness = witness;
                        let script_sig =
                            generate_p2sh_script_sig_script(self.network, prev_pubkey)?;
                        signed_inscribe.input[i].script_sig = script_sig;
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
                        signed_inscribe.input[i].witness = witness;
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
                    signed_inscribe.input[i].witness = witness;
                }
                _ => Err(ConstructionError::ParseError(
                    None,
                    format!("invalid address {:}", prev_address),
                ))?,
            }
        }
        Ok(signed_inscribe)
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

    pub fn extract_message(
        &self,
        redeem_psbt: &Psbt,
    ) -> Result<(Message, TapSighash), ConstructionError> {
        // TODO: Add the verification part.

        let tx = redeem_psbt.clone().extract_tx().unwrap();
        let mut cache = SighashCache::new(&tx);

        let sighash_type = bitcoin::TapSighashType::None;
        let prevouts = &[
            redeem_psbt.inputs[0].witness_utxo.as_ref().unwrap(),
            redeem_psbt.inputs[1].witness_utxo.as_ref().unwrap(),
        ];

        let prevouts = Prevouts::All(prevouts);

        let tap_sighash = cache.taproot_key_spend_signature_hash(0, &prevouts, sighash_type)?;
        let msg = Message::from(tap_sighash);
        Ok((msg, tap_sighash))
    }

    pub fn compute_challenge(&self, message: &Message) -> Result<Scalar, ConstructionError> {
        let hash: [u8; 32] = Sha256::new()
            .chain_update(&self.p_pub_nonce.serialize())
            .chain_update(&self.p_pubkey.serialize())
            .chain_update(message.as_ref())
            .finalize()
            .into();
        let res = MaybeScalar::reduce_from(&hash);
        match res {
            MaybeScalar::Valid(scalar) => Ok(scalar),
            MaybeScalar::Zero => Err(ConstructionError::ParseError(
                None,
                "invalid scalar".to_string(),
            )),
        }
    }

    pub fn sign(
        &self,
        redeem_psbt: &mut Psbt,
        nonce: Scalar,
        secret_key: Scalar,
    ) -> Result<Scalar, ConstructionError> {
        let (msg, _) = self.extract_message(redeem_psbt)?;
        let challenge = self.compute_challenge(&msg)?;
        let signature = nonce + secret_key * challenge;
        match signature {
            MaybeScalar::Valid(signature) => Ok(signature),
            MaybeScalar::Zero => Err(ConstructionError::ParseError(
                None,
                "invalid signature".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}

