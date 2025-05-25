use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::AddressType;
use bitcoin::{
    bip32::{DerivationPath, KeySource, Xpriv},
    ecdsa::Signature as ECDSASignature,
    key::{Secp256k1, TweakedPublicKey},
    opcodes::all::OP_CHECKSIG,
    script::{Builder, PushBytesBuf},
    secp256k1::All,
    secp256k1::PublicKey as SecpPublicKey,
    Address, CompressedPublicKey, KnownHrp, Network, PublicKey, ScriptBuf, TapLeafHash, XOnlyPublicKey,
};

use crate::errors::AddressError;

pub fn is_valid_btc_address_str(address: &str, network: Network) -> bool {
    let res = Address::from_str(address);
    match res {
        Ok(addr) => addr.is_valid_for_network(network),
        Err(_) => false,
    }
}

pub fn is_valid_p2tr_address_str(address: &str, network: Network) -> bool {
    if address.is_empty() {
        return false;
    }
    let res = Address::from_str(address);
    match res {
        Ok(addr) => {
            let addr = addr.require_network(network);
            if addr.is_err() {
                false
            } else {
                let addr = addr.unwrap();
                match addr.address_type() {
                    Some(AddressType::P2tr) => true,
                    _ => false,
                }
            }
        }
        Err(_) => false,
    }
}

pub fn parse_btc_address(address: &str, network: Network) -> Result<Address, AddressError> {
    let res = Address::from_str(address)?;
    let verified_addr = res.require_network(network)?;
    Ok(verified_addr)
}

fn generate_p2pk_script(public_key: &PublicKey) -> ScriptBuf {
    let script: ScriptBuf = Builder::new()
        .push_key(public_key)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    script
}

pub fn generate_p2wpkh_address(network: Network, public_key: &PublicKey) -> Result<Address, AddressError> {
    let address = Address::p2wpkh(&CompressedPublicKey::try_from(*public_key)?, network);
    Ok(address)
}

pub fn generate_p2sh_address(network: Network, public_key: &PublicKey) -> Result<Address, AddressError> {
    let address = Address::p2sh(&generate_p2wpkh_address(network, public_key)?.script_pubkey(), network)?;
    Ok(address)
}

pub fn generate_p2pkh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2pkh(
        &CompressedPublicKey::try_from(*public_key).expect("Could not compress public key"),
        network,
    )
}

pub fn generate_p2wsh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wsh(&generate_p2pk_script(public_key), network)
}

pub fn generate_p2tr_address(network: Network, public_key: &XOnlyPublicKey) -> Address {
    let secp = Secp256k1::new();
    let hrp = match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Testnet => KnownHrp::Testnets,
        Network::Regtest => KnownHrp::Regtest,
        Network::Signet => KnownHrp::Testnets,
        Network::Testnet4 => KnownHrp::Testnets,
        _ => unimplemented!("Network not supported"),
    };
    Address::p2tr(&secp, public_key.clone(), None, hrp)
}

pub fn generate_p2tr_tweaked_address(network: Network, tweaked_key: TweakedPublicKey) -> Address {
    let hrp = match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Testnet => KnownHrp::Testnets,
        Network::Regtest => KnownHrp::Regtest,
        Network::Signet => KnownHrp::Testnets,
        Network::Testnet4 => KnownHrp::Testnets,
        _ => unimplemented!("Network not supported"),
    };
    Address::p2tr_tweaked(tweaked_key, hrp)
}

pub fn generate_redeem_script(network: Network, public_key: &PublicKey) -> Result<ScriptBuf, AddressError> {
    let address_p2wpkh = generate_p2wpkh_address(network, public_key)?;
    let redeem_script = address_p2wpkh.script_pubkey();
    Ok(redeem_script)
}

pub fn generate_p2pkh_script_sig_script(sig: &ECDSASignature, public_key: &PublicKey) -> ScriptBuf {
    let script: ScriptBuf = Builder::new()
        .push_slice(sig.serialize())
        .push_key(public_key)
        .into_script();
    script
}

pub fn generate_p2sh_script_sig_script(network: Network, public_key: &PublicKey) -> Result<ScriptBuf, AddressError> {
    let redeem_script = generate_redeem_script(network, public_key)?;
    let redeem_script_bytes: Vec<u8> = redeem_script.to_bytes();
    let bytes: PushBytesBuf = PushBytesBuf::try_from(redeem_script_bytes).expect("Could not convert to PushBytesBuf");
    let script: ScriptBuf = Builder::new().push_slice(bytes).into_script();
    Ok(script)
}

pub fn generate_tap_key_origins(
    secp: &Secp256k1<All>,
    d_xpriv: &Xpriv,
    x_pubkey: &XOnlyPublicKey,
    leaf_hashes: Vec<TapLeafHash>,
) -> BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)> {
    let mut tap_key_origins = BTreeMap::new();
    let fingerprint = d_xpriv.fingerprint(secp);
    tap_key_origins.insert(x_pubkey.clone(), (leaf_hashes, (fingerprint, DerivationPath::master())));
    tap_key_origins
}

pub fn generate_bip32_derivation(
    secp: &Secp256k1<All>,
    d_xpriv: &Xpriv,
    pubkey: &PublicKey,
) -> BTreeMap<SecpPublicKey, KeySource> {
    let mut bip32_derivation = BTreeMap::new();
    let secp_pubkey = &pubkey.inner;
    let fingerprint = d_xpriv.fingerprint(secp);
    bip32_derivation.insert(secp_pubkey.clone(), (fingerprint, DerivationPath::master()));
    bip32_derivation
}
