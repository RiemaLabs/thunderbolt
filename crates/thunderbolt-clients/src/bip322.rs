use anyhow::Result;
use bip322::sign_simple;
use bitcoin_utils::bitcoin::consensus::Encodable;
use bitcoin_utils::bitcoin::{Address, PrivateKey};

pub fn bip322_sign(address: &Address, message: &[u8], private_key: PrivateKey) -> Result<Vec<u8>> {
    let witness = sign_simple(address, message, private_key)?;

    let mut buffer = Vec::new();

    witness.consensus_encode(&mut buffer)?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use bitcoin_utils::account::AccountInfo;
    use bitcoin_utils::bitcoin::hex::DisplayHex;
    use bitcoin_utils::bitcoin::Network;

    use super::*;

    #[test]
    fn test_bip322_sign() {
        let deployer_secret_seed = "25f5ff288b007263c1ff7e05945a9000c6fb66d1a5e4eaa097e077d5238f7755";
        let account = AccountInfo::new(Network::Bitcoin, deployer_secret_seed);
        let secret_key = account.get_keypair().secret_key();
        println!("Secret key: {}", secret_key.secret_bytes().to_lower_hex_string());
        let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
        let deployer_address = account.p2tr_address(Network::Bitcoin);

        let signature = bip322_sign(&deployer_address, &[], private_key);

        assert!(signature.is_ok());

        let signature = signature.unwrap();

        println!("Signature length: {}", signature.len());

        println!("Signature: {:?}", signature.to_lower_hex_string());
    }
}
