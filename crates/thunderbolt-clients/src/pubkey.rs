use bitcoin_utils::bitcoin::XOnlyPublicKey;
use cosmrs::{Any, ErrorReport};

#[derive(Debug, Clone)]
pub struct ThunderboltPublicKey {
    pub type_url: String,
    pub value: Vec<u8>,
}

impl From<XOnlyPublicKey> for ThunderboltPublicKey {
    fn from(x_only_pubkey: XOnlyPublicKey) -> Self {
        // The protobuf message format is:
        // - First byte (10): Field number 1, wire type 2 (length-delimited)
        // - Second byte (33): Length of the key field (33 bytes)
        // - Third byte (02): The fixed 0x02 prefix for a compressed x-only public key.
        // - Fourth byte to end: The x-only public key.
        let mut bytes = [0u8; 35];
        bytes[0] = 10;
        bytes[1] = 33;
        bytes[2] = 2;
        bytes[3..].copy_from_slice(&x_only_pubkey.serialize());
        Self {
            type_url: "/cosmos.crypto.taproot.PubKey".to_string(),
            value: bytes.to_vec(),
        }
    }
}

impl TryFrom<Any> for ThunderboltPublicKey {
    type Error = ErrorReport;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        if any.type_url != "/cosmos.crypto.taproot.PubKey" {
            return Err(ErrorReport::msg("Invalid type URL"));
        }
        let value = any.value;
        Ok(Self {
            type_url: any.type_url,
            value,
        })
    }
}

impl ThunderboltPublicKey {
    pub fn to_x_only_pubkey(&self) -> XOnlyPublicKey {
        // The protobuf message format is:
        // - First byte (10): Field number 1, wire type 2 (length-delimited)
        // - Second byte (33): Length of the key field (33 bytes)
        // - Third byte (02): The fixed 0x02 prefix for a compressed x-only public key.
        // - Fourth byte to end: The x-only public key.
        XOnlyPublicKey::from_slice(&self.value[3..]).unwrap()
    }

    pub fn to_any(&self) -> Any {
        Any {
            type_url: self.type_url.clone(),
            value: self.value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin_utils::bitcoin::hex::DisplayHex;
    use bitcoin_utils::bitcoin::secp256k1::PublicKey as Secp256k1PublicKey;

    use super::*;

    #[test]
    fn test_bitcoin_pubkey_to_cosmos_pubkey() {
        let pubkey_str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179a";
        let x_only_public_key = Secp256k1PublicKey::from_str(pubkey_str).unwrap().x_only_public_key().0;
        let thunderbolt_pubkey = ThunderboltPublicKey::from(x_only_public_key);
        assert_eq!(thunderbolt_pubkey.type_url, "/cosmos.crypto.taproot.PubKey");
        assert_eq!(thunderbolt_pubkey.value.len(), 35);
        assert_eq!(thunderbolt_pubkey.value[2..].to_lower_hex_string(), pubkey_str);
    }

    #[test]
    fn test_bitcoin_pubkey_to_cosmos_pubkey_from_hex() {
        let pubkey_str = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179a";
        let x_only_public_key = Secp256k1PublicKey::from_str(pubkey_str).unwrap().x_only_public_key().0;
        let thunderbolt_pubkey = ThunderboltPublicKey::from(x_only_public_key);
        assert_eq!(thunderbolt_pubkey.value[2..].to_lower_hex_string()[2..], pubkey_str[2..]);
    }
}
