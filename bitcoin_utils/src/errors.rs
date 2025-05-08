use bitcoin::address::{FromScriptError, P2shError, ParseError};
use bitcoin::key::UncompressedPublicKeyError;
use bitcoin::psbt::Error as PsbtError;
use bitcoin::sighash::TaprootError as TaprootSighashError;
use bitcoin::Txid;
use bitcoin::{bech32::DecodeError as Bech32DecodeError, secp256k1::Error as Secp256k1Error};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AddressError {
    #[error("decode address failed due to: `{0}`")]
    FromScriptError(#[from] FromScriptError),

    #[error("parse address failed due to: `{0}`")]
    ParseError(#[from] ParseError),

    #[error("decode address failed due to: `{0}`")]
    Bech32mDecodeError(#[from] Bech32DecodeError),

    #[error("generate address failed due to: `{0}`")]
    UncompressedPublicKey(#[from] UncompressedPublicKeyError),

    #[error("generate address failed due to: `{0}`")]
    P2ShError(#[from] P2shError),

    #[error("unknown address: `{0}`")]
    UnknownType(String),

    #[error("unstandard address: `{0}`")]
    Unstandard(String),
}

#[derive(Error, Debug)]
pub enum ConstructionError {
    #[error("PSBT error: {0}")]
    PsbtError(#[from] PsbtError),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] Secp256k1Error),

    #[error("invalid transaction due to symbol decoding error: `{0}`")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[error("address error: {0}")]
    AddressError(#[from] AddressError),

    #[error("taproot sighash error: {0}")]
    TaprootSighashError(#[from] TaprootSighashError),

    #[error("invalid transaction `{0:?}`, reason unknown")]
    Unknown(Option<Txid>),

    #[error("invalid transaction `{0:?}`, parsing failed due to: `{1}`")]
    ParseError(Option<Txid>, String),

    #[error("invalid transaction `{0:?}`, insufficient funds: `{1}` sats are required but only `{2}` sats given")]
    InsufficientFunds(Option<Txid>, u64, u64),

    #[error("invalid transaction `{0:?}`, invalid input count: `{1}` inputs are required but only `{2}` inputs given")]
    InvalidInputCount(Option<Txid>, usize, usize),

    #[error("invalid transaction `{0:?}`, calldata chunk too large")]
    CalldataChunkTooLarge(Option<Txid>),
}
