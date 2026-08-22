use thiserror::Error;

/// Thunderbolt 协议错误类型
#[derive(Error, Debug)]
pub enum ThunderboltError {
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("UTXO not found: {0}")]
    UtxoNotFound(String),
    
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    
    #[error("Threshold not met: required {required}, got {actual}")]
    ThresholdNotMet { required: u32, actual: u32 },
    
    #[error("Network communication error: {0}")]
    NetworkError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Serialization/Deserialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Committee member {member_id} behaved maliciously: {behavior}")]
    MaliciousBehavior { member_id: u32, behavior: String },
    
    #[error("Timeout waiting for response from node {node_id}")]
    Timeout { node_id: u32 },
    
    #[error("UTXO already spent: {0}")]
    UtxoAlreadySpent(String),
    
    #[error("Sequence number mismatch: expected {expected}, got {actual}")]
    SequenceNumberMismatch { expected: u64, actual: u64 },
}

pub type Result<T> = std::result::Result<T, ThunderboltError>;
