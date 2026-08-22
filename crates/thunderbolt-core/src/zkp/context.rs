use crate::{Result, ThunderboltError};

/// Domain-separation identifiers are network-controlled inputs in a deployed
/// verifier. Keeping them small prevents oversized transcripts from becoming
/// an allocation or hashing denial of service.
pub const MAX_CONTEXT_ID_BYTES: usize = 128;
pub const MAX_INVOICE_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofTag {
    Invoice,
    Transfer,
    ShareEncryption,
}

impl ProofTag {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Invoice => b"tb/invoice",
            Self::Transfer => b"tb/xfer",
            Self::ShareEncryption => b"tb/share",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofContext {
    ctx_id: Vec<u8>,
    inv_id: Vec<u8>,
    step: Option<u64>,
}

impl ProofContext {
    pub fn invoice(ctx_id: impl AsRef<[u8]>, inv_id: impl AsRef<[u8]>) -> Self {
        Self {
            ctx_id: ctx_id.as_ref().to_vec(),
            inv_id: inv_id.as_ref().to_vec(),
            step: None,
        }
    }

    pub fn transfer(ctx_id: impl AsRef<[u8]>, step: u64, inv_id: impl AsRef<[u8]>) -> Self {
        Self {
            ctx_id: ctx_id.as_ref().to_vec(),
            inv_id: inv_id.as_ref().to_vec(),
            step: Some(step),
        }
    }

    pub fn ctx_id(&self) -> &[u8] {
        &self.ctx_id
    }

    pub fn inv_id(&self) -> &[u8] {
        &self.inv_id
    }

    pub fn step(&self) -> Option<u64> {
        self.step
    }

    pub fn expect_invoice(&self) -> Result<()> {
        self.validate_bounds()?;
        if self.step.is_some() {
            return Err(ThunderboltError::InvalidParameter(
                "invoice proofs must not bind a step index".to_string(),
            ));
        }
        Ok(())
    }

    pub fn expect_transfer(&self) -> Result<u64> {
        self.validate_bounds()?;
        self.step.ok_or_else(|| {
            ThunderboltError::InvalidParameter("transfer proofs must bind an explicit step index".to_string())
        })
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.ctx_id.is_empty() || self.ctx_id.len() > MAX_CONTEXT_ID_BYTES {
            return Err(ThunderboltError::InvalidParameter(format!(
                "context id must contain 1..={MAX_CONTEXT_ID_BYTES} bytes"
            )));
        }
        if self.inv_id.is_empty() || self.inv_id.len() > MAX_INVOICE_ID_BYTES {
            return Err(ThunderboltError::InvalidParameter(format!(
                "invoice id must contain 1..={MAX_INVOICE_ID_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_identifiers() {
        assert!(ProofContext::invoice([], b"invoice").expect_invoice().is_err());
        assert!(ProofContext::invoice(b"channel", []).expect_invoice().is_err());
        assert!(ProofContext::invoice(vec![1; MAX_CONTEXT_ID_BYTES + 1], b"invoice")
            .expect_invoice()
            .is_err());
        assert!(ProofContext::transfer(b"channel", 1, vec![1; MAX_INVOICE_ID_BYTES + 1])
            .expect_transfer()
            .is_err());
    }
}
