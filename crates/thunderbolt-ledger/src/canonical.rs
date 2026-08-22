use std::convert::TryFrom;

use sha2::{Digest as _, Sha256};

use crate::{LedgerContractError, Result};

/// A binary transcript in which every item is length-prefixed.
///
/// Labels are part of the hash contract. This prevents field concatenation,
/// reordering, and cross-protocol interpretation even when two fields have the
/// same byte width.
#[derive(Default)]
pub(crate) struct CanonicalTranscript {
    bytes: Vec<u8>,
}

impl CanonicalTranscript {
    pub(crate) fn new(domain: &'static [u8]) -> Result<Self> {
        let mut transcript = Self::default();
        transcript.item(b"domain", domain)?;
        Ok(transcript)
    }

    pub(crate) fn item(&mut self, label: &'static [u8], value: &[u8]) -> Result<()> {
        self.raw_bytes(label)?;
        self.raw_bytes(value)
    }

    pub(crate) fn u8(&mut self, label: &'static [u8], value: u8) -> Result<()> {
        self.item(label, &[value])
    }

    pub(crate) fn u16(&mut self, label: &'static [u8], value: u16) -> Result<()> {
        self.item(label, &value.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, label: &'static [u8], value: u32) -> Result<()> {
        self.item(label, &value.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, label: &'static [u8], value: u64) -> Result<()> {
        self.item(label, &value.to_be_bytes())
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn digest(self) -> [u8; 32] {
        Sha256::digest(self.finish()).into()
    }

    fn raw_bytes(&mut self, value: &[u8]) -> Result<()> {
        let len = u64::try_from(value.len()).map_err(|_| LedgerContractError::InvalidField {
            field: "canonical byte length",
            reason: "length does not fit in u64",
        })?;
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}
