use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
use sha2::{Digest as _, Sha256};

use crate::{PaillierError, RawPublicKey3072, Result};

const CERTIFICATE_MAGIC: &[u8; 8] = b"TBP3PKC1";
const CERTIFICATE_VERSION: u16 = 1;
const PROFILE_ID: u8 = 2;
const CERTIFICATE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/paillier-key-certificate/1";
const AUTHORITY_ID_DOMAIN: &[u8] = b"bitcoin-thunderbolt/paillier-provisioning-authority/1";

pub const PUBLIC_KEY_CERTIFICATE_BODY_BYTES: usize = 540;
pub const PUBLIC_KEY_CERTIFICATE_BYTES: usize = PUBLIC_KEY_CERTIFICATE_BODY_BYTES + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CertifiedKeyRole3072 {
    Recipient = 1,
    Committee = 2,
    CommitteeMember = 3,
}

impl TryFrom<u8> for CertifiedKeyRole3072 {
    type Error = PaillierError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Recipient),
            2 => Ok(Self::Committee),
            3 => Ok(Self::CommitteeMember),
            _ => Err(PaillierError::InvalidCertificate {
                reason: "key role is unsupported",
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CertifiedKeyIdentity3072 {
    role: CertifiedKeyRole3072,
    subject_id: [u8; 32],
}

impl CertifiedKeyIdentity3072 {
    pub fn new(role: CertifiedKeyRole3072, subject_id: [u8; 32]) -> Result<Self> {
        require_nonzero("subject id", &subject_id)?;
        Ok(Self { role, subject_id })
    }

    #[must_use]
    pub const fn role(&self) -> CertifiedKeyRole3072 {
        self.role
    }

    #[must_use]
    pub const fn subject_id(&self) -> &[u8; 32] {
        &self.subject_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyCertificateBody3072 {
    deployment_digest: [u8; 32],
    committee_epoch: u64,
    identity: CertifiedKeyIdentity3072,
    key_validity_policy_id: [u8; 32],
    authority_id: [u8; 32],
    certificate_serial: u64,
    modulus: RawPublicKey3072,
}

impl PublicKeyCertificateBody3072 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment_digest: [u8; 32],
        committee_epoch: u64,
        identity: CertifiedKeyIdentity3072,
        key_validity_policy_id: [u8; 32],
        authority_id: [u8; 32],
        certificate_serial: u64,
        modulus: RawPublicKey3072,
    ) -> Result<Self> {
        require_nonzero("deployment digest", &deployment_digest)?;
        require_nonzero("key-validity policy id", &key_validity_policy_id)?;
        require_nonzero("authority id", &authority_id)?;
        if committee_epoch == 0 || certificate_serial == 0 {
            return Err(PaillierError::InvalidCertificate {
                reason: "committee epoch and certificate serial must be positive",
            });
        }
        Ok(Self {
            deployment_digest,
            committee_epoch,
            identity,
            key_validity_policy_id,
            authority_id,
            certificate_serial,
            modulus,
        })
    }

    #[must_use]
    pub const fn deployment_digest(&self) -> &[u8; 32] {
        &self.deployment_digest
    }

    #[must_use]
    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }

    #[must_use]
    pub const fn identity(&self) -> &CertifiedKeyIdentity3072 {
        &self.identity
    }

    #[must_use]
    pub const fn key_validity_policy_id(&self) -> &[u8; 32] {
        &self.key_validity_policy_id
    }

    #[must_use]
    pub const fn authority_id(&self) -> &[u8; 32] {
        &self.authority_id
    }

    #[must_use]
    pub const fn certificate_serial(&self) -> u64 {
        self.certificate_serial
    }

    #[must_use]
    pub const fn modulus(&self) -> &RawPublicKey3072 {
        &self.modulus
    }

    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CERTIFICATE_DOMAIN);
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_CERTIFICATE_BODY_BYTES] {
        let mut bytes = [0_u8; PUBLIC_KEY_CERTIFICATE_BODY_BYTES];
        bytes[..8].copy_from_slice(CERTIFICATE_MAGIC);
        bytes[8..10].copy_from_slice(&CERTIFICATE_VERSION.to_be_bytes());
        bytes[10] = PROFILE_ID;
        bytes[11] = self.identity.role as u8;
        bytes[12..44].copy_from_slice(&self.deployment_digest);
        bytes[44..52].copy_from_slice(&self.committee_epoch.to_be_bytes());
        bytes[52..84].copy_from_slice(&self.identity.subject_id);
        bytes[84..116].copy_from_slice(&self.key_validity_policy_id);
        bytes[116..148].copy_from_slice(&self.authority_id);
        bytes[148..156].copy_from_slice(&self.certificate_serial.to_be_bytes());
        bytes[156..].copy_from_slice(&self.modulus.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != PUBLIC_KEY_CERTIFICATE_BODY_BYTES {
            return Err(PaillierError::InvalidLength {
                field: "public-key certificate body",
                expected: PUBLIC_KEY_CERTIFICATE_BODY_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes.get(..8) != Some(CERTIFICATE_MAGIC) {
            return Err(PaillierError::InvalidCertificate {
                reason: "certificate magic is invalid",
            });
        }
        if bytes.get(8..10) != Some(CERTIFICATE_VERSION.to_be_bytes().as_slice()) || bytes.get(10) != Some(&PROFILE_ID)
        {
            return Err(PaillierError::InvalidCertificate {
                reason: "certificate version or profile is unsupported",
            });
        }
        let role = CertifiedKeyRole3072::try_from(bytes[11])?;
        let deployment_digest = array_at::<32>(bytes, 12, "deployment digest")?;
        let committee_epoch = u64::from_be_bytes(array_at::<8>(bytes, 44, "committee epoch")?);
        let subject_id = array_at::<32>(bytes, 52, "subject id")?;
        let key_validity_policy_id = array_at::<32>(bytes, 84, "key-validity policy id")?;
        let authority_id = array_at::<32>(bytes, 116, "authority id")?;
        let certificate_serial = u64::from_be_bytes(array_at::<8>(bytes, 148, "certificate serial")?);
        let modulus = RawPublicKey3072::from_bytes(bytes.get(156..).ok_or(PaillierError::InvalidCertificate {
            reason: "certificate modulus is missing",
        })?)?;
        Self::new(
            deployment_digest,
            committee_epoch,
            CertifiedKeyIdentity3072::new(role, subject_id)?,
            key_validity_policy_id,
            authority_id,
            certificate_serial,
            modulus,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedPublicKeyRecord3072 {
    body: PublicKeyCertificateBody3072,
    signature: [u8; 64],
}

impl CertifiedPublicKeyRecord3072 {
    pub fn new(body: PublicKeyCertificateBody3072, signature: [u8; 64]) -> Result<Self> {
        let _ = Signature::from_byte_array(signature);
        Ok(Self { body, signature })
    }

    #[must_use]
    pub const fn body(&self) -> &PublicKeyCertificateBody3072 {
        &self.body
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_CERTIFICATE_BYTES] {
        let mut bytes = [0_u8; PUBLIC_KEY_CERTIFICATE_BYTES];
        bytes[..PUBLIC_KEY_CERTIFICATE_BODY_BYTES].copy_from_slice(&self.body.to_bytes());
        bytes[PUBLIC_KEY_CERTIFICATE_BODY_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != PUBLIC_KEY_CERTIFICATE_BYTES {
            return Err(PaillierError::InvalidLength {
                field: "public-key certificate",
                expected: PUBLIC_KEY_CERTIFICATE_BYTES,
                actual: bytes.len(),
            });
        }
        let body = PublicKeyCertificateBody3072::from_bytes(&bytes[..PUBLIC_KEY_CERTIFICATE_BODY_BYTES])?;
        let signature = array_at::<64>(bytes, PUBLIC_KEY_CERTIFICATE_BODY_BYTES, "certificate signature")?;
        Self::new(body, signature)
    }
}

#[derive(Clone, Debug)]
pub struct ExpectedPublicKeyCertificate3072 {
    pub deployment_digest: [u8; 32],
    pub committee_epoch: u64,
    pub identity: CertifiedKeyIdentity3072,
    pub key_validity_policy_id: [u8; 32],
    pub certificate_serial: u64,
}

#[derive(Clone, Debug)]
pub struct TrustedProvisioningAuthority3072 {
    public_key: XOnlyPublicKey,
    authority_id: [u8; 32],
    valid_from_epoch: u64,
    valid_through_epoch: u64,
    key_validity_policy_id: [u8; 32],
}

impl TrustedProvisioningAuthority3072 {
    pub fn new(
        public_key: [u8; 32],
        valid_from_epoch: u64,
        valid_through_epoch: u64,
        key_validity_policy_id: [u8; 32],
    ) -> Result<Self> {
        if valid_from_epoch == 0 || valid_from_epoch > valid_through_epoch {
            return Err(PaillierError::InvalidCertificate {
                reason: "authority epoch validity range is invalid",
            });
        }
        require_nonzero("key-validity policy id", &key_validity_policy_id)?;
        let public_key =
            XOnlyPublicKey::from_byte_array(public_key).map_err(|_| PaillierError::InvalidCertificate {
                reason: "authority public key is not a valid BIP340 key",
            })?;
        let authority_id = authority_id(public_key.serialize());
        Ok(Self {
            public_key,
            authority_id,
            valid_from_epoch,
            valid_through_epoch,
            key_validity_policy_id,
        })
    }

    #[must_use]
    pub const fn authority_id(&self) -> &[u8; 32] {
        &self.authority_id
    }

    pub(crate) fn verify(
        &self,
        record: &CertifiedPublicKeyRecord3072,
        expected: &ExpectedPublicKeyCertificate3072,
    ) -> Result<()> {
        let body = record.body();
        if body.authority_id != self.authority_id {
            return Err(PaillierError::InvalidCertificate {
                reason: "certificate authority is not trusted for this record",
            });
        }
        if body.committee_epoch < self.valid_from_epoch || body.committee_epoch > self.valid_through_epoch {
            return Err(PaillierError::InvalidCertificate {
                reason: "certificate is outside the authority rotation window",
            });
        }
        if body.key_validity_policy_id != self.key_validity_policy_id
            || body.deployment_digest != expected.deployment_digest
            || body.committee_epoch != expected.committee_epoch
            || body.identity != expected.identity
            || body.key_validity_policy_id != expected.key_validity_policy_id
            || body.certificate_serial != expected.certificate_serial
        {
            return Err(PaillierError::InvalidCertificate {
                reason: "certificate scope does not match deployment policy",
            });
        }
        let signature = Signature::from_byte_array(record.signature);
        let message = body.signing_digest();
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, &self.public_key)
            .map_err(|_| PaillierError::InvalidCertificate {
                reason: "certificate signature verification failed",
            })
    }
}

#[must_use]
pub fn provisioning_authority_id(public_key: [u8; 32]) -> [u8; 32] {
    authority_id(public_key)
}

fn authority_id(public_key: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

fn require_nonzero(field: &'static str, value: &[u8; 32]) -> Result<()> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(PaillierError::InvalidCertificate { reason: field });
    }
    Ok(())
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize, _field: &'static str) -> Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or(PaillierError::InvalidCertificate {
            reason: "certificate field is truncated",
        })
}
