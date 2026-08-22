use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use thunderbolt_cometbft_client::PeerIdentity;

use crate::config::HttpsPeer;
use crate::credentials::certified_client_profile;
use crate::{Result, RpcTransportError};

pub(crate) struct TrackedClientConfig {
    pub config: Arc<rustls::ClientConfig>,
    pub client_certificate_used: Arc<AtomicBool>,
    pub client_certificate_mismatch: Arc<AtomicBool>,
}

pub(crate) fn client_config(peer: &HttpsPeer) -> Result<TrackedClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in &peer.roots {
        roots
            .add(certificate.clone())
            .map_err(|_| RpcTransportError::Certificate)?;
    }
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .map_err(|_| RpcTransportError::Certificate)?;
    let verifier = Arc::new(PinnedServerVerifier {
        webpki,
        expected_spki: peer.expected_spki,
    });
    let client_certificate_used = Arc::new(AtomicBool::new(false));
    let client_certificate_mismatch = Arc::new(AtomicBool::new(false));
    let resolver = Arc::new(TrackingClientResolver {
        inner: Arc::clone(&peer.client_resolver),
        used: Arc::clone(&client_certificate_used),
        mismatch: Arc::clone(&client_certificate_mismatch),
        expected_profile: peer.client_identity_profile,
        peer: peer.identity.clone(),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| RpcTransportError::Certificate)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TrackedClientConfig {
        config: Arc::new(config),
        client_certificate_used,
        client_certificate_mismatch,
    })
}

pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_owned())
        .map_err(|_| RpcTransportError::InvalidConfiguration("invalid TLS server name"))
}

pub(crate) fn spki_sha256(certificate: &CertificateDer<'_>) -> Result<[u8; 32]> {
    let parsed =
        rustls::server::ParsedCertificate::try_from(certificate).map_err(|_| RpcTransportError::Certificate)?;
    Ok(Sha256::digest(parsed.subject_public_key_info().as_ref()).into())
}

struct PinnedServerVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    expected_spki: [u8; 32],
}

struct TrackingClientResolver {
    inner: Arc<dyn rustls::client::ResolvesClientCert>,
    used: Arc<AtomicBool>,
    mismatch: Arc<AtomicBool>,
    expected_profile: [u8; 32],
    peer: PeerIdentity,
}

impl fmt::Debug for TrackingClientResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrackingClientResolver([redacted])")
    }
}

impl rustls::client::ResolvesClientCert for TrackingClientResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let resolved = self.inner.resolve(root_hint_subjects, sigschemes)?;
        let public_key = match resolved.key.public_key() {
            Some(public_key) => public_key,
            None => {
                self.mismatch.store(true, Ordering::SeqCst);
                return None;
            }
        };
        let actual = certified_client_profile(&self.peer, &resolved.cert, public_key.as_ref());
        if actual.as_ref().ok() != Some(&self.expected_profile) {
            self.mismatch.store(true, Ordering::SeqCst);
            return None;
        }
        self.used.store(true, Ordering::SeqCst);
        Some(resolved)
    }

    fn has_certs(&self) -> bool {
        self.inner.has_certs()
    }
}

impl fmt::Debug for PinnedServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedServerVerifier")
            .field("expected_spki", &self.expected_spki)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        let actual = spki_sha256(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if actual != self.expected_spki {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}
