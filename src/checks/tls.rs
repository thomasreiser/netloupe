//! TLS pane: chain, SANs, expiry, negotiated protocol/cipher.
//!
//! The verifier used here deliberately accepts any certificate chain: this
//! is a diagnostic tool inspecting whatever a server presents (including
//! expired or self-signed certs), not a client establishing a trusted
//! connection, so validity/expiry become results to *report*, not gates
//! that stop the handshake.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};
use crate::target::Target;

#[derive(Debug, Clone, Default)]
pub struct TlsResult {
    pub host: String,
    pub port: u16,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub sans: Vec<String>,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
    pub days_until_expiry: Option<i64>,
    pub chain_len: usize,
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Tls;
    super::run_guarded(&ctx, id, &tx, async {
        let host = match &ctx.target {
            Target::Host { ascii, display } => (ascii.clone(), display.clone()),
            Target::Ip(ip) => (ip.to_string(), ip.to_string()),
        };
        let port = ctx.port.unwrap_or(443);
        let ip = super::resolve_target_ip(&ctx).await?;

        let mut result = TlsResult {
            host: host.1,
            port,
            ..Default::default()
        };
        connect_and_inspect(ip, &host.0, port, ctx.config.timeouts.tls, &mut result).await;

        ctx.shared.set_tls(result.clone()).await;
        Ok(CheckUpdate::Tls(result))
    })
    .await;
}

async fn connect_and_inspect(
    ip: IpAddr,
    sni: &str,
    port: u16,
    timeout: std::time::Duration,
    result: &mut TlsResult,
) {
    let config = client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let server_name = match ServerName::try_from(sni.to_string()) {
        Ok(name) => name,
        Err(err) => {
            result
                .errors
                .push(format!("invalid server name {sni:?}: {err}"));
            return;
        }
    };

    let attempt = async {
        let tcp = TcpStream::connect((ip, port))
            .await
            .map_err(|e| e.to_string())?;
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (_, conn) = stream.get_ref();

        result.protocol_version = conn.protocol_version().map(|v| format!("{v:?}"));
        result.cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()));
        result.alpn = conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string());

        if let Some(certs) = conn.peer_certificates() {
            result.chain_len = certs.len();
            if let Some(leaf) = certs.first() {
                describe_leaf_certificate(leaf, result);
            }
        }
        Ok::<(), String>(())
    };

    if let Err(err) = tokio::time::timeout(timeout, attempt)
        .await
        .unwrap_or_else(|_| Err("TLS handshake timed out".to_string()))
    {
        result.errors.push(err);
    }
}

fn describe_leaf_certificate(der: &CertificateDer<'_>, result: &mut TlsResult) {
    let Ok((_, cert)) = X509Certificate::from_der(der.as_ref()) else {
        result
            .errors
            .push("could not parse the leaf certificate".to_string());
        return;
    };

    result.issuer = Some(cert.issuer().to_string());
    result.subject = Some(cert.subject().to_string());

    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    result.not_before_unix = Some(not_before);
    result.not_after_unix = Some(not_after);

    if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        result.days_until_expiry = Some((not_after - now.as_secs() as i64) / 86_400);
    }

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        result.sans = ext
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                GeneralName::IPAddress(ip) => ip_from_octets(ip).map(|ip| ip.to_string()),
                _ => None,
            })
            .collect();
    }
}

fn ip_from_octets(octets: &[u8]) -> Option<IpAddr> {
    match octets.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(octets).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(octets).ok()?)),
        _ => None,
    }
}

fn client_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth()
}

/// Accepts any certificate/signature: see the module doc for why. Only
/// used for a short-lived inspection connection, never anything that
/// exchanges real data.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_from_octets_handles_v4_and_v6() {
        assert_eq!(
            ip_from_octets(&[8, 8, 8, 8]),
            Some("8.8.8.8".parse().unwrap())
        );
        assert_eq!(ip_from_octets(&[0u8; 16]), Some("::".parse().unwrap()));
        assert_eq!(ip_from_octets(&[1, 2, 3]), None);
    }
}
