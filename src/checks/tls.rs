//! TLS pane: full per-certificate detail (not just the leaf) for the
//! whole chain the server presents, plus negotiated protocol/cipher.
//!
//! The verifier used here deliberately accepts any certificate chain: this
//! is a diagnostic tool inspecting whatever a server presents (including
//! expired or self-signed certs), not a client establishing a trusted
//! connection, so validity/expiry become results to *report*, not gates
//! that stop the handshake.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::OidRegistry;
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
    /// Full detail for every certificate the server presented, leaf
    /// first, then each intermediate in the order sent (rarely including
    /// the root, which servers aren't required to and usually don't
    /// send). The flat `issuer`/`subject`/`sans`/... fields above mirror
    /// `chain[0]` for callers that only ever cared about the leaf.
    pub chain: Vec<CertificateDetail>,
    /// CA identification and ACME DNS-01/HTTP-01 challenge analysis; see
    /// `checks::acme`. `None` when the issuer isn't a CA this module
    /// recognizes (nothing ACME-specific to say), not yet computed, or the
    /// certificate itself failed to parse.
    pub acme: Option<crate::checks::acme::AcmeInfo>,
    pub errors: Vec<String>,
}

/// Full detail for one certificate in the chain -- everything a "view
/// certificate" dialog in a browser would show, parsed straight from the
/// DER the server sent (not fetched from anywhere else).
#[derive(Debug, Clone, Default)]
pub struct CertificateDetail {
    pub subject: String,
    pub issuer: String,
    /// Hex, colon-separated (the conventional presentation form).
    pub serial_number: String,
    /// The X.509 version as written on the wire: 1, 2, or 3.
    pub version: u32,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: usize,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    /// SHA-256 fingerprint of the whole DER-encoded certificate, hex,
    /// colon-separated -- the form most tools (and browsers) show.
    pub sha256_fingerprint: String,
    pub sha1_fingerprint: String,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
    /// Human-readable Key Usage flags present (e.g. "Digital Signature",
    /// "Key Cert Sign"), empty if the extension is absent.
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub subject_key_identifier: Option<String>,
    pub authority_key_identifier: Option<String>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_urls: Vec<String>,
    pub ca_issuers_urls: Vec<String>,
    /// Number of embedded Signed Certificate Timestamps (RFC 6962) --
    /// evidence the cert was logged to Certificate Transparency at
    /// issuance, independent of `checks::altnames`' *external* crt.sh
    /// lookup (that queries the logs directly; this reads what the CA
    /// stapled into the certificate itself).
    pub sct_count: usize,
    pub sans: Vec<String>,
    pub is_self_signed: bool,
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
        connect_and_inspect(
            ip,
            &host.0,
            port,
            &ctx.config.timeouts,
            ctx.resolver,
            &mut result,
        )
        .await;

        ctx.shared.set_tls(result.clone()).await;
        Ok(CheckUpdate::Tls(result))
    })
    .await;
}

async fn connect_and_inspect(
    ip: IpAddr,
    sni: &str,
    port: u16,
    timeouts: &crate::config::TimeoutConfig,
    resolver: Option<IpAddr>,
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
            for der in certs {
                match describe_certificate(der) {
                    Ok(detail) => result.chain.push(detail),
                    Err(err) => result.errors.push(err),
                }
            }
            if let Some(leaf) = result.chain.first() {
                result.issuer = Some(leaf.issuer.clone());
                result.subject = Some(leaf.subject.clone());
                result.sans = leaf.sans.clone();
                result.not_before_unix = Some(leaf.not_before_unix);
                result.not_after_unix = Some(leaf.not_after_unix);
                if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    result.days_until_expiry =
                        Some((leaf.not_after_unix - now.as_secs() as i64) / 86_400);
                }
            }
        }
        Ok::<(), String>(())
    };

    if let Err(err) = tokio::time::timeout(timeouts.tls, attempt)
        .await
        .unwrap_or_else(|_| Err("TLS handshake timed out".to_string()))
    {
        result.errors.push(err);
        return;
    }

    if let Some(issuer) = result.issuer.clone() {
        let domain = super::acme::domain_for_target(sni);
        result.acme = super::acme::inspect(
            domain,
            &result.sans,
            &issuer,
            timeouts.dns,
            timeouts.http,
            resolver,
        )
        .await;
    }
}

/// The registry of OIDs this module can turn into a human-readable name
/// (signature algorithms, key algorithms, ...). Built once: the registry
/// itself has no network/state dependency, just a lookup table.
fn oid_registry() -> &'static OidRegistry<'static> {
    static REGISTRY: OnceLock<OidRegistry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| OidRegistry::default().with_crypto().with_x509().with_x962())
}

fn oid_name(oid: &x509_parser::der_parser::Oid) -> String {
    oid_registry()
        .get(oid)
        .map(|entry| entry.description().to_string())
        .unwrap_or_else(|| oid.to_id_string())
}

/// Parses one DER-encoded certificate (any position in the chain, not
/// just the leaf) into everything a "view certificate" dialog would show.
fn describe_certificate(der: &CertificateDer<'_>) -> Result<CertificateDetail, String> {
    let (_, cert) = X509Certificate::from_der(der.as_ref())
        .map_err(|e| format!("could not parse a certificate in the chain: {e}"))?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    let is_self_signed = issuer == subject;

    let validity = cert.validity();
    let not_before_unix = validity.not_before.timestamp();
    let not_after_unix = validity.not_after.timestamp();

    let public_key = cert.public_key();
    let public_key_algorithm = oid_name(&public_key.algorithm.algorithm);
    let public_key_bits = public_key.parsed().map(|k| k.key_size()).unwrap_or(0);

    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                GeneralName::IPAddress(ip) => ip_from_octets(ip).map(|ip| ip.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let (is_ca, path_len_constraint) = match cert.basic_constraints() {
        Ok(Some(bc)) => (bc.value.ca, bc.value.path_len_constraint),
        _ => (cert.is_ca(), None),
    };

    let key_usage = match cert.key_usage() {
        Ok(Some(ku)) => key_usage_flags(ku.value),
        _ => Vec::new(),
    };
    let extended_key_usage = match cert.extended_key_usage() {
        Ok(Some(eku)) => extended_key_usage_flags(eku.value),
        _ => Vec::new(),
    };

    let mut subject_key_identifier = None;
    let mut authority_key_identifier = None;
    let mut crl_distribution_points = Vec::new();
    let mut ocsp_urls = Vec::new();
    let mut ca_issuers_urls = Vec::new();
    let mut sct_count = 0;
    for ext in cert.iter_extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ki) => {
                subject_key_identifier = Some(hex_colon(ki.0));
            }
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                authority_key_identifier = aki.key_identifier.as_ref().map(|ki| hex_colon(ki.0));
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                for point in points.iter() {
                    if let Some(x509_parser::extensions::DistributionPointName::FullName(names)) =
                        &point.distribution_point
                    {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                crl_distribution_points.push(uri.to_string());
                            }
                        }
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for desc in aia.iter() {
                    let GeneralName::URI(uri) = &desc.access_location else {
                        continue;
                    };
                    // id-ad-ocsp / id-ad-caIssuers (RFC 5280 4.2.2.1). Matched
                    // by numeric OID directly rather than through the
                    // registry's description text: these two access-method
                    // OIDs aren't in oid-registry's crypto/x509/x962 tables,
                    // so a description-based match never fires.
                    match desc.access_method.to_id_string().as_str() {
                        "1.3.6.1.5.5.7.48.1" => ocsp_urls.push(uri.to_string()),
                        "1.3.6.1.5.5.7.48.2" => ca_issuers_urls.push(uri.to_string()),
                        _ => {}
                    }
                }
            }
            ParsedExtension::SCT(scts) => sct_count = scts.len(),
            _ => {}
        }
    }

    let der_bytes = der.as_ref();
    let sha256_fingerprint = hex_colon(&Sha256::digest(der_bytes));
    let sha1_fingerprint = hex_colon(&Sha1::digest(der_bytes));

    Ok(CertificateDetail {
        subject,
        issuer,
        serial_number: hex_colon(cert.raw_serial()),
        version: cert.version().0 + 1,
        signature_algorithm: oid_name(&cert.signature_algorithm.algorithm),
        public_key_algorithm,
        public_key_bits,
        not_before_unix,
        not_after_unix,
        sha256_fingerprint,
        sha1_fingerprint,
        is_ca,
        path_len_constraint,
        key_usage,
        extended_key_usage,
        subject_key_identifier,
        authority_key_identifier,
        crl_distribution_points,
        ocsp_urls,
        ca_issuers_urls,
        sct_count,
        sans,
        is_self_signed,
    })
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn key_usage_flags(ku: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    let flags: &[(bool, &str)] = &[
        (ku.digital_signature(), "Digital Signature"),
        (ku.non_repudiation(), "Non Repudiation"),
        (ku.key_encipherment(), "Key Encipherment"),
        (ku.data_encipherment(), "Data Encipherment"),
        (ku.key_agreement(), "Key Agreement"),
        (ku.key_cert_sign(), "Certificate Signing"),
        (ku.crl_sign(), "CRL Signing"),
        (ku.encipher_only(), "Encipher Only"),
        (ku.decipher_only(), "Decipher Only"),
    ];
    flags
        .iter()
        .filter(|(present, _)| *present)
        .map(|(_, name)| name.to_string())
        .collect()
}

fn extended_key_usage_flags(eku: &x509_parser::extensions::ExtendedKeyUsage) -> Vec<String> {
    let flags: &[(bool, &str)] = &[
        (eku.any, "Any"),
        (eku.server_auth, "TLS Server Authentication"),
        (eku.client_auth, "TLS Client Authentication"),
        (eku.code_signing, "Code Signing"),
        (eku.email_protection, "Email Protection"),
        (eku.time_stamping, "Time Stamping"),
        (eku.ocsp_signing, "OCSP Signing"),
    ];
    flags
        .iter()
        .filter(|(present, _)| *present)
        .map(|(_, name)| name.to_string())
        .chain(eku.other.iter().map(oid_name))
        .collect()
}

fn ip_from_octets(octets: &[u8]) -> Option<IpAddr> {
    match octets.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(octets).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(octets).ok()?)),
        _ => None,
    }
}

/// Also used by `checks::http`'s raw HTTP/1.0 probe, which needs its own
/// bare TLS connection rather than going through reqwest (reqwest's
/// client always writes `HTTP/1.1` on the request line -- there's no
/// builder option to send an actual `HTTP/1.0` request, so answering
/// "does this server handle one" needs to speak the wire protocol
/// directly, the same way this module already does for the inspection
/// connection above).
pub(crate) fn client_config() -> ClientConfig {
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

    #[test]
    fn hex_colon_formats_bytes_as_uppercase_colon_separated_pairs() {
        assert_eq!(hex_colon(&[0x00, 0xd5, 0xff]), "00:D5:FF");
        assert_eq!(hex_colon(&[]), "");
    }

    #[test]
    fn key_usage_flags_lists_only_the_set_bits() {
        use x509_parser::extensions::KeyUsage;
        // digitalSignature (bit 0) + keyCertSign (bit 5): 0b0010_0001,
        // bit-reversed within the byte per the DER BIT STRING encoding
        // `KeyUsage::flags` already expects (see x509-parser's own
        // parse_keyusage).
        let ku = KeyUsage { flags: 0b0010_0001 };
        assert_eq!(
            key_usage_flags(&ku),
            vec!["Digital Signature", "Certificate Signing"]
        );
    }

    #[test]
    fn extended_key_usage_flags_lists_flags_and_other_oids() {
        use x509_parser::der_parser::Oid;
        use x509_parser::extensions::ExtendedKeyUsage;
        let eku = ExtendedKeyUsage {
            any: false,
            server_auth: true,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
            other: vec![Oid::from(&[1, 2, 3]).unwrap()],
        };
        let flags = extended_key_usage_flags(&eku);
        assert_eq!(flags[0], "TLS Server Authentication");
        assert_eq!(flags.len(), 2);
    }
}
