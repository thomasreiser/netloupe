//! Certificate-authority identification and ACME challenge-method
//! analysis for the TLS pane: is this a Let's Encrypt/ZeroSSL/Google
//! Trust Services/Buypass cert, and if so was it issued via DNS-01 or
//! HTTP-01 — plus the equivalent "who manages this and how" question for
//! non-ACME managed issuers like AWS ACM, Azure, and Cloudflare.
//!
//! **What's actually determinable, and what isn't.** The challenge method
//! ACME uses to prove domain control is a one-time step during issuance;
//! a well-behaved client removes the DNS-01 TXT record or HTTP-01 token
//! immediately after validation succeeds, and the resulting certificate
//! carries no metadata saying which method was used. Two things *are*
//! knowable, though:
//! - A **wildcard** SAN (`*.example.com`) can only be issued via DNS-01 —
//!   HTTP-01 can't prove control of an entire subdomain space — so that
//!   case is certain, not a guess.
//! - Some automation (e.g. CNAME-delegated DNS-01 setups) leaves a
//!   `_acme-challenge` CNAME or TXT record in place permanently for
//!   unattended renewal, so a live DNS lookup can turn up real evidence
//!   even when it isn't proof about the currently active certificate.
//!
//! For everything else this reports what it can confirm and says plainly
//! when something can't be known after the fact, rather than guessing.

use std::net::IpAddr;
use std::time::Duration;

/// A certificate authority/issuance system this module knows how to
/// reason about. `Other` carries the raw issuer string for anything not
/// specifically recognized — there's nothing ACME-specific to say about
/// it, so `inspect` returns `None` rather than a mostly-empty report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateAuthority {
    LetsEncrypt,
    ZeroSsl,
    GoogleTrustServices,
    BuypassGo,
    AmazonAcm,
    MicrosoftAzure,
    CloudflareManaged,
    Other(String),
}

impl CertificateAuthority {
    pub fn name(&self) -> String {
        match self {
            CertificateAuthority::LetsEncrypt => "Let's Encrypt".to_string(),
            CertificateAuthority::ZeroSsl => "ZeroSSL".to_string(),
            CertificateAuthority::GoogleTrustServices => "Google Trust Services".to_string(),
            CertificateAuthority::BuypassGo => "Buypass".to_string(),
            CertificateAuthority::AmazonAcm => "Amazon (AWS Certificate Manager)".to_string(),
            CertificateAuthority::MicrosoftAzure => "Microsoft Azure".to_string(),
            CertificateAuthority::CloudflareManaged => "Cloudflare".to_string(),
            CertificateAuthority::Other(raw) => raw.clone(),
        }
    }

    /// `None` for `Other`: nothing ACME-specific applies.
    fn kind(&self) -> Option<CaKind> {
        match self {
            CertificateAuthority::LetsEncrypt
            | CertificateAuthority::ZeroSsl
            | CertificateAuthority::BuypassGo => Some(CaKind::PublicAcme),
            // Unlike Let's Encrypt (ACME is its *only* issuance path),
            // Google Trust Services both runs a public ACME endpoint
            // (used by e.g. GCP-managed certs) *and* issues to Google's
            // own first-party domains through its own internal, non-ACME
            // automation. A GTS-issued cert for google.com itself almost
            // certainly took the latter path, so treating every GTS cert
            // as "public ACME" the way Let's Encrypt's certs are would
            // overclaim certainty about a protocol that may not have
            // been involved at all.
            CertificateAuthority::GoogleTrustServices => Some(CaKind::PossiblyAcme),
            CertificateAuthority::AmazonAcm
            | CertificateAuthority::MicrosoftAzure
            | CertificateAuthority::CloudflareManaged => Some(CaKind::ManagedInternal),
            CertificateAuthority::Other(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaKind {
    /// Issues via the public RFC 8555 ACME protocol (DNS-01/HTTP-01) —
    /// and, for this CA, that's the *only* public issuance path, so a
    /// wildcard SAN reliably implies DNS-01.
    PublicAcme,
    /// Runs a public ACME endpoint but *also* issues certificates through
    /// its own internal, non-ACME automation for its own domains — so
    /// unlike `PublicAcme`, ACME having been used at all isn't a given.
    PossiblyAcme,
    /// Automated, but validated and renewed through the provider's own
    /// internal mechanism rather than public ACME with a predictable
    /// challenge record name.
    ManagedInternal,
}

/// What can be said about which ACME challenge method issued this cert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeHint {
    /// A wildcard SAN is present: DNS-01 is the only method capable of
    /// proving that, so this is certain, not inferred.
    Dns01Certain,
    /// A non-wildcard cert from a public-ACME CA: either method could
    /// have been used, and the certificate itself doesn't say which.
    EitherMethodPossible,
    /// This CA doesn't do public RFC 8555 ACME with a predictable
    /// challenge location (AWS ACM, Azure, Cloudflare); see `note`.
    NotPublicAcme,
    /// This CA runs public ACME but *also* issues outside it for its own
    /// domains (Google Trust Services); whether ACME was used at all —
    /// let alone which challenge — isn't established. See `note`.
    UncertainAcmeUsage,
}

/// A live snapshot of whatever's currently at `_acme-challenge.<domain>`.
/// Not necessarily evidence about *this* certificate specifically — DNS-01
/// automation sometimes leaves this in place permanently for renewal, but
/// a one-off manual issuance would have cleaned it up right after.
#[derive(Debug, Clone, Default)]
pub struct Dns01Evidence {
    pub txt_values: Vec<String>,
    pub cname_target: Option<String>,
}

impl Dns01Evidence {
    pub fn is_empty(&self) -> bool {
        self.txt_values.is_empty() && self.cname_target.is_none()
    }
}

/// A best-effort probe of the HTTP-01 well-known path. A completed
/// HTTP-01 challenge's token file is deleted right after validation, so
/// this almost always comes back empty — that's expected, not a failure.
#[derive(Debug, Clone)]
pub struct Http01Evidence {
    pub status: Option<u16>,
    /// Present only if the path returned a non-empty body (i.e. an
    /// unusually long-lived or still-active challenge responder).
    pub body_sample: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AcmeInfo {
    pub authority: CertificateAuthority,
    pub is_wildcard: bool,
    pub challenge_hint: ChallengeHint,
    /// `None` when not attempted (no domain to query, e.g. an IP target,
    /// or a `ManagedInternal` CA where the generic `_acme-challenge` name
    /// doesn't apply).
    pub dns01: Option<Dns01Evidence>,
    /// `None` when not attempted (no domain, wildcard already certain, or
    /// `ManagedInternal`).
    pub http01: Option<Http01Evidence>,
    pub note: Option<&'static str>,
}

/// Classifies a certificate's issuer string (e.g.
/// `"C=US, O=Let's Encrypt, CN=R3"`) into a known CA. Pure and
/// network-free so it's trivially unit-testable.
pub fn classify_issuer(issuer: &str) -> CertificateAuthority {
    let lower = issuer.to_lowercase();
    if lower.contains("let's encrypt") || lower.contains("lets encrypt") {
        CertificateAuthority::LetsEncrypt
    } else if lower.contains("zerossl") {
        CertificateAuthority::ZeroSsl
    } else if lower.contains("google trust services") {
        CertificateAuthority::GoogleTrustServices
    } else if lower.contains("buypass") {
        CertificateAuthority::BuypassGo
    } else if lower.contains("amazon") {
        CertificateAuthority::AmazonAcm
    } else if lower.contains("microsoft") {
        CertificateAuthority::MicrosoftAzure
    } else if lower.contains("cloudflare") {
        CertificateAuthority::CloudflareManaged
    } else {
        CertificateAuthority::Other(issuer.to_string())
    }
}

fn managed_internal_note(ca: &CertificateAuthority) -> Option<&'static str> {
    match ca {
        CertificateAuthority::AmazonAcm => Some(
            "AWS ACM validates domain control with a per-certificate CNAME record, usually left \
             in the DNS zone permanently for auto-renewal. Its name is randomized per \
             certificate and can't be derived after the fact — look in your DNS zone for a \
             CNAME whose target ends in acm-validations.aws.",
        ),
        CertificateAuthority::MicrosoftAzure => {
            Some("Azure validates and renews its own certificates (App Service, Front Door, ...) internally; there's no public DNS-01/HTTP-01 record to inspect.")
        }
        CertificateAuthority::CloudflareManaged => Some(
            "Cloudflare validates and renews its edge/Universal SSL certificates internally once \
             a zone is proxied through it; there's no public DNS-01/HTTP-01 record to inspect.",
        ),
        CertificateAuthority::GoogleTrustServices => Some(
            "Google Trust Services issues certificates both via a public ACME endpoint (used by \
             e.g. GCP-managed certs) and via Google's own internal automation for its own \
             domains — a GTS-issued cert for a Google property most likely took the latter path, \
             which leaves no public DNS-01/HTTP-01 record to inspect.",
        ),
        _ => None,
    }
}

/// Identifies the issuing CA and, for a recognized one, works out what
/// can be said about its ACME challenge method — including live DNS/HTTP
/// probes for current `_acme-challenge` evidence. Returns `None` for an
/// unrecognized/manually-procured CA, since there's nothing ACME-specific
/// to report.
///
/// `domain` is the hostname the certificate was fetched for (`None` for a
/// bare-IP target: ACME challenges are domain-based, so nothing to probe).
pub async fn inspect(
    domain: Option<&str>,
    sans: &[String],
    issuer: &str,
    dns_timeout: Duration,
    http_timeout: Duration,
) -> Option<AcmeInfo> {
    let authority = classify_issuer(issuer);
    let kind = authority.kind()?;

    let is_wildcard = sans.iter().any(|s| s.starts_with("*."));
    let challenge_hint = match kind {
        CaKind::PublicAcme if is_wildcard => ChallengeHint::Dns01Certain,
        CaKind::PublicAcme => ChallengeHint::EitherMethodPossible,
        CaKind::PossiblyAcme => ChallengeHint::UncertainAcmeUsage,
        CaKind::ManagedInternal => ChallengeHint::NotPublicAcme,
    };
    let note = managed_internal_note(&authority);

    let mut info = AcmeInfo {
        authority,
        is_wildcard,
        challenge_hint,
        dns01: None,
        http01: None,
        note,
    };

    if matches!(kind, CaKind::PublicAcme | CaKind::PossiblyAcme) {
        if let Some(domain) = domain {
            // A wildcard's own label doesn't carry a TXT record; the
            // challenge for `*.example.com` is proven at `example.com`.
            let base = domain.strip_prefix("*.").unwrap_or(domain);
            info.dns01 = Some(probe_dns01(base, dns_timeout).await);
            if challenge_hint != ChallengeHint::Dns01Certain {
                info.http01 = Some(probe_http01(base, http_timeout).await);
            }
        }
    }

    Some(info)
}

async fn probe_dns01(base_domain: &str, timeout: Duration) -> Dns01Evidence {
    let name = format!("_acme-challenge.{base_domain}");
    let txt_values = crate::checks::dns::lookup_txt(&name, timeout)
        .await
        .unwrap_or_default();
    let cname_target = crate::checks::dns::lookup_cname(&name, timeout)
        .await
        .ok()
        .flatten();
    Dns01Evidence {
        txt_values,
        cname_target,
    }
}

async fn probe_http01(base_domain: &str, timeout: Duration) -> Http01Evidence {
    // No token filename is knowable after the fact, so this only checks
    // whether the well-known directory itself responds; see the module
    // doc. `IpAddr` isn't reachable here since `base_domain` always comes
    // from a hostname target (see `inspect`'s `domain` contract).
    let url = format!("http://{base_domain}/.well-known/acme-challenge/");
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return Http01Evidence {
                status: None,
                body_sample: None,
                error: Some(err.to_string()),
            }
        }
    };

    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body_sample = response
                .text()
                .await
                .ok()
                .filter(|b| !b.trim().is_empty())
                .map(|b| b.chars().take(200).collect());
            Http01Evidence {
                status: Some(status),
                body_sample,
                error: None,
            }
        }
        Err(err) => Http01Evidence {
            status: None,
            body_sample: None,
            error: Some(err.to_string()),
        },
    }
}

/// Kept for callers that already have an `IpAddr` and want to confirm
/// `inspect` should be given `None` for `domain`: ACME challenges are
/// always domain-based.
pub fn domain_for_target(host_display: &str) -> Option<&str> {
    if host_display.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host_display)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_lets_encrypt() {
        assert_eq!(
            classify_issuer("C=US, O=Let's Encrypt, CN=R3"),
            CertificateAuthority::LetsEncrypt
        );
    }

    #[test]
    fn classifies_zerossl_google_and_buypass() {
        assert_eq!(
            classify_issuer("C=AT, O=ZeroSSL, CN=ZeroSSL RSA Domain Secure Site CA"),
            CertificateAuthority::ZeroSsl
        );
        assert_eq!(
            classify_issuer("C=US, O=Google Trust Services, CN=WE1"),
            CertificateAuthority::GoogleTrustServices
        );
        assert_eq!(
            classify_issuer("C=NO, O=Buypass AS-983163327, CN=Buypass Go SSL ICA - G2"),
            CertificateAuthority::BuypassGo
        );
    }

    #[test]
    fn classifies_managed_internal_cas() {
        assert_eq!(
            classify_issuer("C=US, O=Amazon, CN=Amazon RSA 2048 M02"),
            CertificateAuthority::AmazonAcm
        );
        assert_eq!(
            classify_issuer("C=US, O=Microsoft Corporation, CN=Microsoft Azure TLS Issuing CA 05"),
            CertificateAuthority::MicrosoftAzure
        );
        assert_eq!(
            classify_issuer("C=US, O=Cloudflare, Inc., CN=Cloudflare Inc ECC CA-3"),
            CertificateAuthority::CloudflareManaged
        );
    }

    #[test]
    fn classifies_unknown_cas_as_other() {
        let ca =
            classify_issuer("C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1");
        assert_eq!(
            ca,
            CertificateAuthority::Other(
                "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1".to_string()
            )
        );
        assert!(ca.kind().is_none());
    }

    #[tokio::test]
    async fn unrecognized_ca_yields_no_acme_info() {
        let info = inspect(
            None,
            &[],
            "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .await;
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn wildcard_lets_encrypt_cert_is_certain_dns01_without_probing() {
        let sans = vec!["*.example.com".to_string(), "example.com".to_string()];
        // `domain: None` guarantees no network call happens, regardless of
        // the hint, so this stays a pure/offline test.
        let info = inspect(
            None,
            &sans,
            "C=US, O=Let's Encrypt, CN=R3",
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        assert_eq!(info.authority, CertificateAuthority::LetsEncrypt);
        assert!(info.is_wildcard);
        assert_eq!(info.challenge_hint, ChallengeHint::Dns01Certain);
        assert!(
            info.dns01.is_none(),
            "no domain was given, so no probe should have run"
        );
        assert!(info.http01.is_none());
    }

    #[tokio::test]
    async fn non_wildcard_lets_encrypt_cert_is_inconclusive() {
        let sans = vec!["example.com".to_string()];
        let info = inspect(
            None,
            &sans,
            "C=US, O=Let's Encrypt, CN=R3",
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        assert!(!info.is_wildcard);
        assert_eq!(info.challenge_hint, ChallengeHint::EitherMethodPossible);
    }

    #[tokio::test]
    async fn managed_internal_cas_get_a_note_and_no_public_acme_hint() {
        for issuer in [
            "C=US, O=Amazon, CN=Amazon RSA 2048 M02",
            "C=US, O=Microsoft Corporation, CN=Microsoft Azure TLS Issuing CA 05",
        ] {
            let info = inspect(
                None,
                &[],
                issuer,
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await
            .unwrap();
            assert_eq!(info.challenge_hint, ChallengeHint::NotPublicAcme);
            assert!(info.note.is_some());
            assert!(info.dns01.is_none());
            assert!(info.http01.is_none());
        }
    }

    #[tokio::test]
    async fn google_trust_services_is_uncertain_even_for_a_wildcard() {
        // Unlike Let's Encrypt, GTS also issues to Google's own domains
        // through its own internal, non-ACME automation, so a wildcard
        // SAN alone can't make DNS-01 "certain" the way it does for a
        // CA where ACME is the only public issuance path.
        for sans in [
            vec!["*.example.com".to_string()],
            vec!["example.com".to_string()],
        ] {
            let info = inspect(
                None,
                &sans,
                "C=US, O=Google Trust Services, CN=WE1",
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await
            .unwrap();
            assert_eq!(info.authority, CertificateAuthority::GoogleTrustServices);
            assert_eq!(info.challenge_hint, ChallengeHint::UncertainAcmeUsage);
            assert!(
                info.note.is_some(),
                "should explain the hybrid issuance path"
            );
        }
    }

    #[test]
    fn domain_for_target_rejects_ip_literals() {
        assert_eq!(domain_for_target("example.com"), Some("example.com"));
        assert_eq!(domain_for_target("8.8.8.8"), None);
        assert_eq!(domain_for_target("2606:4700:4700::1111"), None);
    }
}
