//! Table-driven tests for the provider engine, exercising the scenarios
//! called out in `CLAUDE.md`'s testing section against the real embedded
//! signatures. Range tables are built by hand here (rather than from the
//! bundled snapshot) so these tests stay stable regardless of when the
//! snapshot was last regenerated.

use std::net::IpAddr;

use super::ranges::RangeEntry;
use super::signatures;
use super::*;

fn test_db(range_entries: &[(&str, RangeEntry)]) -> ProviderDb {
    let loaded = signatures::load_all(None).expect("embedded signatures must be valid");
    let signatures = loaded.into_iter().map(|l| l.signature).collect();

    let mut ranges = RangeTable::new();
    for (cidr, entry) in range_entries {
        ranges.insert(
            cidr.parse().expect("valid CIDR in test table"),
            entry.clone(),
        );
    }

    ProviderDb { signatures, ranges }
}

fn range_entry(provider_id: &str, layer: Layer, service: Option<&str>) -> RangeEntry {
    RangeEntry {
        provider_id: provider_id.to_string(),
        layer,
        service: service.map(str::to_string),
        region: None,
        source_name: "test".to_string(),
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn detection_for<'a>(
    detections: &'a [Detection],
    provider_id: &str,
    layer: Layer,
) -> Option<&'a Detection> {
    detections
        .iter()
        .find(|d| d.provider_id == provider_id && d.layer == layer)
}

#[test]
fn cloudflare_proxied_site_edge_only_origin_unknown() {
    let db = test_db(&[]);
    let inputs = Inputs {
        headers: vec![("cf-ray".to_string(), "7d3f2-FRA".to_string())],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    let edge = detection_for(&detections, "cloudflare", Layer::Edge).expect("edge detection");
    assert_eq!(edge.confidence, Confidence::Medium);
    assert!(edge
        .evidence
        .iter()
        .any(|e| e.description.contains("cf-ray")));
    // No origin evidence was supplied, so nothing claims the origin layer.
    assert!(detection_for(&detections, "cloudflare", Layer::Origin).is_none());
    assert!(detections.iter().all(|d| d.layer != Layer::Origin));
}

#[test]
fn cloudfront_in_front_of_s3_edge_and_origin_both_aws() {
    let cloudfront_ip = ip("18.160.0.1");
    let s3_ip = ip("52.216.0.1");
    let db = test_db(&[
        (
            "18.160.0.0/16",
            range_entry("aws", Layer::Edge, Some("CLOUDFRONT")),
        ),
        (
            "52.216.0.0/16",
            range_entry("aws", Layer::Origin, Some("S3")),
        ),
    ]);
    let inputs = Inputs {
        ips: vec![cloudfront_ip, s3_ip],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    let edge = detection_for(&detections, "aws", Layer::Edge).expect("edge detection");
    assert_eq!(edge.confidence, Confidence::High);
    assert!(edge
        .evidence
        .iter()
        .any(|e| e.description.contains("CLOUDFRONT")));

    let origin = detection_for(&detections, "aws", Layer::Origin).expect("origin detection");
    assert_eq!(origin.confidence, Confidence::High);
    assert!(origin.evidence.iter().any(|e| e.description.contains("S3")));
}

#[test]
fn azure_app_service_via_cname() {
    let db = test_db(&[]);
    let inputs = Inputs {
        cnames: vec!["myapp.azurewebsites.net".to_string()],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    let origin = detection_for(&detections, "azure", Layer::Origin).expect("origin detection");
    assert_eq!(origin.confidence, Confidence::Medium);
}

#[test]
fn plain_hetzner_vps_asn_only() {
    let db = test_db(&[]);
    let inputs = Inputs {
        ips: vec![ip("88.99.1.1")],
        asns: vec![24940],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    let origin = detection_for(&detections, "hetzner", Layer::Origin).expect("origin detection");
    assert_eq!(origin.confidence, Confidence::High);
    assert_eq!(
        detections.len(),
        1,
        "no other provider should fire on an unrelated ASN"
    );
}

#[test]
fn dns_on_route53_mail_on_microsoft365() {
    let db = test_db(&[]);
    let inputs = Inputs {
        ns: vec![
            "ns-1234.awsdns-56.com".to_string(),
            "ns-5.awsdns-05.net".to_string(),
        ],
        mx: vec!["contoso-com.mail.protection.outlook.com".to_string()],
        spf_includes: vec!["spf.protection.outlook.com".to_string()],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    // Two independent NS records both match the AWS/Route53 pattern (as a
    // real delegation's 4 nameservers would), which is stronger evidence
    // than one alone and pushes this past the High threshold.
    let dns = detection_for(&detections, "aws", Layer::Dns).expect("dns detection");
    assert_eq!(dns.confidence, Confidence::High);

    let mail = detection_for(&detections, "microsoft365", Layer::Mail).expect("mail detection");
    assert_eq!(mail.confidence, Confidence::High);
    assert_eq!(mail.evidence.len(), 2);
}

#[test]
fn ip_with_no_signals_produces_no_detection() {
    let db = test_db(&[(
        "18.160.0.0/16",
        range_entry("aws", Layer::Edge, Some("CLOUDFRONT")),
    )]);
    let inputs = Inputs {
        ips: vec![ip("203.0.113.7")],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    assert!(
        detections.is_empty(),
        "an IP outside every known range/ASN must not produce a guess"
    );
}

#[test]
fn detections_are_sorted_strongest_first() {
    let db = test_db(&[(
        "18.160.0.0/16",
        range_entry("aws", Layer::Edge, Some("CLOUDFRONT")),
    )]);
    let inputs = Inputs {
        ips: vec![ip("18.160.0.1")],
        headers: vec![("cf-ray".to_string(), "x".to_string())],
        ..Default::default()
    };

    let detections = evaluate(&db, &inputs);

    assert!(detections[0].score >= detections[1].score);
    assert_eq!(detections[0].provider_id, "aws"); // range match (100) beats a header match (60)
}
