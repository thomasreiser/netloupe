//! Geo pane: country/region/city, timezone, org, and connection-type hints
//! from the GeoLite2 City/ASN databases.
//!
//! `crate::geoip`'s background updater is the only thing that ever
//! downloads these (into `crate::geoip::cache_dir()`, once MaxMind
//! credentials are configured); this check only ever reads whatever's
//! there right now and reports plainly when nothing is, rather than
//! guessing or triggering a download itself.

use std::net::IpAddr;
use std::path::PathBuf;

use maxminddb::geoip2;
use tokio::sync::mpsc;

use super::CheckContext;
use crate::event::{CheckEvent, CheckUpdate};

#[derive(Debug, Clone, Default)]
pub struct GeoResult {
    pub ip: Option<IpAddr>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    /// Present whenever the City database found a record at all, even if
    /// its `city`/`region` fields are blank -- this is what the Geo
    /// pane's world map zooms to, so it must not depend on how much
    /// other detail the database happened to have for this address.
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub timezone: Option<String>,
    pub asn_org: Option<String>,
    pub accuracy_hint: Option<&'static str>,
    pub errors: Vec<String>,
}

pub(crate) async fn run(ctx: CheckContext, tx: mpsc::Sender<CheckEvent>) {
    let id = super::CheckId::Geo;
    super::run_guarded(&ctx, id, &tx, async {
        let ip = super::resolve_target_ip(&ctx).await?;
        let mut result = GeoResult {
            ip: Some(ip),
            ..Default::default()
        };

        // A private/loopback/link-local/etc. address was never assigned to
        // a real-world location by a registry, so a GeoLite2 lookup would
        // either miss (reported as a plain "not found", which reads like a
        // data gap) or — worse — land on whatever default entry the
        // database happens to have for reserved space. Skip it and say why.
        let class = crate::checks::ipinfo::classify(ip);
        if !class.is_global() {
            result.errors.push(format!(
                "{ip} is a {} address — it has no real-world geolocation",
                class.label()
            ));
            return Ok(CheckUpdate::Geo(result));
        }

        let Some(cache_dir) = crate::geoip::cache_dir() else {
            result.errors.push(
                "could not determine a cache directory for GeoLite2 databases on this platform"
                    .to_string(),
            );
            return Ok(CheckUpdate::Geo(result));
        };
        let city_path = crate::geoip::city_db_path(&cache_dir);
        let asn_path = crate::geoip::asn_db_path(&cache_dir);
        let city_present = city_path.is_file();
        let asn_present = asn_path.is_file();

        if !city_present && !asn_present {
            result.errors.push(if ctx.config.geoip.credentials().is_some() {
                "GeoLite2 databases not downloaded yet -- see the GeoIP status in the bottom-right corner".to_string()
            } else {
                "GeoLite2 not configured -- set a MaxMind account ID and license key (press 's' for the settings editor)".to_string()
            });
            return Ok(CheckUpdate::Geo(result));
        }

        if city_present {
            match lookup_city(city_path, ip).await {
                Ok(Some(fields)) => apply_city_fields(&mut result, fields),
                Ok(None) => result
                    .errors
                    .push("IP not found in the City database".to_string()),
                Err(err) => result.errors.push(format!("City database: {err}")),
            }
        } else {
            result
                .errors
                .push("City database not downloaded yet".to_string());
        }

        if asn_present {
            match lookup_asn_org(asn_path, ip).await {
                Ok(Some(org)) => result.asn_org = Some(org),
                Ok(None) => result
                    .errors
                    .push("IP not found in the ASN database".to_string()),
                Err(err) => result.errors.push(format!("ASN database: {err}")),
            }
        } else {
            result
                .errors
                .push("ASN database not downloaded yet".to_string());
        }

        Ok(CheckUpdate::Geo(result))
    })
    .await;
}

/// Fields pulled out of a `geoip2::City` record, decoupled from the
/// borrowed lifetime of the underlying reader so they can outlive the
/// `spawn_blocking` call that produced them.
struct CityFields {
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
}

fn apply_city_fields(result: &mut GeoResult, fields: CityFields) {
    result.country = fields.country;
    result.country_code = fields.country_code;
    result.region = fields.region;
    result.city = fields.city;
    result.lat = fields.lat;
    result.lon = fields.lon;
    result.timezone = fields.timezone;
    result.accuracy_hint =
        Some("city-level, as reported by the database; actual accuracy varies by region");
}

async fn lookup_city(path: PathBuf, ip: IpAddr) -> Result<Option<CityFields>, String> {
    tokio::task::spawn_blocking(move || {
        let reader = maxminddb::Reader::open_readfile(&path).map_err(|e| e.to_string())?;
        let result = reader.lookup(ip).map_err(|e| e.to_string())?;
        let Some(city) = result.decode::<geoip2::City>().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        Ok(Some(CityFields {
            country: city.country.names.english.map(str::to_string),
            country_code: city.country.iso_code.map(str::to_string),
            region: city
                .subdivisions
                .first()
                .and_then(|s| s.names.english)
                .map(str::to_string),
            city: city.city.names.english.map(str::to_string),
            lat: city.location.latitude,
            lon: city.location.longitude,
            timezone: city.location.time_zone.map(str::to_string),
        }))
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn lookup_asn_org(path: PathBuf, ip: IpAddr) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || {
        let reader = maxminddb::Reader::open_readfile(&path).map_err(|e| e.to_string())?;
        let result = reader.lookup(ip).map_err(|e| e.to_string())?;
        let Some(asn) = result.decode::<geoip2::Asn>().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        Ok(asn.autonomous_system_organization.map(str::to_string))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::checks::{CheckContext, SharedResultsHandle};
    use crate::config::Config;
    use crate::event::CheckPayload;
    use crate::providers::ProviderDb;
    use crate::target::Target;

    /// A private-address target must skip the GeoLite2 lookups entirely
    /// (there's nothing meaningful to look up) and say why, rather than
    /// reporting a bare "not found" that reads like a data gap.
    #[tokio::test]
    async fn skips_the_lookup_for_a_private_address() {
        let ctx = CheckContext {
            tab_id: 0,
            target: Target::Ip("192.168.1.1".parse().unwrap()),
            port: None,
            config: Arc::new(Config::default()),
            cancel: CancellationToken::new(),
            shared: SharedResultsHandle::new(),
            providers: Arc::new(ProviderDb::default()),
            resolver: None,
            ping_paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let (tx, mut rx) = mpsc::channel(8);
        run(ctx, tx).await;

        let mut done = None;
        while let Some(event) = rx.recv().await {
            if let CheckPayload::Done(CheckUpdate::Geo(geo)) = event.payload {
                done = Some(geo);
                break;
            }
        }
        let geo = done.expect("geo check must report Done even when it skips the lookup");

        assert!(geo.country.is_none());
        assert_eq!(geo.errors.len(), 1);
        assert!(
            geo.errors[0].contains("private"),
            "expected the error to name the address class: {:?}",
            geo.errors[0]
        );
    }
}
