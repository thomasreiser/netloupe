//! Geo pane: country/region/city, timezone, org, and connection-type hints
//! from user-supplied GeoLite2 databases.
//!
//! MaxMind's GeoLite2 `.mmdb` files aren't redistributable, so this check
//! only works when the user has pointed `[geoip]` at their own copies (see
//! `config.rs`); otherwise it reports that plainly instead of guessing.

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

        let city_db = ctx.config.geoip.city_db.clone();
        let asn_db = ctx.config.geoip.asn_db.clone();

        if city_db.is_none() && asn_db.is_none() {
            result.errors.push(
                "no GeoLite2 database configured (set [geoip].city_db / asn_db in config.toml)"
                    .to_string(),
            );
            return Ok(CheckUpdate::Geo(result));
        }

        if let Some(path) = city_db {
            match lookup_city(path, ip).await {
                Ok(Some(fields)) => apply_city_fields(&mut result, fields),
                Ok(None) => result
                    .errors
                    .push("IP not found in the City database".to_string()),
                Err(err) => result.errors.push(format!("City database: {err}")),
            }
        }

        if let Some(path) = asn_db {
            match lookup_asn_org(path, ip).await {
                Ok(Some(org)) => result.asn_org = Some(org),
                Ok(None) => result
                    .errors
                    .push("IP not found in the ASN database".to_string()),
                Err(err) => result.errors.push(format!("ASN database: {err}")),
            }
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
    timezone: Option<String>,
}

fn apply_city_fields(result: &mut GeoResult, fields: CityFields) {
    result.country = fields.country;
    result.country_code = fields.country_code;
    result.region = fields.region;
    result.city = fields.city;
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
