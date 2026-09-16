//! Regenerates `data/geo/`: a low-resolution world coastline/border
//! bitmap pair plus a major-cities table, all bundled into the binary
//! (see `netloupe::worldmap`) so the Geo pane's map works with zero
//! network access at runtime -- the same "ship a snapshot, refresh it
//! with an xtask command" shape as `data/snapshot/`'s provider ranges.
//!
//! Source: Natural Earth's 1:110m public-domain vector data (the scale
//! Natural Earth itself curates for small/low-res world maps), via its
//! GitHub GeoJSON mirror. Rasterized onto a 1-degree-per-cell grid --
//! deliberately coarse, matching the low-resolution/data-saving ask this
//! feeds: 360x180 cells packed one bit each is ~8KB per bitmap, plenty
//! fine for a map that only ever renders onto a terminal pane.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

const GRID_COLS: usize = 360;
const GRID_ROWS: usize = 180;

const COASTLINE_URL: &str = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_coastline.geojson";
const COUNTRIES_URL: &str = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson";
const PLACES_URL: &str = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_populated_places.geojson";

/// Natural Earth's 110m populated-places layer is already curated down to
/// ~243 places significant at world-map scale; this just drops the
/// handful with missing/negligible population data rather than imposing
/// a second opinion on top of Natural Earth's own curation.
const MIN_CITY_POPULATION: i64 = 1;

pub fn update_geo_data(repo_root: &Path) -> Result<()> {
    let geo_dir = repo_root.join("data/geo");
    fs::create_dir_all(&geo_dir)?;

    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!(
            "netloupe-xtask/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/thomasreiser/netloupe)"
        ))
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    print!("fetching coastline ... ");
    let coastline = fetch_json(&client, COASTLINE_URL)?;
    let mut coast_bits = Bitmap::new();
    for feature in features(&coastline) {
        for line in line_strings(&feature["geometry"]) {
            rasterize_line(&line, &mut coast_bits);
        }
    }
    println!("{} cells", coast_bits.count());
    fs::write(geo_dir.join("coastline_1deg.bin"), coast_bits.into_bytes())
        .context("writing coastline_1deg.bin")?;

    print!("fetching country borders ... ");
    let countries = fetch_json(&client, COUNTRIES_URL)?;
    let mut border_bits = Bitmap::new();
    for feature in features(&countries) {
        for ring in polygon_rings(&feature["geometry"]) {
            rasterize_line(&ring, &mut border_bits);
        }
    }
    println!("{} cells", border_bits.count());
    fs::write(geo_dir.join("borders_1deg.bin"), border_bits.into_bytes())
        .context("writing borders_1deg.bin")?;

    print!("fetching populated places ... ");
    let places = fetch_json(&client, PLACES_URL)?;
    let mut rows: Vec<(String, f64, f64, i64)> = Vec::new();
    for feature in features(&places) {
        let props = &feature["properties"];
        let name = props["NAME"].as_str().unwrap_or_default().trim();
        let lat = props["LATITUDE"].as_f64();
        let lon = props["LONGITUDE"].as_f64();
        let pop = props["POP_MAX"].as_i64().unwrap_or(0);
        let (Some(lat), Some(lon)) = (lat, lon) else {
            continue;
        };
        if name.is_empty() || pop < MIN_CITY_POPULATION {
            continue;
        }
        rows.push((name.to_string(), lat, lon, pop));
    }
    rows.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)));

    let mut writer = csv::Writer::from_path(geo_dir.join("cities.csv"))
        .context("opening data/geo/cities.csv for writing")?;
    writer.write_record(["name", "lat", "lon", "population"])?;
    for (name, lat, lon, pop) in &rows {
        writer.write_record([
            name.as_str(),
            &format!("{lat:.4}"),
            &format!("{lon:.4}"),
            &pop.to_string(),
        ])?;
    }
    writer.flush()?;
    println!("{} cities", rows.len());

    Ok(())
}

fn fetch_json(client: &reqwest::blocking::Client, url: &str) -> Result<Value> {
    client
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching {url}"))?
        .json()
        .with_context(|| format!("parsing JSON from {url}"))
}

fn features(doc: &Value) -> &[Value] {
    doc.get("features")
        .and_then(|f| f.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn coords_1d(v: &Value) -> Vec<(f64, f64)> {
    v.as_array()
        .map(|pts| {
            pts.iter()
                .filter_map(|p| {
                    let arr = p.as_array()?;
                    Some((arr.first()?.as_f64()?, arr.get(1)?.as_f64()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `LineString`/`MultiLineString` -> one `(lon, lat)` polyline per line.
fn line_strings(geometry: &Value) -> Vec<Vec<(f64, f64)>> {
    match geometry.get("type").and_then(|t| t.as_str()) {
        Some("LineString") => vec![coords_1d(
            geometry.get("coordinates").unwrap_or(&Value::Null),
        )],
        Some("MultiLineString") => geometry
            .get("coordinates")
            .and_then(|c| c.as_array())
            .map(|lines| lines.iter().map(coords_1d).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// `Polygon`/`MultiPolygon` -> one `(lon, lat)` closed ring per exterior
/// and hole, across every polygon -- rasterized the same way as a line,
/// which draws the outline without needing a fill/point-in-polygon
/// algorithm at all.
fn polygon_rings(geometry: &Value) -> Vec<Vec<(f64, f64)>> {
    match geometry.get("type").and_then(|t| t.as_str()) {
        Some("Polygon") => geometry
            .get("coordinates")
            .and_then(|c| c.as_array())
            .map(|rings| rings.iter().map(coords_1d).collect())
            .unwrap_or_default(),
        Some("MultiPolygon") => geometry
            .get("coordinates")
            .and_then(|c| c.as_array())
            .map(|polys| {
                polys
                    .iter()
                    .filter_map(|p| p.as_array())
                    .flat_map(|rings| rings.iter().map(coords_1d))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// A packed one-degree-per-cell world grid, `GRID_ROWS` (latitude, north
/// to south) x `GRID_COLS` (longitude, -180 to +180) cells, one bit each.
struct Bitmap {
    bytes: Vec<u8>,
}

impl Bitmap {
    fn new() -> Self {
        Self {
            bytes: vec![0u8; (GRID_ROWS * GRID_COLS).div_ceil(8)],
        }
    }

    fn set(&mut self, row: usize, col: usize) {
        let index = row * GRID_COLS + col;
        self.bytes[index / 8] |= 1 << (index % 8);
    }

    fn count(&self) -> usize {
        self.bytes.iter().map(|b| b.count_ones() as usize).sum()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Maps a (lat, lon) to its 1-degree grid cell, matching
/// `netloupe::worldmap`'s lookup exactly (row 0 = the cell just south of
/// the north pole, col 0 = the cell just east of the antimeridian).
fn grid_cell(lat: f64, lon: f64) -> Option<(usize, usize)> {
    if !(-90.0..=90.0).contains(&lat) {
        return None;
    }
    let row = ((90.0 - lat) as usize).min(GRID_ROWS - 1);
    let col = ((lon + 180.0).rem_euclid(360.0) as usize).min(GRID_COLS - 1);
    Some((row, col))
}

/// Walks every point along a polyline (already just vertices, at 110m
/// simplification), plus enough interpolated points between each pair
/// that no grid cell along the way gets skipped, marking every cell it
/// touches.
fn rasterize_line(points: &[(f64, f64)], bitmap: &mut Bitmap) {
    for pair in points.windows(2) {
        rasterize_segment(pair[0], pair[1], bitmap);
    }
    // A single-point "line" (degenerate input) still marks its own cell.
    if points.len() == 1 {
        if let Some((row, col)) = grid_cell(points[0].1, points[0].0) {
            bitmap.set(row, col);
        }
    }
}

fn rasterize_segment(a: (f64, f64), b: (f64, f64), bitmap: &mut Bitmap) {
    // Step finely enough (a fraction of a degree) that a long segment
    // can't hop over a grid cell it actually crosses.
    let steps = ((a.0 - b.0).abs().max((a.1 - b.1).abs()) / 0.4)
        .ceil()
        .max(1.0) as usize;
    for i in 0..=steps {
        let t = i as f64 / steps as f64;
        let lon = a.0 + (b.0 - a.0) * t;
        let lat = a.1 + (b.1 - a.1) * t;
        if let Some((row, col)) = grid_cell(lat, lon) {
            bitmap.set(row, col);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_cell_maps_known_points_to_the_expected_cell() {
        // The north pole side, prime meridian/equator crossing.
        assert_eq!(grid_cell(89.9, 0.0), Some((0, 180)));
        assert_eq!(grid_cell(0.0, 0.0), Some((90, 180)));
        // The antimeridian wraps rather than going out of bounds.
        assert_eq!(grid_cell(0.0, -180.0), Some((90, 0)));
        assert_eq!(grid_cell(0.0, 180.0), Some((90, 0)));
    }

    #[test]
    fn rasterize_segment_marks_both_endpoints_and_the_cells_between() {
        let mut bitmap = Bitmap::new();
        rasterize_segment((0.0, 0.0), (5.0, 0.0), &mut bitmap);
        for lon in 0..=5 {
            let (row, col) = grid_cell(0.0, lon as f64).unwrap();
            let index = row * GRID_COLS + col;
            assert!(
                bitmap.bytes[index / 8] & (1 << (index % 8)) != 0,
                "expected cell at lon={lon} to be set"
            );
        }
    }

    #[test]
    fn coords_1d_parses_a_linestring_coordinate_array() {
        let v: Value = serde_json::json!([[1.0, 2.0], [3.0, 4.0]]);
        assert_eq!(coords_1d(&v), vec![(1.0, 2.0), (3.0, 4.0)]);
    }

    #[test]
    fn line_strings_handles_both_line_and_multiline_geometries() {
        let line: Value =
            serde_json::json!({"type": "LineString", "coordinates": [[0.0, 0.0], [1.0, 1.0]]});
        assert_eq!(line_strings(&line).len(), 1);

        let multi: Value = serde_json::json!({"type": "MultiLineString", "coordinates": [[[0.0, 0.0]], [[1.0, 1.0]]]});
        assert_eq!(line_strings(&multi).len(), 2);
    }

    #[test]
    fn polygon_rings_handles_both_polygon_and_multipolygon_geometries() {
        let polygon: Value = serde_json::json!({
            "type": "Polygon",
            "coordinates": [[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]]]
        });
        assert_eq!(polygon_rings(&polygon).len(), 1);

        let multi: Value = serde_json::json!({
            "type": "MultiPolygon",
            "coordinates": [
                [[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]]],
                [[[10.0, 10.0], [11.0, 10.0], [11.0, 11.0], [10.0, 10.0]]]
            ]
        });
        assert_eq!(polygon_rings(&multi).len(), 2);
    }
}
