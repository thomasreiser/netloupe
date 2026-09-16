//! A low-resolution ASCII world map, zoomed to a geolocation with a
//! pinpoint and the nearest major city label(s) visible.
//!
//! Coastline/border data and the city table are pre-downloaded and
//! embedded (see `xtask geo.rs`/`cargo xtask update-geo-data`, and
//! `data/geo/`) rather than fetched at runtime, so this works fully
//! offline like the provider-range snapshot. Everything here is pure and
//! synchronous -- no I/O, no ratatui -- so it's unit-testable on its own;
//! `ui::widgets::worldmap` is the thin layer that turns a `MapGrid` into
//! styled terminal output.

use std::sync::OnceLock;

const GRID_COLS: usize = 360;
const GRID_ROWS: usize = 180;

static COASTLINE_BITS: &[u8] = include_bytes!("../data/geo/coastline_1deg.bin");
static BORDER_BITS: &[u8] = include_bytes!("../data/geo/borders_1deg.bin");
static CITIES_CSV: &str = include_str!("../data/geo/cities.csv");

/// A terminal character is roughly twice as tall as it is wide; without
/// correcting for that a plate carrée projection (equal degrees per row
/// and per column) would render every landmass squashed vertically.
const CHAR_ASPECT: f64 = 2.0;

/// Viewport heights (in degrees of latitude) to try, smallest -- most
/// zoomed in -- first: `render_map` picks the first that manages to fit
/// at least one major city's label, per the "zoom out far enough that a
/// big city name is visible" brief.
const LAT_SPAN_PRESETS: &[f64] = &[10.0, 20.0, 40.0, 70.0, 110.0, 170.0];

/// Below this population a place isn't "a big city" for labeling
/// purposes, even though it's in the (already curated) embedded table.
const MIN_MAJOR_POPULATION: u64 = 1_000_000;

/// At most this many city labels get placed on one map, so a
/// city-dense viewport (western Europe, the US East Coast, ...) doesn't
/// turn into a wall of text.
const MAX_LABELS: usize = 5;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct City {
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub population: u64,
}

/// The embedded major-cities table, parsed once. Sorted by population
/// descending, matching how `cargo xtask update-geo-data` writes it.
pub fn all_cities() -> &'static [City] {
    static CITIES: OnceLock<Vec<City>> = OnceLock::new();
    CITIES.get_or_init(|| {
        csv::Reader::from_reader(CITIES_CSV.as_bytes())
            .deserialize::<City>()
            .filter_map(Result::ok)
            .collect()
    })
}

/// What one map cell shows. Kept as plain semantic values -- not
/// characters or colors -- so this module stays free of any rendering
/// concern; `ui::widgets::worldmap` maps each variant to a glyph/style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    Empty,
    Coast,
    Border,
    Pin,
    CityDot,
    /// One character of a placed city-name label.
    CityLabel(char),
}

pub struct MapGrid {
    pub width: u16,
    pub height: u16,
    cells: Vec<Cell>,
}

impl MapGrid {
    fn blank(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            cells: vec![Cell::Empty; width as usize * height as usize],
        }
    }

    pub fn get(&self, row: u16, col: u16) -> Cell {
        if row >= self.height || col >= self.width {
            return Cell::Empty;
        }
        self.cells[row as usize * self.width as usize + col as usize]
    }

    fn set(&mut self, row: u16, col: u16, cell: Cell) {
        if row < self.height && col < self.width {
            self.cells[row as usize * self.width as usize + col as usize] = cell;
        }
    }
}

/// Renders a map centered on `(target_lat, target_lon)`, picking the
/// tightest of `LAT_SPAN_PRESETS` that fits at least one major city's
/// label; falls back to the widest preset (still a valid map, just
/// without a guaranteed label) if the target is far from every major
/// city in the embedded table.
///
/// Cheap enough to call fresh on every render rather than caching: at
/// most a few hundred grid cells, each a handful of capped bitmap
/// lookups against an ~8KB array, plus a linear scan of ~250 embedded
/// cities -- no unbounded work, nothing that scales with the terminal
/// growing beyond "still fits on a screen".
pub fn render_map(target_lat: f64, target_lon: f64, width: u16, height: u16) -> MapGrid {
    let width = width.max(20);
    let height = height.max(6);
    let mut widest = None;
    for &lat_span in LAT_SPAN_PRESETS {
        let lon_span = viewport_lon_span(lat_span, width, height);
        let (grid, placed_a_city) =
            render_at(target_lat, target_lon, lat_span, lon_span, width, height);
        if placed_a_city {
            return grid;
        }
        widest = Some(grid);
    }
    widest.expect("LAT_SPAN_PRESETS is non-empty, so the loop runs at least once")
}

fn viewport_lon_span(lat_span: f64, width: u16, height: u16) -> f64 {
    lat_span * (width as f64 / height as f64) / CHAR_ASPECT
}

fn render_at(
    target_lat: f64,
    target_lon: f64,
    lat_span: f64,
    lon_span: f64,
    width: u16,
    height: u16,
) -> (MapGrid, bool) {
    let mut grid = MapGrid::blank(width, height);

    for row in 0..height {
        for col in 0..width {
            if cell_hits(
                BORDER_BITS,
                target_lat,
                target_lon,
                lat_span,
                lon_span,
                width,
                height,
                row,
                col,
            ) {
                grid.set(row, col, Cell::Border);
            }
            // Checked second so a cell that's both a coast and (as most
            // coastal country outlines are) a border shows as coast --
            // the more specific, informative fact.
            if cell_hits(
                COASTLINE_BITS,
                target_lat,
                target_lon,
                lat_span,
                lon_span,
                width,
                height,
                row,
                col,
            ) {
                grid.set(row, col, Cell::Coast);
            }
        }
    }

    let pin_cell = project(
        target_lat, target_lon, lat_span, lon_span, width, height, target_lat, target_lon,
    );
    if let Some((row, col)) = pin_cell {
        grid.set(row, col, Cell::Pin);
    }

    // Occupied (row, col_start..col_end) ranges, so a label never
    // overlaps the pin or an earlier label.
    let mut occupied: Vec<(u16, u16, u16)> = Vec::new();
    if let Some((row, col)) = pin_cell {
        occupied.push((row, col, col + 1));
    }

    let mut candidates: Vec<&City> = all_cities()
        .iter()
        .filter(|c| c.population >= MIN_MAJOR_POPULATION)
        .collect();
    candidates.sort_by(|a, b| b.population.cmp(&a.population));

    let mut placed_any = false;
    let mut placed_count = 0;
    for city in candidates {
        if placed_count >= MAX_LABELS {
            break;
        }
        let Some((row, col)) = project(
            target_lat, target_lon, lat_span, lon_span, width, height, city.lat, city.lon,
        ) else {
            continue;
        };
        if Some((row, col)) == pin_cell {
            // Right on top of the pin -- the pin already marks this spot.
            continue;
        }
        if let Some(range) = place_label(&mut grid, &occupied, row, col, width, &city.name) {
            occupied.push(range);
            placed_any = true;
            placed_count += 1;
        }
    }

    (grid, placed_any)
}

/// Tries to place `name` as a label next to `(row, col)`'s dot, first to
/// the right, then to the left, skipping either side that would run off
/// the grid or overlap something already placed. Returns the label's
/// occupied range on success, after marking the dot and label cells.
fn place_label(
    grid: &mut MapGrid,
    occupied: &[(u16, u16, u16)],
    row: u16,
    col: u16,
    width: u16,
    name: &str,
) -> Option<(u16, u16, u16)> {
    let chars: Vec<char> = name.chars().collect();
    let attempts = [
        col as i32 + 2, // " oName" -- one blank cell of separation from the dot
        col as i32 - chars.len() as i32 - 1,
    ];
    for start in attempts {
        if start < 0 {
            continue;
        }
        let end = start + chars.len() as i32;
        if end > width as i32 {
            continue;
        }
        let (start, end) = (start as u16, end as u16);
        let overlaps_dot = start <= col && col < end;
        if overlaps_dot {
            continue;
        }
        let overlaps_existing = occupied
            .iter()
            .any(|&(r, s, e)| r == row && s < end && start < e);
        if overlaps_existing {
            continue;
        }
        grid.set(row, col, Cell::CityDot);
        for (i, &ch) in chars.iter().enumerate() {
            grid.set(row, start + i as u16, Cell::CityLabel(ch));
        }
        return Some((row, start, end));
    }
    None
}

/// Projects `(lat, lon)` onto the `width`x`height` grid centered on
/// `(center_lat, center_lon)` spanning `lat_span`/`lon_span` degrees.
/// `None` if it falls outside the grid.
#[allow(clippy::too_many_arguments)]
fn project(
    center_lat: f64,
    center_lon: f64,
    lat_span: f64,
    lon_span: f64,
    width: u16,
    height: u16,
    lat: f64,
    lon: f64,
) -> Option<(u16, u16)> {
    let dlat = lat - center_lat;
    let dlon = shortest_lon_delta(center_lon, lon);
    let row = height as f64 / 2.0 - (dlat / lat_span) * height as f64;
    let col = width as f64 / 2.0 + (dlon / lon_span) * width as f64;
    if row < 0.0 || col < 0.0 {
        return None;
    }
    let (row, col) = (row as u16, col as u16);
    if row >= height || col >= width {
        return None;
    }
    Some((row, col))
}

/// The signed difference `lon - center_lon`, taking whichever direction
/// around the antimeridian is shorter, so a viewport centered near
/// +/-180 degrees doesn't see everything on "the other side" as maximally
/// far away.
fn shortest_lon_delta(center_lon: f64, lon: f64) -> f64 {
    let mut d = lon - center_lon;
    if d > 180.0 {
        d -= 360.0;
    }
    if d < -180.0 {
        d += 360.0;
    }
    d
}

/// Whether any embedded-grid cell within terminal cell `(row, col)`'s
/// lat/lon footprint has its bit set in `bits`. Handles both a tightly
/// zoomed-in view (footprint smaller than one embedded-grid cell -- just
/// checks the cell it falls in) and a zoomed-out view (footprint spans
/// several embedded-grid cells -- checks all of them) with the same walk,
/// capped so a very wide-open view doesn't oversample unboundedly.
#[allow(clippy::too_many_arguments)]
fn cell_hits(
    bits: &[u8],
    center_lat: f64,
    center_lon: f64,
    lat_span: f64,
    lon_span: f64,
    width: u16,
    height: u16,
    row: u16,
    col: u16,
) -> bool {
    let deg_per_row = lat_span / height as f64;
    let deg_per_col = lon_span / width as f64;
    let lat_top = center_lat + (height as f64 / 2.0 - row as f64) * deg_per_row;
    let lat_bottom = lat_top - deg_per_row;
    let lon_left = center_lon + (col as f64 - width as f64 / 2.0) * deg_per_col;
    let lon_right = lon_left + deg_per_col;

    const MAX_SAMPLES_PER_AXIS: i32 = 6;
    let lat_steps = (deg_per_row.abs().ceil() as i32).clamp(1, MAX_SAMPLES_PER_AXIS);
    let lon_steps = (deg_per_col.abs().ceil() as i32).clamp(1, MAX_SAMPLES_PER_AXIS);

    for i in 0..=lat_steps {
        let lat = lat_bottom + (lat_top - lat_bottom) * (i as f64 / lat_steps as f64);
        for j in 0..=lon_steps {
            let lon = lon_left + (lon_right - lon_left) * (j as f64 / lon_steps as f64);
            if let Some((r, c)) = grid_cell(lat, lon) {
                if bit_set(bits, r, c) {
                    return true;
                }
            }
        }
    }
    false
}

/// Maps `(lat, lon)` to its 1-degree embedded-grid cell. Must match
/// `xtask`'s `geo.rs::grid_cell` exactly, since that's what wrote the
/// bitmaps this reads.
fn grid_cell(lat: f64, lon: f64) -> Option<(usize, usize)> {
    if !(-90.0..=90.0).contains(&lat) {
        return None;
    }
    let row = ((90.0 - lat) as usize).min(GRID_ROWS - 1);
    let col = ((lon + 180.0).rem_euclid(360.0) as usize).min(GRID_COLS - 1);
    Some((row, col))
}

fn bit_set(bits: &[u8], row: usize, col: usize) -> bool {
    let index = row * GRID_COLS + col;
    bits.get(index / 8)
        .map(|b| b & (1 << (index % 8)) != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_cities_include_well_known_major_cities() {
        let names: Vec<&str> = all_cities().iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"Tokyo"), "{names:?}");
        assert!(names.contains(&"Berlin"), "{names:?}");
        assert!(all_cities().len() > 100);
    }

    #[test]
    fn grid_cell_matches_known_points() {
        assert_eq!(grid_cell(89.9, 0.0), Some((0, 180)));
        assert_eq!(grid_cell(0.0, 0.0), Some((90, 180)));
        assert_eq!(grid_cell(0.0, -180.0), Some((90, 0)));
        assert_eq!(grid_cell(0.0, 180.0), Some((90, 0)));
    }

    #[test]
    fn project_places_the_center_point_at_the_grid_center() {
        let (row, col) = project(52.5, 13.4, 20.0, 20.0, 100, 40, 52.5, 13.4).unwrap();
        assert_eq!(row, 20);
        assert_eq!(col, 50);
    }

    #[test]
    fn project_returns_none_outside_the_viewport() {
        assert!(project(0.0, 0.0, 10.0, 10.0, 40, 20, 50.0, 50.0).is_none());
    }

    #[test]
    fn shortest_lon_delta_wraps_around_the_antimeridian() {
        // 170 to -170 is 20 degrees the short way (through the
        // antimeridian), not 340 degrees the long way around.
        assert!((shortest_lon_delta(170.0, -170.0) - 20.0).abs() < 1e-9);
        assert!((shortest_lon_delta(-170.0, 170.0) + 20.0).abs() < 1e-9);
    }

    #[test]
    fn render_map_places_the_pin_at_the_grid_center() {
        let grid = render_map(52.5, 13.4, 100, 40);
        assert_eq!(grid.get(20, 50), Cell::Pin);
    }

    /// Berlin (in the embedded city table) should get a label at some
    /// span at or before the widest preset when centered nearby.
    #[test]
    fn render_map_labels_a_major_city_near_a_populous_region() {
        let grid = render_map(50.0, 10.0, 120, 40);
        let has_label = (0..grid.height)
            .flat_map(|r| (0..grid.width).map(move |c| (r, c)))
            .any(|(r, c)| matches!(grid.get(r, c), Cell::CityLabel(_)));
        assert!(has_label, "expected at least one city label near Europe");
    }

    /// A target far from every major city (mid South Pacific) must still
    /// render a valid, fully-populated grid via the widest fallback
    /// preset, rather than panicking or returning an empty grid.
    #[test]
    fn render_map_falls_back_gracefully_far_from_any_major_city() {
        let grid = render_map(-25.0, -150.0, 100, 40);
        assert_eq!(grid.width, 100);
        assert_eq!(grid.height, 40);
        // The pin must still be placed even with no city label nearby.
        let has_pin = (0..grid.height)
            .flat_map(|r| (0..grid.width).map(move |c| (r, c)))
            .any(|(r, c)| grid.get(r, c) == Cell::Pin);
        assert!(has_pin);
    }

    #[test]
    fn map_grid_get_is_empty_out_of_bounds() {
        let grid = MapGrid::blank(10, 5);
        assert_eq!(grid.get(4, 9), Cell::Empty);
        assert_eq!(grid.get(5, 0), Cell::Empty);
        assert_eq!(grid.get(0, 10), Cell::Empty);
    }

    #[test]
    fn place_label_does_not_overlap_an_already_occupied_range() {
        let mut grid = MapGrid::blank(30, 5);
        let occupied = vec![(2u16, 5u16, 15u16)];
        // Wants to start right after col 3's dot, landing inside the
        // already-occupied 5..15 range on the right, and the left side
        // doesn't have room either (name too long) -- must fail cleanly.
        let result = place_label(&mut grid, &occupied, 2, 3, 30, "AVeryLongCityName");
        assert!(result.is_none());
    }

    #[test]
    fn renders_at_the_minimum_clamped_size_without_panicking() {
        let grid = render_map(0.0, 0.0, 1, 1);
        assert!(grid.width >= 20);
        assert!(grid.height >= 6);
    }
}
