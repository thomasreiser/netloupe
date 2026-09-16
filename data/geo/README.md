# World map data

What the Geo pane's map (`src/worldmap.rs`) embeds directly via
`include_bytes!`/`include_str!` -- there's no runtime download, unlike
`data/snapshot/`'s provider ranges.

- `coastline_1deg.bin`, `borders_1deg.bin`: a 360x180 (one degree per
  cell) world grid, packed one bit per cell, marking where a coastline or
  a country-border outline crosses that cell. Rasterized from Natural
  Earth's line/polygon vector data -- see `xtask/src/geo.rs` for exactly
  how.
- `cities.csv`: `name,lat,lon,population` for every place in Natural
  Earth's populated-places layer with a usable coordinate, sorted by
  population descending.

Source: [Natural Earth](https://www.naturalearthdata.com/)'s 1:110m
vector data (`ne_110m_coastline`, `ne_110m_admin_0_countries`,
`ne_110m_populated_places`), via its
[GitHub GeoJSON mirror](https://github.com/nvkelso/natural-earth-vector).
Natural Earth data is public domain -- no attribution required, though it
deserves the credit.

Regenerate with:

```
cargo xtask update-geo-data
```
