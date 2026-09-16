# World map data

What the Geo pane's map (`src/worldmap.rs`) embeds directly via
`include_bytes!`/`include_str!` -- there's no runtime download, unlike
`data/snapshot/`'s provider ranges.

- `coastline_0.1deg.bin`, `borders_0.1deg.bin`: a 3600x1800 (one tenth of
  a degree per cell) world grid, packed one bit per cell, marking where a
  coastline or a country-border outline crosses that cell. Rasterized
  from Natural Earth's line/polygon vector data -- see `xtask/src/geo.rs`
  for exactly how. Coarser than this (a 1-degree grid was the original
  choice) made borders in a densely-partitioned region like central
  Europe merge into a solid wash once rasterized.
- `cities.csv`: `name,lat,lon,population` for every place in Natural
  Earth's populated-places layer with a usable coordinate, sorted by
  population descending.

Source: [Natural Earth](https://www.naturalearthdata.com/)'s vector data,
via its
[GitHub GeoJSON mirror](https://github.com/nvkelso/natural-earth-vector):
coastline/borders from the 1:50m ("medium") set
(`ne_50m_coastline`, `ne_50m_admin_0_countries`), cities from the
1:110m set (`ne_110m_populated_places`, since that's specifically the
scale Natural Earth curates down to world-significant places). Natural
Earth data is public domain -- no attribution required, though it
deserves the credit.

Regenerate with:

```
cargo xtask update-geo-data
```
