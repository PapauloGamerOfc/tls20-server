//! Geographic containment uses WGS84 distances, not a planar approximation.
//! Administrative IDs are compared only within their encoded hierarchy; no
//! geographic boundary database is inferred from an untrusted certificate.
use super::{GeographicRegion, IdentifiedRegion, Result, TwoDLocation};
use geographiclib_rs::{Geodesic, InverseGeodesic};
use rasn_its::ieee1609dot2::base_types::*;

const LAT: i64 = 900_000_000;
const LON: i64 = 1_800_000_000;
const MAX_PARTS: usize = 256;
const MAX_CONTAINMENT_WORK: usize = 262144;

fn location(point: &TwoDLocation) -> Result<(i64, i64)> {
    let lat = i64::from(*point.latitude.0);
    let lon = i64::from(*point.longitude.0);
    if !(-LAT..=LAT).contains(&lat) || !(-LON + 1..=LON).contains(&lon) {
        return Err("unknown or invalid ITS geographic coordinate");
    }
    Ok((lat, lon))
}

#[derive(Clone, Copy)]
struct Rectangle {
    south: i64,
    north: i64,
    west: i64,
    east: i64,
}

fn rectangles(values: &SequenceOfRectangularRegion) -> Result<Vec<Rectangle>> {
    if values.0.is_empty() || values.0.len() > MAX_PARTS {
        return Err("ITS rectangle count");
    }
    let mut result = Vec::new();
    for value in &values.0 {
        let (north, west) = location(&value.north_west)?;
        let (south, east) = location(&value.south_east)?;
        if south >= north || west == east {
            return Err("invalid ITS rectangle");
        }
        if west < east {
            result.push(Rectangle {
                south,
                north,
                west,
                east,
            });
        } else {
            // A west longitude numerically greater than east crosses 180°.
            result.push(Rectangle {
                south,
                north,
                west,
                east: LON,
            });
            result.push(Rectangle {
                south,
                north,
                west: -LON,
                east,
            });
        }
    }
    Ok(result)
}

fn covered(child: &Rectangle, parents: &[Rectangle], budget: &mut usize) -> Result<bool> {
    // Sweep every latitude band where coverage can change, then merge longitude
    // intervals. Sampling only four corners would accept holes in a union.
    let mut cuts = vec![child.south, child.north];
    for p in parents {
        for lat in [p.south, p.north] {
            if lat > child.south && lat < child.north {
                cuts.push(lat);
            }
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    for band in cuts.windows(2) {
        *budget = budget
            .checked_sub(parents.len())
            .ok_or("ITS geography work budget exceeded")?;
        let mut intervals = parents
            .iter()
            .filter(|p| p.south <= band[0] && p.north >= band[1])
            .map(|p| (p.west, p.east))
            .collect::<Vec<_>>();
        intervals.sort_unstable();
        let mut edge = child.west;
        for (west, east) in intervals {
            if west > edge {
                break;
            }
            edge = edge.max(east);
        }
        if edge < child.east {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Administrative {
    country: u16,
    region: Option<u8>,
    subregion: Option<u16>,
}

fn administrative(values: &SequenceOfIdentifiedRegion) -> Result<Vec<Administrative>> {
    if values.0.is_empty() || values.0.len() > MAX_PARTS {
        return Err("ITS identified-region count");
    }
    let mut result = Vec::new();
    for value in &values.0 {
        match value {
            IdentifiedRegion::CountryOnly(country) => result.push(Administrative {
                country: country.0,
                region: None,
                subregion: None,
            }),
            IdentifiedRegion::CountryAndRegions(value) => {
                if value.regions.0.is_empty() || value.regions.0.len() > MAX_PARTS {
                    return Err("ITS country-region count");
                }
                for region in &value.regions.0 {
                    result.push(Administrative {
                        country: value.country_only.0,
                        region: Some(*region),
                        subregion: None,
                    });
                }
            }
            IdentifiedRegion::CountryAndSubregions(value) => {
                if value.region_and_subregions.0.is_empty()
                    || value.region_and_subregions.0.len() > MAX_PARTS
                {
                    return Err("ITS subregion group count");
                }
                for region in &value.region_and_subregions.0 {
                    if region.subregions.0.is_empty() || region.subregions.0.len() > MAX_PARTS {
                        return Err("ITS subregion count");
                    }
                    for subregion in &region.subregions.0 {
                        result.push(Administrative {
                            country: value.country_only.0,
                            region: Some(region.region),
                            subregion: Some(*subregion),
                        });
                    }
                }
            }
            _ => return Err("unknown ITS geographic hierarchy"),
        }
        if result.len() > MAX_PARTS {
            return Err("ITS geographic hierarchy size");
        }
    }
    Ok(result)
}

pub(super) fn validate(region: &GeographicRegion) -> Result<()> {
    match region {
        GeographicRegion::CircularRegion(circle) => {
            location(&circle.center)?;
        }
        GeographicRegion::RectangularRegion(values) => {
            rectangles(values)?;
        }
        GeographicRegion::IdentifiedRegion(values) => {
            administrative(values)?;
        }
        GeographicRegion::PolygonalRegion(polygon) => {
            if polygon.0.len() < 3 || polygon.0.len() > MAX_PARTS {
                return Err("ITS polygon vertex count");
            }
            let mut vertices = std::collections::BTreeSet::new();
            for point in &polygon.0 {
                if !vertices.insert(location(point)?) {
                    return Err("duplicate ITS polygon vertex");
                }
            }
            // A locally authenticated geometry authority must still establish
            // geodesic simplicity and containment; syntax is not that proof.
        }
        _ => return Err("unknown ITS geographic region"),
    }
    Ok(())
}

pub(super) fn contains(parent: &GeographicRegion, child: &GeographicRegion) -> Result<bool> {
    validate(parent)?;
    validate(child)?;
    if matches!(parent, GeographicRegion::PolygonalRegion(_))
        || matches!(child, GeographicRegion::PolygonalRegion(_))
    {
        return Err("ITS geometry requires provisioned containment attestation");
    }
    if parent == child {
        return Ok(true);
    }
    match (parent, child) {
        (GeographicRegion::CircularRegion(p), GeographicRegion::CircularRegion(c)) => {
            let (py, px) = location(&p.center)?;
            let (cy, cx) = location(&c.center)?;
            let distance: f64 = Geodesic::wgs84().inverse(
                py as f64 / 1e7,
                px as f64 / 1e7,
                cy as f64 / 1e7,
                cx as f64 / 1e7,
            );
            // The metric triangle inequality proves inclusion for every point,
            // not just sampled compass directions. A micrometre inward margin
            // prevents floating-point roundoff from widening authorization.
            Ok(
                distance.is_finite()
                    && distance + f64::from(c.radius) + 1e-6 <= f64::from(p.radius),
            )
        }
        (GeographicRegion::RectangularRegion(p), GeographicRegion::RectangularRegion(c)) => {
            let parents = rectangles(p)?;
            let mut budget = MAX_CONTAINMENT_WORK;
            for child in rectangles(c)? {
                if !covered(&child, &parents, &mut budget)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (GeographicRegion::IdentifiedRegion(p), GeographicRegion::IdentifiedRegion(c)) => {
            let parents = administrative(p)?;
            Ok(administrative(c)?.iter().all(|c| {
                parents.iter().any(|p| {
                    p.country == c.country
                        && (p.region.is_none() || p.region == c.region)
                        && (p.subregion.is_none() || p.subregion == c.subregion)
                })
            }))
        }
        _ => Err("ITS geometry requires provisioned containment attestation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn point(lat: i32, lon: i32) -> TwoDLocation {
        TwoDLocation {
            latitude: Latitude(NinetyDegreeInt::new(lat).unwrap()),
            longitude: Longitude(OneEightyDegreeInt::new(lon).unwrap()),
        }
    }
    fn rect(n: i32, w: i32, s: i32, e: i32) -> RectangularRegion {
        RectangularRegion {
            north_west: point(n, w),
            south_east: point(s, e),
        }
    }
    fn region(values: Vec<RectangularRegion>) -> GeographicRegion {
        GeographicRegion::RectangularRegion(SequenceOfRectangularRegion(values))
    }
    #[test]
    fn rectangle_union_holes_and_antimeridian() {
        let child = region(vec![rect(100, 0, 0, 100)]);
        let covered = region(vec![rect(100, 0, 0, 50), rect(100, 50, 0, 100)]);
        assert_eq!(contains(&covered, &child), Ok(true));
        let hole = region(vec![rect(100, 0, 60, 100), rect(40, 0, 0, 100)]);
        assert_eq!(contains(&hole, &child), Ok(false));
        let parent = region(vec![rect(100, 1_700_000_000, 0, -1_700_000_000)]);
        let child = region(vec![rect(90, 1_750_000_000, 10, -1_750_000_000)]);
        assert_eq!(contains(&parent, &child), Ok(true));
        assert_eq!(contains(&child, &parent), Ok(false));
        assert!(validate(&region(vec![rect(0, 0, 0, 100)])).is_err());
    }
    #[test]
    fn geodesic_circle_does_not_expand_permission() {
        let circle = |lat, radius| {
            GeographicRegion::CircularRegion(CircularRegion {
                center: point(lat, 0),
                radius,
            })
        };
        assert_eq!(contains(&circle(0, 1000), &circle(1000, 100)), Ok(true));
        assert_eq!(contains(&circle(0, 100), &circle(100_000, 100)), Ok(false));
        assert_eq!(contains(&circle(0, 100), &circle(0, 101)), Ok(false));
        assert_eq!(contains(&circle(0, 0), &circle(0, 0)), Ok(true));
    }
    #[test]
    fn administrative_hierarchy_is_directional() {
        let country = |id| {
            GeographicRegion::IdentifiedRegion(SequenceOfIdentifiedRegion(vec![
                IdentifiedRegion::CountryOnly(UnCountryId(id)),
            ]))
        };
        let state = GeographicRegion::IdentifiedRegion(SequenceOfIdentifiedRegion(vec![
            IdentifiedRegion::CountryAndRegions(CountryAndRegions {
                country_only: UnCountryId(840),
                regions: SequenceOfUint8(vec![6, 12]),
            }),
        ]));
        assert_eq!(contains(&country(840), &state), Ok(true));
        assert_eq!(contains(&state, &country(840)), Ok(false));
        assert_eq!(contains(&country(76), &state), Ok(false));
    }
}
