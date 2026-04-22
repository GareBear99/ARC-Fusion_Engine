"""Planar geometry helpers for small building-scale polygons.

All polygons are lists of ``[lat, lng]`` pairs. Formulas here assume
near-rectangular structures (a few hundred meters at most); don't rely on
them for country-scale shapes where Earth's curvature matters significantly.
For distance the module switches to haversine (``distance_meters``).
"""
from __future__ import annotations
from math import atan2, cos, radians, sin, sqrt


def centroid(polygon: list[list[float]]) -> dict[str, float]:
    """Return the arithmetic centroid ``{lat, lng}`` of a polygon's vertices.

    This is not area-weighted — good enough for small convex-ish footprints,
    not correct for large or highly non-convex shapes.
    """
    lat = sum(p[0] for p in polygon) / len(polygon)
    lng = sum(p[1] for p in polygon) / len(polygon)
    return {"lat": lat, "lng": lng}


def bounds_from_polygon(poly: list[list[float]]) -> dict[str, float]:
    """Return the axis-aligned bounding box ``{minLat, maxLat, minLng, maxLng}``."""
    lats = [p[0] for p in poly]
    lngs = [p[1] for p in poly]
    return {
        "minLat": min(lats),
        "maxLat": max(lats),
        "minLng": min(lngs),
        "maxLng": max(lngs),
    }


def point_in_polygon(point: dict[str, float], polygon: list[list[float]]) -> bool:
    """Test whether ``point`` lies inside ``polygon`` via ray-casting.

    Classic even-odd rule. Edge cases (point exactly on a vertex / edge) are
    not specially handled — results on the boundary are implementation-
    defined. The ``1e-12`` guard avoids division-by-zero when two vertices
    share a latitude.
    """
    x = point["lng"]
    y = point["lat"]
    inside = False
    for i in range(len(polygon)):
        j = (i - 1) % len(polygon)
        xi, yi = polygon[i][1], polygon[i][0]
        xj, yj = polygon[j][1], polygon[j][0]
        denom = (yj - yi) if (yj - yi) != 0 else 1e-12
        intersect = ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / denom + xi)
        if intersect:
            inside = not inside
    return inside


def clamp_point_to_bounds(point: dict[str, float], bounds: dict[str, float]) -> dict[str, float]:
    """Return ``point`` snapped to lie within ``bounds`` (box-clamped, not polygon-clamped)."""
    return {
        "lat": min(bounds["maxLat"], max(bounds["minLat"], point["lat"])),
        "lng": min(bounds["maxLng"], max(bounds["minLng"], point["lng"])),
    }


def seeded(seed: float) -> float:
    """Deterministic 0..1 pseudo-random sampler from a float seed.

    Equivalent to ``(sin(seed)*10000) mod 1``. Not cryptographic — its only
    job is to reproducibly place sensors inside structure polygons so
    ``build_sensors_for_structure`` is idempotent.
    """
    x = sin(seed) * 10000
    return x - int(x)


def seeded_point_in_polygon(polygon: list[list[float]], seed_value: float = 1.0) -> dict[str, float]:
    """Return a deterministic in-polygon point for a given ``seed_value``.

    Tries up to 300 bounding-box samples driven by ``seeded()``; returns the
    first one that lies inside the polygon via ``point_in_polygon``. Falls
    back to ``centroid(polygon)`` if no in-polygon sample is found (which is
    rare for realistic footprints but possible for pathological concave
    shapes).
    """
    bounds = bounds_from_polygon(polygon)
    for idx in range(300):
        r1 = seeded(seed_value + idx * 2.17)
        r2 = seeded(seed_value + idx * 3.41 + 9.2)
        candidate = {
            "lat": bounds["minLat"] + (bounds["maxLat"] - bounds["minLat"]) * r1,
            "lng": bounds["minLng"] + (bounds["maxLng"] - bounds["minLng"]) * r2,
        }
        if point_in_polygon(candidate, polygon):
            return candidate
    return centroid(polygon)


def distance_meters(a: dict[str, float], b: dict[str, float]) -> float:
    """Return the great-circle distance in meters between two ``{lat, lng}`` points.

    Haversine formula using ``earth_radius = 6_371_000``. Used by the RF
    estimator's synthetic forward model (``rssi_from_distance_meters``).
    """
    earth_radius = 6_371_000
    d_lat = radians(b["lat"] - a["lat"])
    d_lng = radians(b["lng"] - a["lng"])
    lat1 = radians(a["lat"])
    lat2 = radians(b["lat"])
    hav = sin(d_lat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(d_lng / 2) ** 2
    return 2 * earth_radius * atan2(sqrt(hav), sqrt(1 - hav))
