"""RF-based position estimation.

ARC-Core's geolocation model is deliberately simple: a weighted centroid
of sensor positions where the weight grows exponentially with RSSI. This
works well enough for building-interior anchor meshes and keeps the math
transparent for operators. See ``docs/ARCHITECTURE.md`` §9.2 for the
derivation.

For real deployments with high-quality calibration, swap in a multilateration
or particle-filter estimator and keep this signature.
"""
from __future__ import annotations
from arc.geo.geometry import (
    bounds_from_polygon,
    clamp_point_to_bounds,
    distance_meters,
    point_in_polygon,
)


def rssi_from_distance_meters(meters: float, noise_db: float = 2.5) -> float:
    """Synthetic forward RSSI model: RSSI(dBm) from distance(meters).

    ``rssi = -30 - (32 + 20*log10(d))`` — a classic log-distance path-loss
    model with TX=-30 dBm and a hardcoded path-loss exponent of 2.0. The
    ``noise_db`` argument is currently a no-op (coefficient is 0) but is
    kept for forward-compatibility with a jitter-injection variant. Used
    only by ``make_observations`` to generate demo RF traces; real
    observations come in directly from calibrated sensors.
    """
    d = max(1.0, meters)
    path_loss = 32 + 20 * __import__("math").log10(d)
    tx = -30.0
    return tx - path_loss + noise_db * 0.0


def estimate_from_observations(observations: list[dict], structure: dict | None = None) -> dict | None:
    """Estimate a position from multiple sensor observations.

    For each observation, compute ``weight = max(0.0001, 10^((rssi+100)/12)) *
    max(0.2, reliability)`` — exponential in RSSI, linear in reliability.
    Then take the weighted mean of sensor lat/lng to get the point. If a
    ``structure`` polygon is supplied and the estimate lands outside it,
    box-clamp to the structure's bounds.

    Confidence is a linear combination of (a) how much the top observation
    dominates the second-strongest (spread/22) and (b) average sensor
    reliability (avg_rel*0.25), offset +0.32 and clamped to ``[0.15, 0.99]``.

    Returns ``None`` for empty input, otherwise a dict with ``point``,
    ``confidence``, ``method="weighted-rssi-centroid"``, and ``sensor_count``.
    """
    if not observations:
        return None
    sum_w = 0.0
    lat = 0.0
    lng = 0.0
    for obs in observations:
        reliability = float(obs.get("reliability", 1.0))
        rssi = float(obs["rssi"])
        weight = max(0.0001, pow(10, (rssi + 100.0) / 12.0)) * max(0.2, reliability)
        sum_w += weight
        lat += float(obs["sensor_lat"]) * weight
        lng += float(obs["sensor_lng"]) * weight
    point = {"lat": lat / sum_w, "lng": lng / sum_w}
    if structure:
        polygon = structure["polygon"] if isinstance(structure["polygon"], list) else structure.get("polygon")
        if polygon and not point_in_polygon(point, polygon):
            point = clamp_point_to_bounds(point, bounds_from_polygon(polygon))
    sorted_obs = sorted(observations, key=lambda o: o["rssi"], reverse=True)
    spread = abs(sorted_obs[0]["rssi"] - sorted_obs[1]["rssi"]) if len(sorted_obs) >= 2 else 0.0
    avg_rel = sum(float(o.get("reliability", 1.0)) for o in observations) / len(observations)
    confidence = max(0.15, min(0.99, 0.32 + spread / 22.0 + avg_rel * 0.25))
    return {
        "point": point,
        "confidence": round(confidence, 4),
        "method": "weighted-rssi-centroid",
        "sensor_count": len(observations),
    }


def make_observations(truth: dict[str, float], sensors: list[dict], noise_db: float = 2.5) -> list[dict]:
    """Synthesize sensor observations for a known ground-truth position.

    Used by ``generate_demo_track``: for each sensor, compute the haversine
    distance to ``truth`` and convert to RSSI via
    ``rssi_from_distance_meters``. This lets the demo exercise the full
    estimator pipeline without real RF hardware.
    """
    out = []
    for sensor in sensors:
        out.append(
            {
                "sensor_id": sensor["sensor_id"],
                "sensor_lat": sensor["lat"],
                "sensor_lng": sensor["lng"],
                "rssi": round(rssi_from_distance_meters(distance_meters(truth, sensor), noise_db=noise_db), 2),
                "reliability": sensor.get("reliability", 1.0),
            }
        )
    return out
