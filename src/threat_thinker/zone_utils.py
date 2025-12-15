"""
Utilities for working with zones and nested trust boundaries.
"""

from typing import Dict, Iterable, List, Optional, Sequence

from threat_thinker.models import Zone


def _rect_contains(a: Dict[str, float], b: Dict[str, float]) -> bool:
    """Return True if rectangle a fully contains rectangle b."""
    return (
        a["x"] <= b["x"]
        and a["y"] <= b["y"]
        and a["x"] + a["width"] >= b["x"] + b["width"]
        and a["y"] + a["height"] >= b["y"] + b["height"]
    )


def _rect_contains_point(rect: Dict[str, float], x: float, y: float) -> bool:
    """Return True if a point is inside (or on the boundary of) rect."""
    return (
        rect["x"] <= x <= rect["x"] + rect["width"]
        and rect["y"] <= y <= rect["y"] + rect["height"]
    )


def _area(rect: Dict[str, float]) -> float:
    return float(rect["width"]) * float(rect["height"])


def compute_zone_tree_from_rectangles(
    rects: Sequence[Dict[str, float]],
) -> Dict[str, Zone]:
    """
    Build Zone objects from rectangles by inferring parent-child relationships.

    The parent of a rectangle is the smallest-area rectangle that fully contains it.
    """
    zones: Dict[str, Zone] = {}
    sorted_rects = sorted(rects, key=_area)
    for rect in sorted_rects:
        parent_id = None
        parent_area = None
        for candidate in sorted_rects:
            if candidate["id"] == rect["id"]:
                continue
            if not _rect_contains(candidate, rect):
                continue
            cand_area = _area(candidate)
            if parent_area is None or cand_area < parent_area:
                parent_id = candidate["id"]
                parent_area = cand_area
        zones[rect["id"]] = Zone(
            id=str(rect["id"]),
            name=str(rect.get("name") or rect["id"]),
            parent_id=parent_id,
        )
    return zones


def zone_depth(
    zone_id: str, zones: Dict[str, Zone], cache: Optional[Dict[str, int]] = None
) -> int:
    """Compute depth of a zone within a zone forest (root depth = 0)."""
    cache = cache or {}
    if zone_id in cache:
        return cache[zone_id]
    z = zones.get(zone_id)
    if not z or not z.parent_id or z.parent_id == zone_id:
        cache[zone_id] = 0
        return 0
    depth = 1 + zone_depth(z.parent_id, zones, cache)
    cache[zone_id] = depth
    return depth


def sort_zone_ids_by_hierarchy(
    zone_ids: Iterable[str], zones: Dict[str, Zone]
) -> List[str]:
    """Return unique zone ids sorted outer -> inner using the zone tree."""
    seen = set()
    cache: Dict[str, int] = {}
    unique_ids: List[str] = []
    for zid in zone_ids:
        if zid is None or zid in seen:
            continue
        seen.add(zid)
        unique_ids.append(zid)
    unique_ids.sort(key=lambda z: zone_depth(z, zones, cache))
    return unique_ids


def zone_path_names(zone_ids: Iterable[str], zones: Dict[str, Zone]) -> List[str]:
    """Convert a zone id path to human-friendly names, preserving outer->inner order."""
    ordered = sort_zone_ids_by_hierarchy(zone_ids, zones)
    names: List[str] = []
    for zid in ordered:
        zone = zones.get(zid)
        names.append(zone.name if zone else str(zid))
    return names


def representative_zone_name(
    zone_ids: Iterable[str], zones: Dict[str, Zone]
) -> Optional[str]:
    """
    Return the deepest (most inner) zone name for compatibility with legacy single-zone fields.
    """
    ordered = sort_zone_ids_by_hierarchy(zone_ids, zones)
    if not ordered:
        return None
    inner_id = ordered[-1]
    inner_zone = zones.get(inner_id)
    return inner_zone.name if inner_zone else str(inner_id)


def containing_zone_ids_for_point(
    x: float, y: float, rects: Sequence[Dict[str, float]], zones: Dict[str, Zone]
) -> List[str]:
    """
    Return ordered zone ids (outer->inner) that contain a given point.
    """
    candidates = [rect["id"] for rect in rects if _rect_contains_point(rect, x, y)]
    return sort_zone_ids_by_hierarchy(candidates, zones)
