"""P4 original PNG lighting response, source-byte diagnostic only.

Recompute corresponding *pixels* rather than trusting average luminance,
producer tags or file hashes. This does not authenticate an external renderer
or prove physically correct shading; never promote these diagnostics to MG0.
"""
import math

from visual_content_metrics import decode_grid, VisualContentBlocked


def original_pixels(raw):
    if type(raw) is not bytes:
        return None
    try:
        width, height, grid = decode_grid(raw, step=1)
    except (VisualContentBlocked, ValueError, TypeError):
        return None
    if width < 2 or height < 2 or len(grid) != width * height:
        return None
    return width, height, grid


def neutral_pixel_qa(raw, *, min_luma=70, max_luma=200,
                     max_chroma=10, required_fraction=0.95):
    """Reject chromatic/checkerboard casts hidden by a neutral RGB *mean*."""
    sample = original_pixels(raw)
    if sample is None:
        return False
    _, _, grid = sample
    valid = 0
    for pixel in grid:
        luma = sum(pixel[:3]) / 3.0
        if (min_luma <= luma <= max_luma and
                max(pixel[:3]) - min(pixel[:3]) <= max_chroma):
            valid += 1
    return valid / len(grid) >= required_fraction


def pixel_light_response(reference, changed, *, direction,
                         minimum_delta=1, required_fraction=0.75):
    """Check registered same-size PNG pixels for a consistent light response.

    direction=1: direct light brighter; -1: shadow darker;
    direction=0: different capture (nonzero per-pixel RGB response).
    One different SHA or a shifted *average* alone is insufficient.
    """
    if direction not in (-1, 0, 1) or not (
            type(minimum_delta) in (int, float) and
            math.isfinite(minimum_delta) and minimum_delta > 0):
        return False
    a, b = original_pixels(reference), original_pixels(changed)
    if a is None or b is None or a[:2] != b[:2]:
        return False
    good = inverse = 0
    for x, y in zip(a[2], b[2]):
        d = (sum(y[:3]) - sum(x[:3])) / 3.0
        if direction == 0:
            good += max(abs(y[k]-x[k]) for k in range(3)) >= minimum_delta
        else:
            good += direction*d >= minimum_delta
            inverse += direction*d < -minimum_delta
    count = len(a[2])
    return good / count >= required_fraction and (
        direction == 0 or inverse / count <= 0.1)


def player_camera_horizontal_alignment(position, forward, native):
    """Project an original camera ray to the front of actual GLB XY bounds.

    This is a geometric *preflight*, not a FiveM player-view certification:
    source GLB floor planes may have zero vertical extent.
    """
    if not (type(position) is list and type(forward) is list and
            len(position) == len(forward) == 3 and type(native) is dict):
        return False
    if not all(type(x) in (int, float) and math.isfinite(x)
               for x in position + forward):
        return False
    low, high = native.get('bbox_min'), native.get('bbox_max')
    if not (type(low) in (tuple, list) and type(high) in (tuple, list)
            and len(low) >= 2 and len(high) >= 2 and
            all(type(x) in (int, float) and math.isfinite(x)
                for x in list(low[:2]) + list(high[:2]))):
        return False
    if forward[1] <= 1e-6 or position[1] >= low[1]:
        return False
    distance = (low[1] - position[1]) / forward[1]
    hit_x = position[0] + distance * forward[0]
    return low[0] - 0.05 <= hit_x <= high[0] + 0.05
