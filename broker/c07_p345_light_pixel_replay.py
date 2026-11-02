"""P4 original PNG lighting response, source-byte diagnostic only.

Recompute corresponding *pixels* rather than trusting average luminance,
producer tags or file hashes. This does not authenticate an external renderer
or prove physically correct shading; never promote these diagnostics to MG0.
"""
import math
import zlib

from visual_content_metrics import decode_grid, VisualContentBlocked


def original_alpha_grid(raw):
    """Decode original per-pixel alpha, retaining invisible surface information.

    The shared PNG decoder deliberately returns RGB only. An RGBA capture with
    zero alpha can therefore fabricate any apparent neutral/direct/shadow
    response using completely invisible RGB values. Validate the original
    CRC-checked bytes, then reconstruct each RGBA alpha scanline (all five
    PNG filters). This applies to QA screenshots, never to asset textures
    where transparency is intentional. Source evidence is NOT renderer proof.
    """
    if type(raw) is not bytes:
        return None
    try:
        width, height, pixels = decode_grid(raw, step=1)
        if len(pixels) != width * height or raw[12:16] != b'IHDR':
            return None
        color = raw[25]
        if color == 2:
            return width, height, [255] * (width * height)
        if color != 6:
            return None
        offset, parts = 8, []
        while offset < len(raw):
            length = int.from_bytes(raw[offset:offset+4], 'big')
            kind = raw[offset+4:offset+8]
            if kind == b'IDAT':
                parts.append(raw[offset+8:offset+8+length])
            offset += length + 12
        expected = height * (width * 4 + 1)
        decoder = zlib.decompressobj()
        expanded = bytearray()
        for part in parts:
            expanded.extend(decoder.decompress(
                part, expected + 1 - len(expanded)))
            if len(expanded) > expected or decoder.unconsumed_tail:
                return None
        expanded.extend(decoder.flush(expected + 1 - len(expanded)))
        if (len(expanded) != expected or not decoder.eof or
                decoder.unused_data):
            return None
        cursor, previous, pitch = 0, [0] * width, width * 4
        alpha_grid = []
        for _ in range(height):
            mode = expanded[cursor]
            cursor += 1
            if mode > 4:
                return None
            current = []
            for x in range(width):
                left = current[x-1] if x else 0
                up = previous[x]
                corner = previous[x-1] if x else 0
                if mode == 0:
                    predictor = 0
                elif mode == 1:
                    predictor = left
                elif mode == 2:
                    predictor = up
                elif mode == 3:
                    predictor = (left + up) // 2
                else:
                    p = left + up - corner
                    da, db, dc = abs(p-left), abs(p-up), abs(p-corner)
                    predictor = (left if da <= db and da <= dc else
                                 up if db <= dc else corner)
                alpha = (expanded[cursor + 4*x + 3] + predictor) & 255
                current.append(alpha)
            cursor += pitch
            previous = current
            alpha_grid.extend(current)
        return (width, height, alpha_grid) if cursor == len(expanded) else None
    except (VisualContentBlocked, ValueError, TypeError, IndexError,
            zlib.error):
        return None



def opaque_capture_png(raw):
    """Require real opaque QA screenshot pixels, not invisible RGBA RGB."""
    sample = original_alpha_grid(raw)
    return sample is not None and all(alpha == 255 for alpha in sample[2])

def original_pixels(raw):
    if not opaque_capture_png(raw):
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


def triplet_light_response(neutral, direct, shadow, *,
                           min_direct_delta=5, min_shadow_delta=5,
                           required_fraction=0.75):
    """Recompute *coincident* original pixels under three light conditions.

    Separate average/75%-each comparisons can pass when the bright and dark
    regions are disjoint. This requires the SAME spatial pixels to respond in
    both directions. It is source QA only, not renderer or FiveM provenance.
    """
    values = [original_pixels(raw) for raw in (neutral, direct, shadow)]
    if (any(v is None for v in values) or
            len({v[:2] for v in values}) != 1 or
            not all(type(x) in (int, float) and math.isfinite(x) and x>0
                    for x in (min_direct_delta, min_shadow_delta)) or
            type(required_fraction) not in (int, float) or
            not math.isfinite(required_fraction) or
            not 0 < required_fraction <= 1):
        return False
    n, d, s = (v[2] for v in values)
    correct = inverse = 0
    for pn, pd, ps in zip(n, d, s):
        rise = (sum(pd[:3]) - sum(pn[:3])) / 3.0
        fall = (sum(pn[:3]) - sum(ps[:3])) / 3.0
        correct += rise >= min_direct_delta and fall >= min_shadow_delta
        inverse += rise < -min_direct_delta or fall < -min_shadow_delta
    return correct / len(n) >= required_fraction and inverse / len(n) <= 0.1


def lod_view_color_distance(near, far, max_channel_delta):
    """Check original near/far raster continuity against a pre-D bound.

    Image alignment/capture authenticity still require separate evidence.
    """
    a, b = original_pixels(near), original_pixels(far)
    if (a is None or b is None or a[:2] != b[:2] or
            type(max_channel_delta) not in (int, float) or
            not math.isfinite(max_channel_delta) or
            not 0 <= max_channel_delta <= 255):
        return False
    return all(max(abs(x[k]-y[k]) for k in range(3)) <= max_channel_delta
               for x,y in zip(a[2],b[2]))


def frame_samples_within_budget(samples, target):
    """Original frame observations: both mean and nearest-rank P95 must fit.

    A single severe stutter must not disappear behind a passing mean.
    Authentic in-game provenance is NOT established by numeric samples.
    """
    if (type(samples) is not list or len(samples)<10 or
            type(target) not in (int,float) or
            not math.isfinite(target) or not 0<target<10000 or
            not all(type(v) in (int,float) and math.isfinite(v)
                    and 0<v<10000 for v in samples)):
        return False
    ordered=sorted(samples)
    p95=ordered[math.ceil(0.95*len(ordered))-1]
    return sum(ordered)/len(ordered)<=target and p95<=target


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
