"""Split-face art: cyborg (left) / Anonymous mask (right).

Standalone, truecolor (24-bit) ASCII art rendered with Unicode half-blocks
(``▀``/``▄``/``█``) so each text cell carries two vertical pixels. Nothing here
is imported by the banner yet: run it directly with ``python -m
nexus_core.cli.face`` (or ``--no-color`` for a plain density preview).

The face is defined as pure math so it stays tiny and fast: no external assets
are read and the pixel grid is computed once per call.
"""

from __future__ import annotations

import math
from typing import Iterable

#: Pixel canvas: 100 columns x 48 rows => 100 chars x 24 terminal lines.
WIDTH, HEIGHT = 100, 48
#: Vertical split between the cyborg half and the mask half.
SPLIT = 50

# --- palette (24-bit) -------------------------------------------------------
WHITE = (255, 255, 255)
ELECTRIC = (0, 162, 255)
AQUA = (0, 229, 255)
MASK = (169, 229, 232)
MASK_SHADE = (120, 176, 182)
DARK = (6, 12, 16)
CIRCUIT = (22, 126, 146)
CIRCUIT_HI = (0, 200, 220)

RGB = tuple[int, int, int]

#: Density ramp for the plain (no-color) preview, darkest -> brightest.
_GRAY_RAMP = " .:-=+*#%@"


def _lerp(a: RGB, b: RGB, t: float) -> RGB:
    t = max(0.0, min(1.0, t))
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))  # type: ignore[return-value]


#: Vertical centre and half-height of the head (pixels).
FACE_CY, FACE_RY = 23.0, 21.0
#: Widest half-width of the head (pixels).
FACE_RX = 30.0


def _face_halfwidth(y: int) -> float:
    """Half-width of the head at row ``y`` (egg shape, slightly narrow chin)."""
    t = (y - FACE_CY) / FACE_RY
    if abs(t) > 1.0:
        return -1.0
    half = FACE_RX * math.sqrt(max(0.0, 1.0 - t * t))
    if t > 0.0:
        half *= 1.0 - 0.30 * t  # tapered chin
    return half


def _inside_face(x: int, y: int) -> bool:
    """Egg-shaped silhouette shared by the cyborg and the mask halves."""
    half = _face_halfwidth(y)
    return half > 0.0 and abs(x - 50) <= half


def _cyborg_eye(x: int, y: int) -> RGB | None:
    """Concentric eye glow: white core -> electric blue -> dark rim."""
    radius = math.hypot(x - 34, (y - 22) * 1.15)
    if radius <= 3.0:
        return _lerp(WHITE, ELECTRIC, radius / 3.0)
    if radius <= 10.0:
        return _lerp(ELECTRIC, DARK, (radius - 3.0) / 7.0 * 0.92)
    return None


#: Orthogonal circuit traces (rows and columns) on the dark cyborg half.
_TRACE_ROWS = (9, 17, 30, 38)
_TRACE_COLS = (11, 19, 27, 43)


def _cyborg(x: int, y: int) -> RGB | None:
    eye = _cyborg_eye(x, y)
    if eye is not None:
        return eye
    if not _inside_face(x, y):
        return None
    on_row = y in _TRACE_ROWS and 6 <= x <= SPLIT - 3
    on_col = x in _TRACE_COLS and 4 <= y <= 42
    if on_row and on_col:
        return CIRCUIT_HI  # node where a trace crosses
    if on_row or on_col:
        return CIRCUIT
    if (x + 3 * y) % 19 == 0:  # sparse micro-vias
        return CIRCUIT_HI
    return DARK


def _brow(x: int, y: int, cx: int) -> bool:
    """Arched eye-brow above the right-half eye centred at ``cx``."""
    if abs(x - cx) > 9:
        return False
    # Arch: highest point just inboard of the outer tip.
    top = 15 - int((9 - abs(x - cx)) * 0.6)
    return top <= y <= top + 2


def _mask(x: int, y: int) -> RGB | None:
    if not _inside_face(x, y):
        return None
    for cx in (63, 79):  # eyes
        if ((x - cx) / 5.4) ** 2 + ((y - 20) / 3.8) ** 2 <= 1.0:
            return DARK
        if _brow(x, y, cx):
            return DARK
    if 70 <= x <= 72 and 25 <= y <= 29:  # nose ridge
        return MASK_SHADE
    if 59 <= x <= 83 and 32 <= y <= 33:  # moustache bar
        return DARK
    if x in (59, 60, 82, 83) and 30 <= y <= 33:  # curled ends
        return DARK
    if 62 <= x <= 80:  # smile: centre low, corners high
        smile_y = 40 - int(4.5 * ((x - 71) / 9.0) ** 2)
        if smile_y - 1 <= y <= smile_y:
            return DARK
    # Dithered cheek/jaw shading for volume.
    if (x + y) % 7 == 0 and 13 <= y <= 40:
        return MASK_SHADE
    return MASK


def _pixel(x: int, y: int) -> RGB | None:
    """Color of one pixel, or ``None`` for transparent (terminal background)."""
    if not 0 <= x < WIDTH or not 0 <= y < HEIGHT:
        return None
    return _cyborg(x, y) if x < SPLIT else _mask(x, y)


def _luma(color: RGB) -> float:
    return (0.2126 * color[0] + 0.7152 * color[1] + 0.0722 * color[2]) / 255.0


def _half_block(top: RGB | None, bottom: RGB | None, *, no_color: bool) -> str:
    if no_color:
        if top is None and bottom is None:
            return " "
        samples = [_luma(c) for c in (top, bottom) if c is not None]
        index = int(sum(samples) / len(samples) * (len(_GRAY_RAMP) - 1))
        return _GRAY_RAMP[index]
    if top is None and bottom is None:
        return "\x1b[0m "
    if top is not None and bottom is None:
        return f"\x1b[38;2;{top[0]};{top[1]};{top[2]}m▀"
    if top is None and bottom is not None:
        return f"\x1b[38;2;{bottom[0]};{bottom[1]};{bottom[2]}m▄"
    return (
        f"\x1b[38;2;{top[0]};{top[1]};{top[2]}m"
        f"\x1b[48;2;{bottom[0]};{bottom[1]};{bottom[2]}m▀"
    )


def render_split_face(*, no_color: bool = False) -> str:
    """Return the split face as a newline-joined string.

    ``no_color`` swaps the truecolor half-blocks for a grayscale density ramp
    (a plain-text preview that survives any terminal).
    """
    rows: list[str] = []
    for row in range(HEIGHT // 2):
        cells: list[str] = []
        for x in range(WIDTH):
            top = _pixel(x, row * 2)
            bottom = _pixel(x, row * 2 + 1)
            cells.append(_half_block(top, bottom, no_color=no_color))
        rows.append("".join(cells) + "\x1b[0m")
    return "\n".join(rows)


def render_split_face_lines(*, no_color: bool = False) -> Iterable[str]:
    """Same art, one string per terminal line (for embedders)."""
    return render_split_face(no_color=no_color).splitlines()


def main() -> None:
    import sys

    print(render_split_face(no_color="--no-color" in sys.argv or not sys.stdout.isatty()))


if __name__ == "__main__":  # pragma: no cover - manual preview entry point
    main()
