"""
Generate tray icon images using Pillow (no external image files needed).
Returns PIL Image objects.
"""
from PIL import Image, ImageDraw, ImageFont


def _draw_shield(draw: ImageDraw.ImageDraw, size: int, fill: str, outline: str):
    """Draw a shield shape."""
    s = size
    p = s * 0.08
    points = [
        (p, p),              # top-left
        (s - p, p),          # top-right
        (s - p, s * 0.55),   # right-mid
        (s / 2, s - p),      # bottom tip
        (p, s * 0.55),       # left-mid
    ]
    draw.polygon(points, fill=fill, outline=outline)


def make_icon(state: str = "normal", size: int = 64) -> Image.Image:
    """
    Create a tray icon image.
    state: "normal" (green shield), "alert" (red), "warning" (yellow), "inactive" (gray)
    """
    colors = {
        "normal":   ("#27ae60", "#1e8449"),
        "alert":    ("#e74c3c", "#b03a2e"),
        "warning":  ("#f39c12", "#d68910"),
        "inactive": ("#555577", "#44446a"),
    }
    fill, outline = colors.get(state, colors["normal"])

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    _draw_shield(draw, size, fill, outline)

    # Symbol in center of shield
    cx = size / 2
    cy = size * 0.42
    r = size * 0.13

    if state == "normal":
        # Checkmark
        lw = max(2, size // 16)
        draw.line(
            [(cx - r, cy), (cx - r * 0.2, cy + r * 0.8), (cx + r, cy - r)],
            fill="white", width=lw
        )
    elif state == "alert":
        # X
        lw = max(2, size // 16)
        draw.line([(cx - r, cy - r), (cx + r, cy + r)], fill="white", width=lw)
        draw.line([(cx + r, cy - r), (cx - r, cy + r)], fill="white", width=lw)
    elif state == "warning":
        # Exclamation mark
        lw = max(2, size // 18)
        draw.rectangle(
            [cx - lw, cy - r, cx + lw, cy + r * 0.35],
            fill="white"
        )
        dot_r = max(1, size // 20)
        draw.ellipse(
            [cx - dot_r, cy + r * 0.55, cx + dot_r, cy + r],
            fill="white"
        )
    else:
        # Shield with dash (inactive/paused)
        lw = max(2, size // 16)
        draw.line([(cx - r, cy), (cx + r, cy)], fill="white", width=lw)

    return img


def make_all_icons(size: int = 64) -> dict[str, Image.Image]:
    return {state: make_icon(state, size)
            for state in ("normal", "alert", "warning", "inactive")}
