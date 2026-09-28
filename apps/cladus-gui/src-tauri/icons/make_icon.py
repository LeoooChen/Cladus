"""Renders the Cladus icon (a lineage tree) as PNG and ICO without dependencies.

Run from this directory: python make_icon.py
"""
import math
import struct
import zlib

BG = (15, 118, 110)       # teal
FG = (255, 255, 255)
SEGMENTS = [((128, 206), (128, 142)), ((128, 142), (78, 82)), ((128, 142), (128, 62)), ((128, 142), (178, 82))]
NODES = [((128, 206), 20), ((78, 78), 19), ((128, 58), 19), ((178, 78), 19)]
STROKE = 9  # half width


def seg_dist(p, a, b):
    ax, ay = a; bx, by = b; px, py = p
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def inside_bg(x, y, r=56):
    # Rounded square covering 8..248.
    lo, hi = 8, 248
    cx = min(max(x, lo + r), hi - r)
    cy = min(max(y, lo + r), hi - r)
    return math.hypot(x - cx, y - cy) <= r


def fg_at(x, y):
    return any(seg_dist((x, y), a, b) <= STROKE for a, b in SEGMENTS) or any(
        math.hypot(x - cx, y - cy) <= r for (cx, cy), r in NODES)


def render(size):
    ss = 4
    rows = []
    for py in range(size):
        row = bytearray([0])
        for px in range(size):
            bg = fg = 0
            for sy in range(ss):
                for sx in range(ss):
                    x = (px + (sx + 0.5) / ss) * 256 / size
                    y = (py + (sy + 0.5) / ss) * 256 / size
                    if inside_bg(x, y):
                        bg += 1
                        if fg_at(x, y):
                            fg += 1
            n = ss * ss
            a = bg / n
            f = fg / bg if bg else 0
            rgb = [round(BG[i] * (1 - f) + FG[i] * f) for i in range(3)]
            row += bytes(rgb + [round(a * 255)])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


sizes = [16, 24, 32, 48, 64, 128, 256]
pngs = {s: render(s) for s in sizes}
with open("icon.ico", "wb") as f:
    f.write(struct.pack("<HHH", 0, 1, len(sizes)))
    offset = 6 + 16 * len(sizes)
    for s in sizes:
        f.write(struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(pngs[s]), offset))
        offset += len(pngs[s])
    for s in sizes:
        f.write(pngs[s])
for s, name in [(32, "32x32.png"), (128, "128x128.png"), (256, "icon.png")]:
    open(name, "wb").write(pngs[s])
