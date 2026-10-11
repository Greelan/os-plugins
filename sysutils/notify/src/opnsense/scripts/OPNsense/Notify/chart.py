"""
Copyright (C) 2026 Greelan
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

--

Plain charts as PNG for summaries sent by email, in pure Python: OPNsense's rrdtool
is built without graphics, and the plugin carries no compiled imaging library. The
background is transparent, so a chart suits a light or a dark page.
"""

import bisect
import datetime
import itertools
import math
import operator
import struct
import zlib


GRAPH_SIZE = (720, 180)  # the report's column
PIE_SIZE = 150
PIE_COLORS = ("#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f", "#edc948", "#b07aa1", "#9c755f")
PIE_OTHER = "#bab0ac"
# gray at part opacity, visible on light and dark: (premultiplied gray, alpha)
GRID = (38, 77)
MARK = (58, 115)
# share of the color in a filled area: outlined, or on its own (shaded more, so it still reads)
SHADE = 0.35
AREA_SHADE = 0.4


def day_marks(first, last):
    """Midnights along the period as fractions; Mondays only beyond about a week."""
    if last <= first:
        return []
    moment = datetime.datetime.fromtimestamp(first).replace(hour=0, minute=0, second=0, microsecond=0)
    marks: list = []
    while True:
        moment += datetime.timedelta(days=1)
        stamp = moment.timestamp()
        if stamp >= last:
            return marks
        if last - first <= 8 * 86400 or moment.weekday() == 0:
            marks.append((stamp - first) / (last - first))


def chart_png(series, marks, scale=2, top=None):
    """A line chart as PNG: series of (values, color, filled[, outlined]), None being a gap; a filled
    one is outlined unless told otherwise. The top edge is top, else a tenth above the highest value.
    Drawn at scale and averaged down to smooth edges."""
    width, height = GRAPH_SIZE
    w, h = width * scale, height * scale
    # a plane per channel, column after column, so a column is one slice; colors are
    # premultiplied by alpha, so averaging down stays right at the edges
    planes = [bytearray(w * h) for _ in range(4)]

    def dot(x, y, rgba):
        if 0 <= x < w and 0 <= y < h:
            for k in range(4):
                planes[k][x * h + y] = rgba[k]

    top = top or max([v for values, *_ in series for v in values if v is not None] + [0]) * 1.1 or 1
    for step in range(1, 4):
        y = h - 1 - round(step / 4 * (h - 1))
        for x in range(0, w, 2 * scale):
            for dx in range(scale):
                dot(x + dx, y, (GRID[0],) * 3 + (GRID[1],))
    for mark in marks:
        x = round(mark * (w - 1))
        if 0 <= x < w:
            for k in range(4):
                planes[k][x * h:(x + 1) * h] = bytes([MARK[k == 3]]) * h
    for values, color, filled, *style in series:
        outlined = not filled or not style or style[0]
        shade = SHADE if outlined else AREA_SHADE
        rgb = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5)) + (255,)
        count = len(values)
        ys = [None if v is None else h - 1 - round(v / top * (h - 1)) for v in values]
        if count < 2:
            continue
        if filled:
            # a fixed blend maps each byte to one other
            tables = [bytes(round(v * (1 - shade) + rgb[k] * shade) for v in range(256)) for k in range(4)]
            for x in range(w):
                at = x / (w - 1) * (count - 1)
                i = min(int(at), count - 2)
                here, after = ys[i], ys[i + 1]
                if here is None or after is None:
                    continue
                start = x * h + min(max(round(here + (after - here) * (at - i)), 0), h)
                end = (x + 1) * h
                for k in range(4):
                    planes[k][start:end] = planes[k][start:end].translate(tables[k])
        for i in range(count - 1 if outlined else 0):
            y0, y1 = ys[i], ys[i + 1]
            if y0 is None or y1 is None:
                continue
            x0, x1 = round(i / (count - 1) * (w - 1)), round((i + 1) / (count - 1) * (w - 1))
            steps = max(abs(x1 - x0), abs(y1 - y0), 1)
            for n in range(steps + 1):
                x, y = round(x0 + (x1 - x0) * n / steps), round(y0 + (y1 - y0) * n / steps)
                for dx in range(scale):
                    for dy in range(scale):
                        dot(x + dx, y + dy, rgb)
    out = [bytearray(width * height) for _ in range(4)]
    blocks = itertools.repeat(scale * scale)
    for k in range(4):
        plane = planes[k]
        tall: list = list(plane[0::scale])
        for dy in range(1, scale):
            tall = list(map(operator.add, tall, plane[dy::scale]))
        for x in range(width):
            at = x * scale * height
            column = tall[at:at + height]
            for dx in range(1, scale):
                at += height
                column = list(map(operator.add, column, tall[at:at + height]))
            out[k][x::width] = bytes(map(operator.floordiv, column, blocks))
    return png(width, height, rgba(out))


def straight(color, alpha):
    return (color * 255 + alpha // 2) // alpha if alpha else 0


def rgba(planes):
    """Premultiplied color planes and alpha, row after row, as straight RGBA pixels."""
    alpha = planes[3]
    out = bytearray(len(alpha) * 4)
    for k in range(3):
        out[k::4] = bytes(map(straight, planes[k], alpha))
    out[3::4] = alpha
    return out


def png(width, height, pixels):
    """RGBA pixels, row after row, as a PNG file."""
    raw = b"".join(b"\x00" + bytes(pixels[y * width * 4:(y + 1) * width * 4]) for y in range(height))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def donut_png(slices, size=PIE_SIZE, scale=2):
    """A donut chart as PNG of (value, color) slices, clockwise from the top."""
    big = size * scale
    middle = (big - 1) / 2
    outer, total = big / 2 - 1, sum(value for value, _ in slices) or 1
    inner = outer * 0.58
    ends, colors, turn = [], [], 0.0
    for value, color in slices:
        turn += value / total * 2 * math.pi
        ends.append(turn)
        colors.append(bytes(int(color[i:i + 2], 16) for i in (1, 3, 5)) + b"\xff")
    rows = []
    for y in range(big):
        row = bytearray(big * 4)
        dy = y - middle
        if abs(dy) <= outer:
            reach = math.sqrt(outer * outer - dy * dy)
            for x in range(math.ceil(middle - reach), math.floor(middle + reach) + 1):
                dx = x - middle
                if dx * dx + dy * dy < inner * inner:
                    continue
                angle = math.atan2(dx, -dy) % (2 * math.pi)
                row[x * 4:x * 4 + 4] = colors[min(bisect.bisect_left(ends, angle), len(colors) - 1)]
        rows.append(row)
    # opaque on transparent, so the colors are already premultiplied
    out = [bytearray(size * size) for _ in range(4)]
    blocks = itertools.repeat(scale * scale)
    for y in range(size):
        summed = list(rows[y * scale])
        for dy in range(1, scale):
            summed = list(map(operator.add, summed, rows[y * scale + dy]))
        for k in range(4):
            column = list(summed[k::4 * scale])
            for dx in range(1, scale):
                column = list(map(operator.add, column, summed[k + 4 * dx::4 * scale]))
            out[k][y * size:(y + 1) * size] = bytes(map(operator.floordiv, column, blocks))
    return png(size, size, rgba(out))
