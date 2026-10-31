"""Outline the wordmark in Archivo Black as SVG paths, with the teal square.

    pip install fonttools uharfbuzz brotli
    python docs/brand/wordmark.py ArchivoBlack-Regular.ttf docs/brand/wordmark.svg
    python docs/brand/wordmark.py ArchivoBlack-Regular.ttf docs/brand/mark.svg s

Archivo Black is OFL: https://fonts.google.com/specimen/Archivo+Black. Use the
TTF; harfbuzz does not read woff2.

The spacing and the square are matched to docs/banner.png: tracking -55 font
units, the square 0.38 of the x-height, 0.077 from the "e", lifted 0.03 off the
baseline.
"""
import sys

import uharfbuzz as hb
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

WORD = "#e8eef4"
ACCENT = "#19c7b2"
TRACKING = -55

font_path, out = sys.argv[1], sys.argv[2]
text = sys.argv[3] if len(sys.argv) > 3 else "stathe"

tt = TTFont(font_path)
glyphs = tt.getGlyphSet()
xh = tt["OS/2"].sxHeight

buf = hb.Buffer()
buf.add_str(text)
buf.guess_segment_properties()
hb.shape(hb.Font(hb.Face(hb.Blob.from_file_path(font_path))), buf, {"kern": True})

placed, x = [], 0
for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
    placed.append((tt.getGlyphName(info.codepoint), x))
    x += pos.x_advance + TRACKING

bp = BoundsPen(glyphs)
for name, gx in placed:
    glyphs[name].draw(TransformPen(bp, (1, 0, 0, 1, gx, 0)))
xmin, ymin, xmax, ymax = bp.bounds

sp = SVGPathPen(glyphs)
for name, gx in placed:
    # SVG y runs down, font y runs up: flip around the top of the bounds.
    glyphs[name].draw(TransformPen(sp, (1, 0, 0, -1, gx - xmin, ymax)))

size, gap, lift = 0.38 * xh, 0.077 * xh, 0.03 * xh
sq_x = xmax - xmin + gap
sq_y = ymax - lift - size
width, height = sq_x + size, ymax - min(ymin, 0)

with open(out, "w") as f:
    f.write(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" role="img" aria-label="stathe">\n'
        f'<path fill="{WORD}" d="{sp.getCommands()}"/>\n'
        f'<rect fill="{ACCENT}" x="{sq_x:.0f}" y="{sq_y:.0f}" width="{size:.0f}" height="{size:.0f}"/>\n'
        "</svg>\n"
    )
