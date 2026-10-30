import zlib, struct
exec(open('pnglib.py').read())

SRC = '/Users/ja12n0/testrebel/stathe/docs/banner.png'
w, h, ch, rows, pal, color = read(SRC)
px = [bytearray(r) for r in rows]

# 1. Erase the tagline. The background is a radial gradient, so each column is
#    blended between a clean row above and a clean row below rather than filled
#    with one colour -- a flat fill leaves a visible rectangle.
TOP, BOT = 420, 482
above, below = px[TOP-1], px[BOT+1]
for y in range(TOP, BOT+1):
    t = (y-TOP+1)/(BOT-TOP+2)
    row = px[y]
    for x in range(w):
        for c in range(ch):
            i = x*ch+c
            row[i] = round(above[i]*(1-t) + below[i]*t)

# 2. Crop a 4:1 window centred on the wordmark (measured at y 157-346,
#    x 774-1635), so the letters are not moved and the composition still
#    balances with the tagline gone.
CY, CX = (157+346)//2, (774+1635)//2
CH_ = CY*2                      # 502: keeps the glow at the top edge
CW = CH_*4                      # 2008
x0, y0 = CX - CW//2, 0
assert x0 >= 0 and x0+CW <= w and CH_ <= h, (x0, CW, CH_)

# 3. Scale to the LinkedIn size by averaging each source area, which is what
#    keeps the heavy letterforms clean at 79%.
OW, OH = 1584, 396
out = []
for oy in range(OH):
    sy0, sy1 = y0 + oy*CH_//OH, y0 + (oy+1)*CH_//OH
    line = bytearray()
    for ox in range(OW):
        sx0, sx1 = x0 + ox*CW//OW, x0 + (ox+1)*CW//OW
        acc, n = [0]*ch, 0
        for sy in range(sy0, max(sy1, sy0+1)):
            r = px[sy]
            for sx in range(sx0, max(sx1, sx0+1)):
                for c in range(ch):
                    acc[c] += r[sx*ch+c]
                n += 1              # source pixels, not channel reads
        n = max(n, 1)
        line += bytes(min(a//n, 255) for a in acc)
    out.append(bytes(line))

def write(path, width, height, channels, rows):
    ctype = {1:0, 3:2, 4:6}[channels]
    raw = b''.join(b'\x00' + r for r in rows)
    def chunk(t, d):
        c = struct.pack('>I', len(d)) + t + d
        return c + struct.pack('>I', zlib.crc32(t+d) & 0xffffffff)
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, ctype, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(raw, 9))
    png += chunk(b'IEND', b'')
    open(path, 'wb').write(png)

write('cover/stathe-linkedin-profile-from-banner.png', OW, OH, ch, out)
print(f"crop {CW}x{CH_} vanaf ({x0},{y0}) -> {OW}x{OH}")
