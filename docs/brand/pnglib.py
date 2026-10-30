import zlib, struct, sys

def read(path):
    data = open(path,'rb').read()
    assert data[:8] == b'\x89PNG\r\n\x1a\n'
    pos, idat, pal = 8, b'', None
    while pos < len(data):
        ln = struct.unpack('>I', data[pos:pos+4])[0]
        typ = data[pos+4:pos+8]
        body = data[pos+8:pos+8+ln]
        if typ == b'IHDR':
            w,h,depth,color,comp,filt,inter = struct.unpack('>IIBBBBB', body)
        elif typ == b'IDAT':
            idat += body
        elif typ == b'PLTE':
            pal = body
        pos += 12+ln
    assert depth == 8 and inter == 0, (depth, inter)
    channels = {0:1,2:3,3:1,4:2,6:4}[color]
    raw = zlib.decompress(idat)
    stride = w*channels
    out, prev = [], bytearray(stride)
    i = 0
    for y in range(h):
        f = raw[i]; i += 1
        line = bytearray(raw[i:i+stride]); i += stride
        for x in range(stride):
            a = line[x-channels] if x >= channels else 0
            b = prev[x]
            c = prev[x-channels] if x >= channels else 0
            if f == 1: line[x] = (line[x]+a) & 255
            elif f == 2: line[x] = (line[x]+b) & 255
            elif f == 3: line[x] = (line[x]+(a+b)//2) & 255
            elif f == 4:
                p = a+b-c
                pa,pb,pc = abs(p-a),abs(p-b),abs(p-c)
                pr = a if (pa<=pb and pa<=pc) else (b if pb<=pc else c)
                line[x] = (line[x]+pr) & 255
        out.append(bytes(line)); prev = line
    return w,h,channels,out,pal,color


