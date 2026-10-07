"""Bounded PNG content measurement; adapted from the existing renderer probe."""
import struct
import zlib

def decode_png(data: bytes) -> tuple[int, int, int, bytes]:
    """(width, height, channels, raw rows) for a non-interlaced 8-bit RGB/RGBA PNG. adb screencap is exactly that."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    if len(data) > 32 * 1024 * 1024:
        raise ValueError("PNG compressed byte limit exceeded")
    pos = 8
    width = height = depth = ctype = interlace = None
    idat = b""
    while pos < len(data):
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        if pos + 12 + length > len(data):
            raise ValueError("truncated PNG chunk")
        body = data[pos + 8:pos + 8 + length]
        crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        if crc != zlib.crc32(kind + body) & 0xFFFFFFFF:
            raise ValueError("PNG CRC mismatch")
        pos += 12 + length
        if kind == b"IHDR":
            width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
    if width is None or depth != 8 or ctype not in (2, 6) or interlace != 0:
        raise ValueError(f"unsupported PNG (depth={depth}, colour type={ctype}, interlace={interlace})")
    channels = 3 if ctype == 2 else 4
    if not (0 < width <= 8192 and 0 < height <= 8192) or width * height > 16000000:
        raise ValueError("PNG dimension limit exceeded")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(idat, height * (width * channels + 1) + 1)
    if not decoder.eof or decoder.unused_data:
        raise ValueError("PNG compressed stream invalid or exceeds expected dimensions")
    stride = width * channels
    if len(raw) != height * (stride + 1):
        raise ValueError("truncated PNG")
    rows = bytearray()
    prev = bytearray(stride)
    for y in range(height):
        base = y * (stride + 1)
        ftype = raw[base]
        row = bytearray(raw[base + 1:base + 1 + stride])
        for i in range(stride):
            a = row[i - channels] if i >= channels else 0
            b = prev[i]
            c = prev[i - channels] if i >= channels else 0
            if ftype == 1:
                row[i] = (row[i] + a) & 255
            elif ftype == 2:
                row[i] = (row[i] + b) & 255
            elif ftype == 3:
                row[i] = (row[i] + ((a + b) >> 1)) & 255
            elif ftype == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                row[i] = (row[i] + pred) & 255
            elif ftype != 0:
                raise ValueError(f"bad PNG filter {ftype}")
        rows += row
        prev = row
    return width, height, channels, bytes(rows)


def measure_pixels(data: bytes) -> dict[str, float]:
    """Sampled (every 3rd pixel each way) so a 1080x1920 frame costs a fraction of a second."""
    width, height, ch, rows = decode_png(data)
    lit = magenta = cyan = samples = 0
    colours: dict[tuple[int, int, int], int] = {}
    for y in range(0, height, 3):
        base = y * width * ch
        for x in range(0, width, 3):
            i = base + x * ch
            r, g, b = rows[i], rows[i + 1], rows[i + 2]
            samples += 1
            if max(r, g, b) > 16:
                lit += 1
            if r > 200 and g < 60 and b > 200:
                magenta += 1
            elif r < 60 and g > 200 and b > 200:
                cyan += 1
            key = (r >> 4, g >> 4, b >> 4)
            colours[key] = colours.get(key, 0) + 1
    return {"width": width, "height": height, "lit": lit / samples, "magenta": magenta / samples,
            "cyan": cyan / samples, "flat": max(colours.values()) / samples}
