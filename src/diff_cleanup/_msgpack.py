"""Minimal MessagePack codec — just enough to round-trip rl-html ``diffData`` blobs.

The rl-html report embeds its diff data as a MessagePack document (see
:mod:`diff_cleanup.html_report`). This project ships no third-party dependencies,
so rather than take one on for one file format, this vendors the small slice of
the spec those blobs use: nil, bool, int, float, str, bin, array, and map.

Encoding chooses the shortest representation for each value, which is always a
valid encoding — the decoder on the other side accepts any. Extension types do
not appear in these reports; meeting one is an error rather than silent
corruption.
"""

import struct


class MsgpackError(ValueError):
    pass


def unpackb(data: bytes) -> object:
    """Decode a single MessagePack value, requiring it to consume all of ``data``."""
    value, offset = _unpack(memoryview(data), 0)
    if offset != len(data):
        raise MsgpackError(f"trailing bytes after value: {len(data) - offset} left")
    return value


def packb(obj: object) -> bytes:
    out = bytearray()
    _pack(obj, out)
    return bytes(out)


# --- decoding ---------------------------------------------------------------


def _unpack(buf: memoryview, i: int) -> tuple[object, int]:
    c = buf[i]
    i += 1
    if c <= 0x7F:  # positive fixint
        return c, i
    if c >= 0xE0:  # negative fixint
        return c - 0x100, i
    if 0xA0 <= c <= 0xBF:  # fixstr
        return _read_str(buf, i, c & 0x1F)
    if 0x90 <= c <= 0x9F:  # fixarray
        return _read_array(buf, i, c & 0x0F)
    if 0x80 <= c <= 0x8F:  # fixmap
        return _read_map(buf, i, c & 0x0F)
    if c == 0xC0:
        return None, i
    if c == 0xC2:
        return False, i
    if c == 0xC3:
        return True, i
    if c == 0xCC:
        return buf[i], i + 1
    if c == 0xCD:
        return _read_uint(buf, i, 2)
    if c == 0xCE:
        return _read_uint(buf, i, 4)
    if c == 0xCF:
        return _read_uint(buf, i, 8)
    if c == 0xD0:
        return _read_int(buf, i, 1)
    if c == 0xD1:
        return _read_int(buf, i, 2)
    if c == 0xD2:
        return _read_int(buf, i, 4)
    if c == 0xD3:
        return _read_int(buf, i, 8)
    if c == 0xCA:
        return struct.unpack_from(">f", buf, i)[0], i + 4
    if c == 0xCB:
        return struct.unpack_from(">d", buf, i)[0], i + 8
    if c == 0xD9:
        return _read_str(buf, i + 1, buf[i])
    if c == 0xDA:
        return _read_str(buf, i + 2, _be(buf, i, 2))
    if c == 0xDB:
        return _read_str(buf, i + 4, _be(buf, i, 4))
    if c == 0xC4:
        return _read_bin(buf, i + 1, buf[i])
    if c == 0xC5:
        return _read_bin(buf, i + 2, _be(buf, i, 2))
    if c == 0xC6:
        return _read_bin(buf, i + 4, _be(buf, i, 4))
    if c == 0xDC:
        return _read_array(buf, i + 2, _be(buf, i, 2))
    if c == 0xDD:
        return _read_array(buf, i + 4, _be(buf, i, 4))
    if c == 0xDE:
        return _read_map(buf, i + 2, _be(buf, i, 2))
    if c == 0xDF:
        return _read_map(buf, i + 4, _be(buf, i, 4))
    raise MsgpackError(f"unsupported msgpack byte {c:#04x} at offset {i - 1}")


def _be(buf: memoryview, i: int, n: int) -> int:
    return int.from_bytes(buf[i : i + n], "big")


def _read_uint(buf: memoryview, i: int, n: int) -> tuple[int, int]:
    return int.from_bytes(buf[i : i + n], "big"), i + n


def _read_int(buf: memoryview, i: int, n: int) -> tuple[int, int]:
    return int.from_bytes(buf[i : i + n], "big", signed=True), i + n


def _read_str(buf: memoryview, i: int, n: int) -> tuple[str, int]:
    # surrogateescape: msgpack str is defined as UTF-8, but some encoders put
    # arbitrary bytes here. Round-tripping via surrogates preserves them exactly
    # (paired with the same option in _pack_str) instead of crashing on decode.
    return bytes(buf[i : i + n]).decode("utf-8", "surrogateescape"), i + n


def _read_bin(buf: memoryview, i: int, n: int) -> tuple[bytes, int]:
    return bytes(buf[i : i + n]), i + n


def _read_array(buf: memoryview, i: int, n: int) -> tuple[list, int]:
    out = []
    for _ in range(n):
        value, i = _unpack(buf, i)
        out.append(value)
    return out, i


def _read_map(buf: memoryview, i: int, n: int) -> tuple[dict, int]:
    out = {}
    for _ in range(n):
        key, i = _unpack(buf, i)
        value, i = _unpack(buf, i)
        out[key] = value
    return out, i


# --- encoding ---------------------------------------------------------------


def _pack(obj: object, out: bytearray) -> None:
    # bool must precede int: bool is a subclass of int.
    if obj is None:
        out.append(0xC0)
    elif obj is True:
        out.append(0xC3)
    elif obj is False:
        out.append(0xC2)
    elif isinstance(obj, int):
        _pack_int(obj, out)
    elif isinstance(obj, float):
        out.append(0xCB)
        out += struct.pack(">d", obj)
    elif isinstance(obj, str):
        _pack_str(obj, out)
    elif isinstance(obj, (bytes, bytearray)):
        _pack_bin(obj, out)
    elif isinstance(obj, (list, tuple)):
        _pack_array(obj, out)
    elif isinstance(obj, dict):
        _pack_map(obj, out)
    else:
        raise MsgpackError(f"cannot encode {type(obj).__name__}")


def _pack_int(n: int, out: bytearray) -> None:
    if 0 <= n <= 0x7F:
        out.append(n)
    elif -0x20 <= n < 0:
        out.append(n & 0xFF)
    elif 0 <= n <= 0xFF:
        out += bytes((0xCC, n))
    elif 0 <= n <= 0xFFFF:
        out.append(0xCD)
        out += n.to_bytes(2, "big")
    elif 0 <= n <= 0xFFFFFFFF:
        out.append(0xCE)
        out += n.to_bytes(4, "big")
    elif 0 <= n <= 0xFFFFFFFFFFFFFFFF:
        out.append(0xCF)
        out += n.to_bytes(8, "big")
    elif -0x80 <= n < 0:
        out.append(0xD0)
        out += n.to_bytes(1, "big", signed=True)
    elif -0x8000 <= n < 0:
        out.append(0xD1)
        out += n.to_bytes(2, "big", signed=True)
    elif -0x80000000 <= n < 0:
        out.append(0xD2)
        out += n.to_bytes(4, "big", signed=True)
    elif -0x8000000000000000 <= n < 0:
        out.append(0xD3)
        out += n.to_bytes(8, "big", signed=True)
    else:
        raise MsgpackError(f"int out of range: {n}")


def _pack_str(s: str, out: bytearray) -> None:
    b = s.encode("utf-8", "surrogateescape")  # mirror _read_str: lossless round-trip
    _pack_len(len(b), out, fix=0xA0, n8=0xD9, n16=0xDA, n32=0xDB, fixmax=0x1F)
    out += b


def _pack_bin(b: bytes | bytearray, out: bytearray) -> None:
    _pack_len(len(b), out, n8=0xC4, n16=0xC5, n32=0xC6)
    out += b


def _pack_array(seq, out: bytearray) -> None:
    _pack_len(len(seq), out, fix=0x90, n16=0xDC, n32=0xDD, fixmax=0x0F)
    for value in seq:
        _pack(value, out)


def _pack_map(mapping: dict, out: bytearray) -> None:
    _pack_len(len(mapping), out, fix=0x80, n16=0xDE, n32=0xDF, fixmax=0x0F)
    for key, value in mapping.items():
        _pack(key, out)
        _pack(value, out)


def _pack_len(
    n: int,
    out: bytearray,
    *,
    fix: int | None = None,
    n8: int | None = None,
    n16: int,
    n32: int,
    fixmax: int = 0,
) -> None:
    if fix is not None and n <= fixmax:
        out.append(fix | n)
    elif n8 is not None and n <= 0xFF:
        out += bytes((n8, n))
    elif n <= 0xFFFF:
        out.append(n16)
        out += n.to_bytes(2, "big")
    elif n <= 0xFFFFFFFF:
        out.append(n32)
        out += n.to_bytes(4, "big")
    else:
        raise MsgpackError(f"length too large to encode: {n}")
