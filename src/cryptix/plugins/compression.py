"""Compression formats. Decompression is bounded to defeat decompression bombs."""

from __future__ import annotations

import bz2
import lzma
import zlib

from cryptix.core.magic import is_zlib_header
from cryptix.core.plugin import (
    Category, Codec, Cost, DataKind, Detection, Example, Param, ParamType, PluginInfo,
)  # fmt: skip
from cryptix.errors import DecodeError

MAX_OUTPUT_DEFAULT = 64 * 1024 * 1024
_STRICT = Param("strict", ParamType.BOOL, False, "Reject trailing garbage after the stream.")
_MAX = Param("max_output", ParamType.INT, MAX_OUTPUT_DEFAULT, "Abort if output exceeds this many bytes.")
_LEVEL = Param("level", ParamType.INT, 9, "Compression level (1-9).")


def _check(out: bytes, limit: int) -> bytes:
    if len(out) > limit:
        raise DecodeError(f"decompressed output exceeds the {limit}-byte limit (raise max_output)")
    return out


def _zlib_family(data: bytes, wbits: int, strict: bool, limit: int) -> bytes:
    out = bytearray()
    rest = data
    while True:
        d = zlib.decompressobj(wbits)
        chunk = d.decompress(rest, limit - len(out) + 1)
        out += chunk
        _check(bytes(out), limit)
        if not d.eof:
            raise DecodeError("compressed stream is truncated or incomplete")
        rest = d.unused_data
        if wbits == 31 and rest.startswith(b"\x1f\x8b"):  # multi-member gzip
            continue
        break
    if rest and strict:
        raise DecodeError(f"{len(rest)} bytes of trailing data after the compressed stream")
    return bytes(out)


class Zlib(Codec):
    info = PluginInfo(
        name="zlib", category=Category.COMPRESSION,
        description="zlib stream (RFC 1950: 2-byte header, DEFLATE, Adler-32).",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(_STRICT, _MAX, _LEVEL), cost=Cost.CHEAP, auto_safe=True,
        detection_notes="Valid RFC 1950 header (CM=8, checksum % 31 == 0).",
        examples=(Example(bytes.fromhex("789cf348cdc9c90700058c01f5"), b"Hello", {"level": 6}),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, max_output: int, level: int) -> bytes:
        return zlib.compress(data, level)

    def _decode(self, data: bytes, strict: bool, max_output: int, level: int = 9) -> bytes:
        return _zlib_family(data, zlib.MAX_WBITS, strict, max_output)

    def detect(self, data: bytes) -> Detection | None:
        return Detection(0.8, "valid zlib header") if is_zlib_header(data) else None


class Gzip(Codec):
    info = PluginInfo(
        name="gzip", aliases=("gz",), category=Category.COMPRESSION,
        description="gzip (RFC 1952), multi-member aware. Encoding writes mtime=0 for reproducible output.",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(_STRICT, _MAX, _LEVEL), cost=Cost.CHEAP, auto_safe=True,
        detection_notes="Magic bytes 1f 8b 08.",
        examples=(Example(bytes.fromhex("1f8b0800000000000003f348cdc9c907008289d1f705000000"), b"Hello", {"level": 6}),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, max_output: int, level: int) -> bytes:
        c = zlib.compressobj(level, zlib.DEFLATED, 31)
        return c.compress(data) + c.flush()

    def _decode(self, data: bytes, strict: bool, max_output: int, level: int = 9) -> bytes:
        return _zlib_family(data, 31, strict, max_output)

    def detect(self, data: bytes) -> Detection | None:
        return Detection(0.95, "gzip magic 1f 8b 08") if data[:3] == b"\x1f\x8b\x08" else None


class Deflate(Codec):
    info = PluginInfo(
        name="deflate", aliases=("raw-deflate",), category=Category.COMPRESSION,
        description="Raw DEFLATE (RFC 1951) with no zlib/gzip framing.",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(_STRICT, _MAX, _LEVEL), cost=Cost.CHEAP, auto_safe=False,
        detection_notes="No magic bytes: cannot be detected structurally, so never auto-tried.",
        examples=(Example(bytes.fromhex("f348cdc9c90700"), b"Hello", {"level": 6}),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, max_output: int, level: int) -> bytes:
        c = zlib.compressobj(level, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()

    def _decode(self, data: bytes, strict: bool, max_output: int, level: int = 9) -> bytes:
        return _zlib_family(data, -15, strict, max_output)


class Bzip2(Codec):
    info = PluginInfo(
        name="bzip2", aliases=("bz2",), category=Category.COMPRESSION,
        description="bzip2 stream.",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(_STRICT, _MAX, _LEVEL), cost=Cost.CHEAP, auto_safe=True,
        detection_notes="Magic 'BZh' followed by a block-size digit 1-9.",
        examples=(),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, max_output: int, level: int) -> bytes:
        return bz2.compress(data, level)

    def _decode(self, data: bytes, strict: bool, max_output: int, level: int = 9) -> bytes:
        d = bz2.BZ2Decompressor()
        out = d.decompress(data, max_output + 1)
        _check(out, max_output)
        if not d.eof:
            raise DecodeError("bzip2 stream is truncated or incomplete")
        if d.unused_data and strict:
            raise DecodeError(f"{len(d.unused_data)} bytes of trailing data")
        return out

    def detect(self, data: bytes) -> Detection | None:
        if data[:3] == b"BZh" and len(data) > 3 and 0x31 <= data[3] <= 0x39:
            return Detection(0.95, "bzip2 magic 'BZh' + block size")
        return None


class Lzma(Codec):
    info = PluginInfo(
        name="lzma", aliases=("xz",), category=Category.COMPRESSION,
        description="XZ container (default) or legacy .lzma ('alone') format; decoding auto-detects both.",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(
            _STRICT, _MAX, _LEVEL,
            Param("format", ParamType.STR, "xz", "Encode: xz or alone.", choices=("xz", "alone")),
        ),
        cost=Cost.CHEAP, auto_safe=True,
        detection_notes="xz magic fd 37 7a 58 5a 00 (high); legacy .lzma header 5d 00 00 (weak).",
        examples=(),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, max_output: int, level: int, format: str) -> bytes:
        fmt = lzma.FORMAT_XZ if format == "xz" else lzma.FORMAT_ALONE
        return lzma.compress(data, format=fmt, preset=level)

    def _decode(self, data: bytes, strict: bool, max_output: int, level: int = 9, format: str = "xz") -> bytes:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)
        out = d.decompress(data, max_output + 1)
        _check(out, max_output)
        if not d.eof:
            raise DecodeError("lzma stream is truncated or incomplete")
        if d.unused_data and strict:
            raise DecodeError(f"{len(d.unused_data)} bytes of trailing data")
        return out

    def detect(self, data: bytes) -> Detection | None:
        if data[:6] == b"\xfd7zXZ\x00":
            return Detection(0.95, "xz magic")
        if data[:3] == b"\x5d\x00\x00" and len(data) > 13:
            return Detection(0.3, "possible legacy .lzma header")
        return None
