"""Byte-level manipulation."""

from __future__ import annotations

from cryptix.core.plugin import Category, Cipher, Codec, Cost, DataKind, Example, Param, ParamType, PluginInfo
from cryptix.errors import DecodeError


class Reverse(Codec):
    info = PluginInfo(
        name="reverse", aliases=("rev",), category=Category.BYTES,
        description="Reverse the data. unit=bytes reverses byte order; unit=chars reverses UTF-8 "
        "characters (requires valid UTF-8, so multi-byte characters stay intact).",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(Param("unit", ParamType.STR, "bytes", "bytes or chars.", choices=("bytes", "chars")),),
        auto_safe=False,  # self-inverse: applying it twice is a no-op, so auto-search must not loop on it
        examples=(Example(b"olleH", b"Hello"),),
    )  # fmt: skip

    def _encode(self, data: bytes, unit: str) -> bytes:
        if unit == "bytes":
            return data[::-1]
        try:
            return data.decode("utf-8")[::-1].encode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError(f"unit=chars requires valid UTF-8: {exc}") from exc

    _decode = _encode


class Xor(Cipher):
    info = PluginInfo(
        name="xor", category=Category.XOR,
        description="XOR with a repeating key (single-byte keys included). The operation is its "
        "own inverse. Key syntax: hex:41ff, int:65, esc:\\x00A, b64:..., or plain text.",
        input_type=DataKind.BYTES, output_type=DataKind.BYTES, reversible=True,
        params=(Param("key", ParamType.BYTES, None, "Repeating key (non-empty).", required=True),),
        cost=Cost.TRIVIAL, auto_safe=False,
        examples=(Example(b"\x0b7/>,", b"Hello", {"key": "hex:4352"}),),
    )  # fmt: skip

    def _encode(self, data: bytes, key: bytes) -> bytes:
        if not key:
            raise DecodeError("xor key must not be empty")
        if len(key) == 1:
            return data.translate(bytes(b ^ key[0] for b in range(256)))
        if not data:
            return b""
        n = len(data)
        stream = (key * (n // len(key) + 1))[:n]
        return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(n, "big")

    _decode = _encode
