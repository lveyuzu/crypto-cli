"""Canonical byte handling.

Raw ``bytes`` are the only internal data representation. This module converts
between user-facing text notations (hex, C-style escapes, charsets) and bytes,
without ever passing data through a lossy text round trip.

Input formats  (how the *text of the input* maps to bytes):
    raw      bytes exactly as given (argv text is taken as its original OS bytes)
    utf8     like raw, but the input must be valid UTF-8
    latin1   each character is one byte (argv text is encoded as Latin-1)
    hex      hexadecimal digits; whitespace, ``0x`` and ``\\x`` markers are ignored
    escaped  C/Python-style escapes (``\\x41``, ``\\n``, ``\\101``, ``\\u00e9`` ...)

Output formats:
    raw      the bytes exactly
    hex      lowercase hexadecimal
    escaped  printable ASCII as-is, everything else as ``\\xHH`` (always round-trips)
    text     UTF-8 with U+FFFD replacement (display only; lossy)
    latin1   bytes shown as Latin-1 characters, written as UTF-8 (display only)
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from collections.abc import Iterable

from cryptix.errors import InputError

INPUT_FORMATS = ("raw", "utf8", "latin1", "hex", "escaped")
OUTPUT_FORMATS = ("raw", "hex", "escaped", "text", "latin1")

_SIMPLE_ESCAPES = {
    "\\": 0x5C, "'": 0x27, '"': 0x22, "a": 7, "b": 8, "f": 12,
    "n": 10, "r": 13, "t": 9, "v": 11,
}  # fmt: skip
_HEX = frozenset("0123456789abcdefABCDEF")


def parse_escaped(text: str) -> bytes:
    """Parse C/Python-style escapes into bytes. Never uses eval/ast.

    Literal non-escape characters are encoded as UTF-8 (surrogateescape-aware,
    so bytes recovered from argv survive). ``\\uXXXX`` / ``\\UXXXXXXXX`` produce the
    UTF-8 encoding of that code point; ``\\xHH`` and octal produce one raw byte.
    """
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != "\\":
            out += ch.encode("utf-8", "surrogateescape")
            i += 1
            continue
        i += 1
        if i >= n:
            raise InputError("dangling backslash at end of escaped input")
        c = text[i]
        if c in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[c])
            i += 1
        elif c == "\n":  # line continuation, as in Python literals
            i += 1
        elif c in "01234567":
            j = i
            while j < n and j < i + 3 and text[j] in "01234567":
                j += 1
            value = int(text[i:j], 8)
            if value > 255:
                raise InputError(f"octal escape \\{text[i:j]} out of byte range")
            out.append(value)
            i = j
        elif c in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[c]
            digits = text[i + 1 : i + 1 + width]
            if len(digits) != width or not set(digits) <= _HEX:
                raise InputError(f"invalid \\{c} escape at position {i - 1}")
            value = int(digits, 16)
            if c == "x":
                out.append(value)
            else:
                try:
                    out += chr(value).encode("utf-8")
                except (ValueError, OverflowError, UnicodeEncodeError) as exc:
                    raise InputError(f"invalid code point \\{c}{digits}") from exc
            i += 1 + width
        else:
            raise InputError(f"invalid escape '\\{c}' at position {i - 1}")
    return bytes(out)


def to_escaped(data: bytes) -> str:
    """Render bytes as an escaped string that :func:`parse_escaped` inverts exactly."""
    parts: list[str] = []
    for b in data:
        if b == 0x5C:
            parts.append("\\\\")
        elif b == 0x0A:
            parts.append("\\n")
        elif b == 0x0D:
            parts.append("\\r")
        elif b == 0x09:
            parts.append("\\t")
        elif 0x20 <= b <= 0x7E:
            parts.append(chr(b))
        else:
            parts.append(f"\\x{b:02x}")
    return "".join(parts)


_HEX_NOISE = re.compile(r"(?i)0x|\\x|[\s:,\-]")


def parse_hex(text: str) -> bytes:
    cleaned = _HEX_NOISE.sub("", text)
    if len(cleaned) % 2:
        raise InputError("hex input has an odd number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise InputError(f"invalid hex input: {exc}") from exc


def bytes_from_arg(arg: str, fmt: str = "raw") -> bytes:
    """Convert a command-line argument string to bytes."""
    _check_fmt(fmt, INPUT_FORMATS)
    if fmt == "raw":
        return os.fsencode(arg)
    if fmt == "utf8":
        raw = os.fsencode(arg)
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError(f"argument is not valid UTF-8: {exc}") from exc
        return raw
    if fmt == "latin1":
        try:
            return arg.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise InputError(f"character not representable in Latin-1: {exc}") from exc
    if fmt == "hex":
        return parse_hex(arg)
    return parse_escaped(arg)


def bytes_from_stream(raw: bytes, fmt: str = "raw") -> bytes:
    """Convert bytes read from stdin or a file according to the input format.

    For ``raw`` and ``latin1`` the bytes are used 1:1. ``hex`` and ``escaped``
    treat the stream as text; for ``escaped`` one trailing newline is dropped
    (write ``\\n`` explicitly if you want it).
    """
    _check_fmt(fmt, INPUT_FORMATS)
    if fmt in ("raw", "latin1"):
        return raw
    if fmt == "utf8":
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError(f"input is not valid UTF-8: {exc}") from exc
        return raw
    text = raw.decode("utf-8", "surrogateescape")
    if fmt == "hex":
        return parse_hex(text)
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    return parse_escaped(text)


def format_output(data: bytes, fmt: str) -> bytes:
    """Render *data* for output. Text-like formats get a trailing newline."""
    _check_fmt(fmt, OUTPUT_FORMATS)
    if fmt == "raw":
        return data
    if fmt == "hex":
        body = binascii.hexlify(data)
    elif fmt == "escaped":
        body = to_escaped(data).encode("ascii")
    elif fmt == "text":
        body = data.decode("utf-8", "replace").encode("utf-8")
    else:
        body = data.decode("latin-1").encode("utf-8")
    return body + b"\n"


def is_texty(data: bytes) -> bool:
    """True if *data* is valid UTF-8 without control characters (besides \\t \\n \\r)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ch in "\t\n\r" or ch.isprintable() for ch in text)


def parse_bytes_arg(value: str) -> bytes:
    """Parse a plugin parameter of type BYTES.

    Prefixes: ``hex:41ff``, ``b64:QUJD``, ``esc:\\x00A``, ``int:65`` (one byte if
    < 256, else minimal big-endian), ``str:text``. No prefix means UTF-8 text.
    """
    prefix, sep, rest = value.partition(":")
    if sep:
        if prefix == "hex":
            return parse_hex(rest)
        if prefix == "b64":
            try:
                return base64.b64decode(rest, validate=True)
            except binascii.Error as exc:
                raise InputError(f"invalid b64: value: {exc}") from exc
        if prefix == "esc":
            return parse_escaped(rest)
        if prefix == "int":
            try:
                number = int(rest, 0)
            except ValueError as exc:
                raise InputError(f"invalid int: value {rest!r}") from exc
            if number < 0:
                raise InputError("int: value must be non-negative")
            return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
        if prefix == "str":
            return os.fsencode(rest)
    return os.fsencode(value)


def _check_fmt(fmt: str, allowed: Iterable[str]) -> None:
    if fmt not in allowed:
        raise InputError(f"unknown format {fmt!r}; choose from {', '.join(allowed)}")
