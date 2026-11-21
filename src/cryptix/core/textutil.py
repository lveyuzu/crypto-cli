"""Helpers shared by text-based codecs."""

from __future__ import annotations

from cryptix.errors import DecodeError

_WS = b" \t\r\n\x0b\x0c"


def clean_ascii(data: bytes, strict: bool) -> str:
    """Return *data* as ASCII text with whitespace handled.

    strict:      only leading/trailing whitespace is removed.
    permissive:  all whitespace (including line wraps) is removed.
    """
    body = data.strip(_WS) if strict else data.translate(None, _WS)
    try:
        return body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"non-ASCII byte 0x{body[exc.start]:02x} in text input") from exc


def first_bad_char(text: str, allowed: frozenset[str] | set[str]) -> str | None:
    for ch in text:
        if ch not in allowed:
            return ch
    return None
