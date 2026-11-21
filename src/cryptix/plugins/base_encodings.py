"""Base-N encodings.

Similarly named encodings are NOT interchangeable; each class documents its exact
alphabet and byte-packing rule.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct

from cryptix.core.plugin import (
    Category,
    Codec,
    Cost,
    DataKind,
    Detection,
    Example,
    Param,
    ParamType,
    PluginInfo,
)
from cryptix.core.textutil import clean_ascii
from cryptix.errors import DecodeError, EncodeError

STRICT = Param(
    "strict", ParamType.BOOL, False,
    "Reject inner whitespace, missing padding and other tolerated sloppiness.",
)  # fmt: skip
_B = ParamType.BOOL


def _ascii_stripped(data: bytes) -> str | None:
    try:
        return data.strip().decode("ascii")
    except UnicodeDecodeError:
        return None


def _det(conf: float, why: str) -> Detection:
    return Detection(conf, why)


# --------------------------------------------------------------------- hex
class Hex(Codec):
    info = PluginInfo(
        name="hex", aliases=("base16", "hexadecimal"), category=Category.BASE,
        description="Hexadecimal / Base16 (RFC 4648 section 8): two digits per byte.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, Param("upper", _B, False, "Encode with uppercase digits.")),
        auto_safe=True,
        detection_notes="Even-length string of [0-9a-fA-F]; all-digit strings score low (ambiguous).",
        examples=(Example(b"48656c6c6f", b"Hello"),),
    )  # fmt: skip

    def _encode(self, data: bytes, upper: bool, strict: bool = False) -> bytes:
        out = binascii.hexlify(data)
        return out.upper() if upper else out

    def _decode(self, data: bytes, strict: bool, upper: bool = False) -> bytes:
        s = clean_ascii(data, strict)
        if not strict:  # tolerate 0x41,0x42 / \x41\x42 / 41:42 / 41-42 notations
            s = re.sub(r"(?i)0x|\\x", "", s)
            s = re.sub(r"[:,\-]", "", s)
        bad = re.search(r"[^0-9a-fA-F]", s)
        if bad:
            raise DecodeError(f"invalid hex digit {bad.group()!r} at offset {bad.start()}")
        if len(s) % 2:
            raise DecodeError("odd number of hex digits")
        return bytes.fromhex(s)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
            return None
        if s.isdigit():
            return _det(0.25, "even-length decimal-digit string (also looks like base10)")
        return _det(0.6, "even-length hexadecimal digits")


# ------------------------------------------------------------- base2 / 8 / 10
class Base2(Codec):
    info = PluginInfo(
        name="base2", aliases=("binary", "bin"), category=Category.BASE,
        description="Binary string. Each group of `width` bits becomes one byte "
        "(width 8 = ordinary bytes, width 7 = 7-bit ASCII groups).",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(
            STRICT,
            Param("width", ParamType.INT, 8, "Bits per output byte (1-8)."),
        ),
        auto_safe=True,
        detection_notes="Only 0/1/whitespace, bit count a multiple of 8 (or 7).",
        examples=(Example(b"0100100001101001", b"Hi"),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, width: int) -> bytes:
        if not 1 <= width <= 8:
            raise EncodeError("width must be 1..8")
        if width < 8 and any(b >> width for b in data):
            raise EncodeError(f"byte value does not fit in {width} bits")
        return "".join(format(b, f"0{width}b") for b in data).encode()

    def _decode(self, data: bytes, strict: bool, width: int) -> bytes:
        if not 1 <= width <= 8:
            raise DecodeError("width must be 1..8")
        s = clean_ascii(data, strict)
        if not s:
            return b""
        bad = re.search(r"[^01]", s)
        if bad:
            raise DecodeError(f"invalid binary digit {bad.group()!r} at offset {bad.start()}")
        if len(s) % width:
            raise DecodeError(f"{len(s)} bits is not a multiple of width {width}")
        return bytes(int(s[i : i + width], 2) for i in range(0, len(s), width))

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s or not re.fullmatch(r"[01\s]+", s):
            return None
        bits = len(re.sub(r"\s", "", s))
        if bits % 8 == 0:
            return _det(0.8, "only 0/1, length multiple of 8")
        if bits % 7 == 0:
            return _det(0.5, "only 0/1, length multiple of 7 (7-bit groups?)")
        return None


class Base8(Codec):
    info = PluginInfo(
        name="base8", aliases=("octal", "oct"), category=Category.BASE,
        description="Octal byte values: each byte is a group of up to 3 octal digits "
        "(000-377). This is per-byte octal, NOT RFC-style 3-bit packing.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT,), auto_safe=True,
        detection_notes="Whitespace-separated groups of 1-3 octal digits each <= 377, "
        "or an unseparated string whose length is a multiple of 3.",
        examples=(Example(b"110 151", b"Hi"),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool) -> bytes:
        return " ".join(format(b, "03o") for b in data).encode()

    def _decode(self, data: bytes, strict: bool) -> bytes:
        text = data.strip().decode("ascii", "replace")
        if re.search(r"\s", text):
            tokens = text.split()
        else:
            if len(text) % 3:
                raise DecodeError("unseparated octal must have length divisible by 3")
            tokens = [text[i : i + 3] for i in range(0, len(text), 3)]
        out = bytearray()
        for tok in tokens:
            if not re.fullmatch(r"[0-7]{1,3}", tok) or (strict and len(tok) != 3):
                raise DecodeError(f"invalid octal group {tok!r}")
            value = int(tok, 8)
            if value > 255:
                raise DecodeError(f"octal group {tok} exceeds 0o377")
            out.append(value)
        return bytes(out)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s or not re.fullmatch(r"[0-7\s]+", s):
            return None
        try:
            self._decode(data, strict=False)
        except DecodeError:
            return None
        return _det(0.45, "valid octal byte groups")


class Base10(Codec):
    info = PluginInfo(
        name="base10", aliases=("decimal", "dec"), category=Category.BASE,
        description="Decimal. mode=bytes: space-separated byte values (72 101 ...). "
        "mode=integer: the whole data as one big-endian integer (leading zero bytes "
        "are lost unless `length` is given when decoding).",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(
            STRICT,
            Param("mode", ParamType.STR, "bytes", "bytes or integer.", choices=("bytes", "integer")),
            Param("byteorder", ParamType.STR, "big", "Integer mode byte order.", choices=("big", "little")),
            Param("length", ParamType.INT, 0, "Integer mode decode: left-pad to this many bytes."),
            Param("sep", ParamType.STR, " ", "Bytes mode encode separator."),
        ),
        auto_safe=True,
        detection_notes="Bytes mode: >=2 tokens, each 0-255. Integer mode: long digit string (low confidence).",
        examples=(
            Example(b"72 101 108 108 111", b"Hello"),
            Example(b"79600447942433", b"Hello!", {"mode": "integer"}),
        ),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, mode: str, byteorder: str, length: int, sep: str) -> bytes:
        if mode == "integer":
            return str(int.from_bytes(data, byteorder)).encode()  # type: ignore[arg-type]
        return sep.join(str(b) for b in data).encode()

    def _decode(self, data: bytes, strict: bool, mode: str, byteorder: str, length: int, sep: str) -> bytes:
        text = clean_ascii(data, True) if mode == "integer" else data.strip().decode("ascii", "replace")
        if mode == "integer":
            text = re.sub(r"\s", "", text) if not strict else text
            if not re.fullmatch(r"[0-9]+", text):
                raise DecodeError("integer mode expects only decimal digits")
            n = int(text)
            size = max((n.bit_length() + 7) // 8, length, 1)
            if length and (n.bit_length() + 7) // 8 > length:
                raise DecodeError(f"value needs more than {length} bytes")
            return n.to_bytes(size, byteorder)  # type: ignore[arg-type]
        if not text.strip():
            return b""
        tokens = [t for t in re.split(r"[\s,;]+", text) if t] if not strict else text.split(sep)
        out = bytearray()
        for tok in tokens:
            if not re.fullmatch(r"[0-9]{1,3}", tok) or int(tok) > 255:
                raise DecodeError(f"{tok!r} is not a byte value (0-255)")
            out.append(int(tok))
        return bytes(out)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s or not re.fullmatch(r"[0-9\s,;]+", s):
            return None
        tokens = [t for t in re.split(r"[\s,;]+", s) if t]
        if len(tokens) >= 2 and all(len(t) <= 3 and int(t) <= 255 for t in tokens):
            return _det(0.5, f"{len(tokens)} decimal tokens all within 0-255")
        if len(tokens) == 1 and len(tokens[0]) >= 12:
            return _det(0.15, "long decimal integer (possible big-endian byte string)")
        return None


# ------------------------------------------------------------ RFC 4648 family
def _pad_b64(s: str) -> str:
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        raise DecodeError("invalid length: a trailing group of 1 character cannot encode a byte")
    return s + "=" * (-len(s) % 4)


class Base64(Codec):
    info = PluginInfo(
        name="base64", aliases=("b64",), category=Category.BASE,
        description="Base64, RFC 4648 section 4 alphabet (A-Za-z0-9+/). Permissive mode "
        "ignores whitespace and repairs missing padding; strict mode demands canonical "
        "padded input. Encoding with pad=false produces the unpadded variant.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, Param("pad", _B, True, "Encode: emit '=' padding.")),
        auto_safe=True,
        detection_notes="[A-Za-z0-9+/] with optional '=' padding, length % 4 != 1; '=' padding raises confidence.",
        examples=(
            Example(b"SGVsbG8gV29ybGQ=", b"Hello World"),
            Example(b"SGVsbG8", b"Hello", {"pad": False}),
        ),
    )  # fmt: skip
    _std = True

    def _encode(self, data: bytes, strict: bool, pad: bool) -> bytes:
        out = base64.b64encode(data) if self._std else base64.urlsafe_b64encode(data)
        return out if pad else out.rstrip(b"=")

    def _decode(self, data: bytes, strict: bool, pad: bool = True) -> bytes:
        s = clean_ascii(data, strict)
        alphabet = r"[A-Za-z0-9+/]" if self._std else r"[A-Za-z0-9_\-]"
        if not re.fullmatch(alphabet + r"*={0,2}", s):
            bad = re.search(r"[^A-Za-z0-9+/=]" if self._std else r"[^A-Za-z0-9_\-=]", s)
            raise DecodeError(
                f"character {bad.group()!r} outside the {self.info.name} alphabet"
                if bad else "misplaced '=' padding"
            )
        if strict:
            if len(s) % 4:
                raise DecodeError("strict mode: input length is not a multiple of 4 (missing padding)")
            core = s
        else:
            core = _pad_b64(s)
        raw = base64.b64decode(core.replace("-", "+").replace("_", "/"), validate=True)
        if strict:
            canon = base64.b64encode(raw).decode()
            if not self._std:
                canon = canon.replace("+", "-").replace("/", "_")
            if canon != s:
                raise DecodeError("strict mode: non-canonical trailing bits")
        return raw

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s:
            return None
        s = re.sub(r"\s", "", s)
        if len(s) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) or len(s.rstrip("=")) % 4 == 1:
            return None
        if s.endswith("="):
            return _det(0.85, "base64 alphabet with '=' padding")
        if len(s) % 4 == 0:
            return _det(0.5 if re.fullmatch(r"[0-9a-fA-F]+", s) is None else 0.2, "base64 alphabet, length % 4 == 0")
        return _det(0.3, "base64 alphabet, padding missing")


class Base64Url(Base64):
    info = PluginInfo(
        name="base64url", aliases=("b64url", "urlsafe-base64"), category=Category.BASE,
        description="URL/filename-safe Base64, RFC 4648 section 5 alphabet (A-Za-z0-9-_). "
        "Padding is optional when decoding in permissive mode (JWT style).",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, Param("pad", _B, True, "Encode: emit '=' padding.")),
        auto_safe=True,
        detection_notes="[A-Za-z0-9_-]; contains '-' or '_' (otherwise plain base64 is the better match).",
        examples=(Example(b"_-8=", b"\xff\xef"),),
    )  # fmt: skip
    _std = False

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s or not re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", s) or len(s.rstrip("=")) % 4 == 1:
            return None
        if re.search(r"[_\-]", s):
            return _det(0.7, "contains URL-safe characters - or _")
        return None


class Base32(Codec):
    info = PluginInfo(
        name="base32", aliases=("b32",), category=Category.BASE,
        description="Base32, RFC 4648 section 6 alphabet (A-Z2-7), '=' padded to 8 characters. "
        "Permissive mode is case-insensitive and repairs missing padding.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, Param("pad", _B, True, "Encode: emit '=' padding.")),
        auto_safe=True,
        detection_notes="Uppercase [A-Z2-7] with '=' padding, length multiple of 8 (higher with padding).",
        examples=(Example(b"MZXW6YTBOI======", b"foobar"),),
    )  # fmt: skip
    _hex = False

    def _alpha(self) -> str:
        return r"[0-9A-V]" if self._hex else r"[A-Z2-7]"

    def _encode(self, data: bytes, strict: bool, pad: bool) -> bytes:
        out = base64.b32hexencode(data) if self._hex else base64.b32encode(data)
        return out if pad else out.rstrip(b"=")

    def _decode(self, data: bytes, strict: bool, pad: bool = True) -> bytes:
        s = clean_ascii(data, strict)
        if not strict:
            s = s.upper()
        body = s.rstrip("=")
        if not re.fullmatch(self._alpha() + "*", body):
            bad = re.search(r"[^0-9A-V]" if self._hex else r"[^A-Z2-7]", body)
            raise DecodeError(f"character {bad.group() if bad else '?'!r} outside the {self.info.name} alphabet")
        if strict and len(s) % 8:
            raise DecodeError("strict mode: length must be a multiple of 8 (padding required)")
        if len(body) % 8 in (1, 3, 6):
            raise DecodeError("invalid length for base32")
        padded = body + "=" * (-len(body) % 8)
        fn = base64.b32hexdecode if self._hex else base64.b32decode
        return fn(padded)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if not s or len(s) < 8 or not re.fullmatch(self._alpha() + r"+={0,6}", s):
            return None
        if self._hex and re.fullmatch(r"[A-Z2-7]+={0,6}", s):
            return None  # plain base32 is the better explanation
        if len(s) % 8:
            return None
        return _det(0.75 if s.endswith("=") else 0.45, "base32 alphabet, length multiple of 8")


class Base32Hex(Base32):
    info = PluginInfo(
        name="base32hex", aliases=("b32hex",), category=Category.BASE,
        description="Base32 'extended hex' alphabet, RFC 4648 section 7 (0-9A-V). "
        "Different alphabet from base32: do not confuse them.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, Param("pad", _B, True, "Encode: emit '=' padding.")),
        auto_safe=True,
        detection_notes="Uppercase [0-9A-V], padded to 8; skipped when plain base32 also fits.",
        examples=(Example(b"CPNMUOJ1E8======", b"foobar"),),
    )  # fmt: skip
    _hex = True


# ----------------------------------------------- big-integer bases (36/58/62)
def _int_encode(data: bytes, alphabet: str, keep_zeros: bool) -> str:
    base = len(alphabet)
    n = int.from_bytes(data, "big")
    digits: list[str] = []
    while n:
        n, r = divmod(n, base)
        digits.append(alphabet[r])
    lead = len(data) - len(data.lstrip(b"\x00")) if keep_zeros else 0
    return alphabet[0] * lead + "".join(reversed(digits))


def _int_decode(text: str, alphabet: str, keep_zeros: bool) -> bytes:
    base = len(alphabet)
    index = {c: i for i, c in enumerate(alphabet)}
    lead = 0
    if keep_zeros:
        lead = len(text) - len(text.lstrip(alphabet[0]))
    n = 0
    for ch in text[lead:]:
        try:
            n = n * base + index[ch]
        except KeyError:
            raise DecodeError(f"character {ch!r} is not in the alphabet") from None
    return b"\x00" * lead + n.to_bytes((n.bit_length() + 7) // 8, "big")


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62 = {
    "digits-upper-lower": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "digits-lower-upper": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}
_ZEROS = Param(
    "zeros", _B, True,
    "Preserve leading 0x00 bytes as leading zero-digits (false = pure big-integer view).",
)  # fmt: skip


class Base36(Codec):
    info = PluginInfo(
        name="base36", category=Category.BASE,
        description="Base36 big-integer encoding, alphabet 0-9a-z (case-insensitive on decode). "
        "No standard defines byte packing, so the data is treated as one big-endian "
        "integer; with zeros=true each leading 0x00 byte becomes a leading '0'.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, _ZEROS), auto_safe=True,
        detection_notes="[0-9a-zA-Z]+; very weak signal.",
        examples=(Example(b"73", b"\xff"), Example(b"073", b"\x00\xff")),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, zeros: bool) -> bytes:
        return _int_encode(data, "0123456789abcdefghijklmnopqrstuvwxyz", zeros).encode()

    def _decode(self, data: bytes, strict: bool, zeros: bool) -> bytes:
        s = clean_ascii(data, strict).lower()
        return _int_decode(s, "0123456789abcdefghijklmnopqrstuvwxyz", zeros)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if s and len(s) >= 6 and re.fullmatch(r"[0-9a-zA-Z]+", s):
            return _det(0.1, "alphanumeric (very weak)")
        return None


class Base58(Codec):
    info = PluginInfo(
        name="base58", aliases=("b58", "base58btc"), category=Category.BASE,
        description="Base58 with the Bitcoin alphabet (no 0, O, I, l). Leading 0x00 bytes "
        "are encoded as leading '1' characters. No checksum (not Base58Check).",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT,), auto_safe=True, cost=Cost.CHEAP,
        detection_notes="Alphanumeric without 0, O, I or l; weak signal.",
        examples=(Example(b"2NEpo7TZRRrLZSi2U", b"Hello World!"), Example(b"11ZiCa", b"\x00\x00abc")),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool) -> bytes:
        return _int_encode(data, _B58, True).encode()

    def _decode(self, data: bytes, strict: bool) -> bytes:
        return _int_decode(clean_ascii(data, strict), _B58, True)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if s and len(s) >= 6 and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", s):
            return _det(0.2, "base58 alphabet (no 0/O/I/l)")
        return None


class Base62(Codec):
    info = PluginInfo(
        name="base62", category=Category.BASE,
        description="Base62 big-integer encoding. Alphabet order is NOT standardised: variant "
        "'digits-upper-lower' (0-9A-Za-z, default) or 'digits-lower-upper' (0-9a-zA-Z, GMP).",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(
            STRICT, _ZEROS,
            Param("variant", ParamType.STR, "digits-upper-lower", "Alphabet ordering.", choices=tuple(_B62)),
        ),
        auto_safe=True,
        detection_notes="[0-9A-Za-z]+; very weak signal.",
        examples=(Example(b"1Z", b"a"), Example(b"0z", b"\x00="), Example(b"z", b"=", {"zeros": False})),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, zeros: bool, variant: str) -> bytes:
        return _int_encode(data, _B62[variant], zeros).encode()

    def _decode(self, data: bytes, strict: bool, zeros: bool, variant: str) -> bytes:
        return _int_decode(clean_ascii(data, strict), _B62[variant], zeros)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if s and len(s) >= 6 and re.fullmatch(r"[0-9A-Za-z]+", s):
            return _det(0.08, "alphanumeric (very weak)")
        return None


# ------------------------------------------------------------------ base85 family
class Base85(Codec):
    info = PluginInfo(
        name="base85", aliases=("b85", "git-base85"), category=Category.BASE,
        description="Base85 as implemented by Python's base64.b85encode / git: 4-byte blocks "
        "with the RFC 1924 character set (0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~). This is NOT "
        "Ascii85 and NOT the RFC 1924 128-bit-integer encoding of IPv6 addresses.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT,), auto_safe=True,
        detection_notes="Printable ASCII drawn from the base85 set; very weak signal.",
        examples=(Example(b"NM&qnZv", b"Hello"),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool) -> bytes:
        return base64.b85encode(data)

    def _decode(self, data: bytes, strict: bool) -> bytes:
        return base64.b85decode(clean_ascii(data, strict).encode())

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if s and len(s) >= 5 and re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+", s):
            if re.search(r"[!#$%&()*+;<=>?@^`{|}~]", s):
                return _det(0.15, "contains base85-specific punctuation")
        return None


class Ascii85(Codec):
    info = PluginInfo(
        name="ascii85", aliases=("a85", "base85-adobe"), category=Category.BASE,
        description="Ascii85 (btoa/Adobe): characters '!'..'u', 4 bytes -> 5 chars, 'z' for "
        "four zero bytes. Decoding auto-detects the Adobe '<~ ... ~>' wrapper; encode with "
        "adobe=true to add it.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT, Param("adobe", _B, False, "Encode: wrap in <~ ~>.")),
        auto_safe=True,
        detection_notes="'<~' ... '~>' wrapper (high); otherwise only chars in '!'-'u' (weak).",
        examples=(Example(b"87cURDZ", b"Hello"), Example(b"<~87cURDZ~>", b"Hello", {"adobe": True})),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, adobe: bool) -> bytes:
        return base64.a85encode(data, adobe=adobe)

    def _decode(self, data: bytes, strict: bool, adobe: bool = False) -> bytes:
        s = data.strip()
        use_adobe = s.startswith(b"<~")
        if use_adobe and not s.endswith(b"~>"):
            raise DecodeError("Adobe wrapper opened with '<~' but not closed with '~>'")
        return base64.a85decode(s, adobe=use_adobe)

    def detect(self, data: bytes) -> Detection | None:
        s = data.strip()
        if s.startswith(b"<~") and s.endswith(b"~>"):
            return _det(0.95, "Adobe Ascii85 <~ ~> wrapper")
        if len(s) >= 5 and all(33 <= b <= 117 or b in b" \t\r\n" for b in s) and re.search(rb"[^0-9A-Za-z]", s):
            return _det(0.12, "characters within '!'..'u'")
        return None


_Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85_INDEX = {c: i for i, c in enumerate(_Z85)}


class Z85(Codec):
    info = PluginInfo(
        name="z85", category=Category.BASE,
        description="ZeroMQ Z85 (ZMQ RFC 32): its own 85-character alphabet; input length must be "
        "a multiple of 4 bytes (output a multiple of 5 characters). Not interchangeable with "
        "base85/ascii85.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT,), auto_safe=True,
        detection_notes="Z85 alphabet, length multiple of 5; very weak signal.",
        examples=(Example(b"HelloWorld", b"\x86\x4f\xd2\x6f\xb5\x59\xf7\x5b"),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool) -> bytes:
        if len(data) % 4:
            raise EncodeError("Z85 requires input length to be a multiple of 4 bytes")
        out: list[str] = []
        for (value,) in struct.iter_unpack(">I", data):
            chunk = []
            for _ in range(5):
                value, r = divmod(value, 85)
                chunk.append(_Z85[r])
            out.extend(reversed(chunk))
        return "".join(out).encode()

    def _decode(self, data: bytes, strict: bool) -> bytes:
        s = clean_ascii(data, strict)
        if len(s) % 5:
            raise DecodeError("Z85 input length must be a multiple of 5 characters")
        out = bytearray()
        for i in range(0, len(s), 5):
            value = 0
            for ch in s[i : i + 5]:
                try:
                    value = value * 85 + _Z85_INDEX[ch]
                except KeyError:
                    raise DecodeError(f"character {ch!r} is not in the Z85 alphabet") from None
            if value > 0xFFFFFFFF:
                raise DecodeError("Z85 block overflows 32 bits")
            out += value.to_bytes(4, "big")
        return bytes(out)

    def detect(self, data: bytes) -> Detection | None:
        s = _ascii_stripped(data)
        if s and len(s) % 5 == 0 and len(s) >= 5 and all(c in _Z85_INDEX for c in s):
            return _det(0.12, "Z85 alphabet, length multiple of 5")
        return None
