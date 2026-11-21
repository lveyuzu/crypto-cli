"""Text-level encodings and simple substitution ciphers."""

from __future__ import annotations

import binascii
import html
import re

from cryptix.core.plugin import (
    Category, Cipher, Codec, DataKind, Detection, Example, Param, ParamType, PluginInfo,
)  # fmt: skip
from cryptix.core.textutil import clean_ascii
from cryptix.errors import DecodeError, EncodeError

_B, _I, _S = ParamType.BOOL, ParamType.INT, ParamType.STR
STRICT = Param("strict", _B, False, "Reject malformed sequences instead of tolerating them.")


def _stripped(data: bytes) -> str | None:
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None


# ------------------------------------------------------------------ percent
class UrlEncoding(Codec):
    info = PluginInfo(
        name="url", aliases=("urlencode", "percent"), category=Category.TEXT,
        description="URL percent-encoding (RFC 3986). Works on bytes: every byte outside "
        "A-Za-z0-9-._~ becomes %XX. Decoding leaves malformed '%' sequences untouched "
        "unless strict.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(
            STRICT,
            Param("plus", _B, False, "Decode '+' as space (form encoding); encode space as '+'."),
            Param("safe", _S, "", "Extra ASCII characters to leave unescaped when encoding."),
        ),
        auto_safe=True,
        detection_notes="Contains at least one valid %XX sequence.",
        examples=(Example(b"a%20b%26c%3D%C3%A9", "a b&c=é".encode()),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, plus: bool, safe: str) -> bytes:
        keep = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        keep |= set(safe.encode("ascii"))
        out = bytearray()
        for b in data:
            if b in keep:
                out.append(b)
            elif b == 0x20 and plus:
                out.append(0x2B)
            else:
                out += b"%%%02X" % b
        return bytes(out)

    def _decode(self, data: bytes, strict: bool, plus: bool, safe: str = "") -> bytes:
        if strict:
            bad = re.search(rb"%(?![0-9A-Fa-f]{2})", data)
            if bad:
                raise DecodeError(f"malformed percent escape at offset {bad.start()}")
        if plus:
            data = data.replace(b"+", b" ")
        return re.sub(rb"%([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)

    def detect(self, data: bytes) -> Detection | None:
        n = len(re.findall(rb"%[0-9A-Fa-f]{2}", data))
        if n:
            return Detection(min(0.9, 0.5 + 0.05 * n), f"{n} percent-escape sequence(s)")
        return None


class HtmlEntities(Codec):
    info = PluginInfo(
        name="html", aliases=("html-entities", "entities"), category=Category.TEXT,
        description="HTML character references via Python's html module (HTML5 named and "
        "numeric entities). Requires valid UTF-8 text. Note HTML5 maps numeric references "
        "0x80-0x9F through Windows-1252, so those cannot be produced by `all=true`.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        params=(
            STRICT,
            Param("all", _B, False, "Encode: also escape every non-ASCII character as &#N;."),
        ),
        auto_safe=True,
        detection_notes="Matches &name; or &#N; / &#xH; references.",
        examples=(Example(b"&lt;b&gt; &amp; &quot;x&quot; &#233;", '<b> & "x" é'.encode(), {"all": True}),),
    )  # fmt: skip

    @staticmethod
    def _text(data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError(f"html operates on UTF-8 text: {exc}") from exc

    def _encode(self, data: bytes, strict: bool, all: bool) -> bytes:
        text = html.escape(self._text(data), quote=True)
        if all:
            out = []
            for ch in text:
                cp = ord(ch)
                if cp > 127:
                    if 0x80 <= cp <= 0x9F:
                        raise EncodeError("C1 control characters cannot round-trip through HTML5 numeric references")
                    out.append(f"&#{cp};")
                else:
                    out.append(ch)
            text = "".join(out)
        return text.encode("utf-8")

    def _decode(self, data: bytes, strict: bool, all: bool = False) -> bytes:
        text = self._text(data)
        if strict and re.search(r"&(?![A-Za-z0-9#]+;)", text):
            raise DecodeError("strict mode: bare '&' that is not part of a reference")
        return html.unescape(text).encode("utf-8")

    def detect(self, data: bytes) -> Detection | None:
        n = len(re.findall(rb"&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);", data))
        return Detection(min(0.9, 0.5 + 0.05 * n), f"{n} HTML character reference(s)") if n else None


class QuotedPrintable(Codec):
    info = PluginInfo(
        name="quoted-printable", aliases=("qp",), category=Category.TEXT,
        description="MIME Quoted-Printable (RFC 2045). Encoding is binary-safe (newlines and "
        "tabs are escaped too) and inserts soft line breaks every 76 characters.",
        input_type=DataKind.TEXT, output_type=DataKind.BYTES, reversible=True,
        params=(STRICT,), auto_safe=True,
        detection_notes="Contains =XX hex escapes or '=' soft line breaks.",
        examples=(Example(b"caf=C3=A9", "café".encode()),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool) -> bytes:
        return binascii.b2a_qp(data, quotetabs=True, istext=False)

    def _decode(self, data: bytes, strict: bool) -> bytes:
        if strict and re.search(rb"=(?![0-9A-F]{2}|\r?\n)", data):
            raise DecodeError("strict mode: '=' not followed by two uppercase hex digits")
        return binascii.a2b_qp(data)

    def detect(self, data: bytes) -> Detection | None:
        n = len(re.findall(rb"=[0-9A-F]{2}", data))
        return Detection(min(0.85, 0.4 + 0.05 * n), f"{n} =XX sequence(s)") if n else None


# ------------------------------------------------------------ unicode escapes
_UESC = re.compile(r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|(.))", re.S)
_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"', "0": "\0"}


def _join_pair(m: re.Match[str]) -> str:
    hi, lo = ord(m.group()[0]), ord(m.group()[1])
    return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))


class UnicodeEscape(Codec):
    info = PluginInfo(
        name="unicode-escape", aliases=("uescape", "u-escape"), category=Category.TEXT,
        description="\\uXXXX, \\UXXXXXXXX and \\xHH escapes interpreted as Unicode code points "
        "(surrogate pairs \\ud83d\\ude00 are combined). Output is UTF-8. Encoding writes "
        "\\uXXXX / \\UXXXXXXXX for non-ASCII, and \\xHH-free escapes for control characters.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        params=(STRICT, Param("all", _B, False, "Encode: escape ASCII characters too.")),
        auto_safe=True,
        detection_notes="Contains \\uXXXX, \\UXXXXXXXX or \\xHH sequences.",
        examples=(Example(b"caf\\u00e9 \\U0001f600", "café 😀".encode()),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, all: bool) -> bytes:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EncodeError(f"unicode-escape operates on UTF-8 text: {exc}") from exc
        out = []
        for ch in text:
            cp = ord(ch)
            if ch == "\\":
                out.append("\\\\")
            elif ch in "\n\r\t":
                out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
            elif all or cp < 0x20 or cp == 0x7F or cp > 0x7E:
                out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
            else:
                out.append(ch)
        return "".join(out).encode("ascii")

    def _decode(self, data: bytes, strict: bool, all: bool = False) -> bytes:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError(f"input is not valid UTF-8: {exc}") from exc

        def repl(m: re.Match[str]) -> str:
            if m.group(1) or m.group(2) or m.group(3):
                return chr(int(m.group(1) or m.group(2) or m.group(3), 16))
            c = m.group(4)
            if c in _SIMPLE:
                return _SIMPLE[c]
            if strict:
                raise DecodeError(f"unknown escape \\{c}")
            return m.group(0)

        try:
            decoded = _UESC.sub(repl, text)
        except (ValueError, OverflowError) as exc:
            raise DecodeError(f"invalid code point: {exc}") from exc
        # combine UTF-16 surrogate pairs produced by consecutive \ud83d\ude00 escapes
        decoded = re.sub("[\ud800-\udbff][\udc00-\udfff]", _join_pair, decoded)
        try:
            return decoded.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DecodeError("lone UTF-16 surrogate escape cannot be represented in UTF-8") from exc

    def detect(self, data: bytes) -> Detection | None:
        n = len(re.findall(rb"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2})", data))
        return Detection(min(0.9, 0.5 + 0.05 * n), f"{n} unicode/hex escape(s)") if n else None


# --------------------------------------------------------- letter rotations
def _rot_table(n: int, digits: bool = False) -> bytes:
    """Translation table rotating letters by n (mod 26) and optionally digits (mod 10)."""
    t = bytearray(range(256))
    for i in range(26):
        t[ord("a") + i] = ord("a") + (i + n) % 26
        t[ord("A") + i] = ord("A") + (i + n) % 26
    if digits:
        for i in range(10):
            t[ord("0") + i] = ord("0") + (i + n) % 10
    return bytes(t)


class RotN(Cipher):
    info = PluginInfo(
        name="rotn", aliases=("rot", "caesar-shift"), category=Category.CLASSICAL,
        description="Rotate ASCII letters by n positions (Caesar shift). decode shifts by -n. "
        "Non-letters unchanged; digits rotated mod 10 only if digits=true.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        params=(
            Param("n", _I, 13, "Shift amount (any integer; reduced mod 26)."),
            Param("digits", _B, False, "Also rotate digits by n mod 10."),
        ),
        auto_safe=False,  # 26 candidates per node; the dedicated solver ranks them
        examples=(Example(b"Khoor, Zruog!", b"Hello, World!", {"n": 3}),),
    )  # fmt: skip

    def _encode(self, data: bytes, n: int, digits: bool) -> bytes:
        return data.translate(_rot_table(n, digits))

    def _decode(self, data: bytes, n: int, digits: bool) -> bytes:
        return self._encode(data, -n, digits)


class Rot13(Codec):
    info = PluginInfo(
        name="rot13", category=Category.CLASSICAL,
        description="ROT13: letters rotated by 13; its own inverse.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        auto_safe=True,
        detection_notes="Output is only plausible if it scores as text; no structural check.",
        examples=(Example(b"Uryyb", b"Hello"),),
    )  # fmt: skip
    _T = _rot_table(13)

    def _encode(self, data: bytes) -> bytes:
        return data.translate(self._T)

    _decode = _encode


class Rot47(Codec):
    info = PluginInfo(
        name="rot47", category=Category.CLASSICAL,
        description="ROT47: rotate printable ASCII 0x21-0x7E by 47; its own inverse.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        auto_safe=True,
        detection_notes="Printable ASCII without letters-only structure; no reliable check.",
        examples=(Example(b"w6==@", b"Hello"),),
    )  # fmt: skip
    _T = bytes((33 + (b - 33 + 47) % 94) if 33 <= b <= 126 else b for b in range(256))

    def _encode(self, data: bytes) -> bytes:
        return data.translate(self._T)

    _decode = _encode


class Atbash(Codec):
    info = PluginInfo(
        name="atbash", category=Category.CLASSICAL,
        description="Atbash: A<->Z, B<->Y ... (letters only, case preserved); its own inverse.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        auto_safe=True,
        examples=(Example(b"Svool", b"Hello"),),
    )  # fmt: skip
    _T = bytes(
        (ord("a") + 25 - (b - ord("a"))) if 97 <= b <= 122
        else (ord("A") + 25 - (b - ord("A"))) if 65 <= b <= 90 else b
        for b in range(256)
    )  # fmt: skip

    def _encode(self, data: bytes) -> bytes:
        return data.translate(self._T)

    _decode = _encode


# ----------------------------------------------------------------- morse etc.
_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.",
    "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.",
    "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-",
    "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
    "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--", "/": "-..-.",
    "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.", "-": "-....-", "_": "..--.-", '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}  # fmt: skip
_MORSE_REV = {v: k for k, v in _MORSE.items()}
_UNKNOWN = Param("unknown", _S, "error", "Unsupported characters: error or skip.", choices=("error", "skip"))


class Morse(Codec):
    info = PluginInfo(
        name="morse", category=Category.TEXT,
        description="International Morse code (ITU). Letters separated by a space, words by ' / '. "
        "Decoding also accepts '|', '/', or 3+ spaces between words and the dot/dash look-alikes "
        "'•' '·' '−' '_'. Output is uppercase (Morse has no case).",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        params=(STRICT, _UNKNOWN), auto_safe=True,
        detection_notes="Only '.', '-', '/', '|' and whitespace.",
        examples=(Example(b"... --- ... / .-", b"SOS A"),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, unknown: str) -> bytes:
        words = []
        for word in data.decode("utf-8").upper().split():
            letters = []
            for ch in word:
                if ch in _MORSE:
                    letters.append(_MORSE[ch])
                elif unknown == "error":
                    raise EncodeError(f"no Morse code for {ch!r}")
            words.append(" ".join(letters))
        return " / ".join(w for w in words if w).encode()

    def _decode(self, data: bytes, strict: bool, unknown: str) -> bytes:
        text = data.decode("utf-8")
        for src in "•·":
            text = text.replace(src, ".")
        text = text.replace("−", "-").replace("_", "-") if not strict else text
        text = re.sub(r"[|/]| {3,}", " / ", text)
        out = []
        for word in re.split(r"\s*/\s*", text.strip()):
            letters = []
            for sym in word.split():
                if sym in _MORSE_REV:
                    letters.append(_MORSE_REV[sym])
                elif strict or unknown == "error":
                    raise DecodeError(f"invalid Morse symbol {sym!r}")
                elif unknown == "skip":
                    continue
            out.append("".join(letters))
        return " ".join(out).encode()

    def detect(self, data: bytes) -> Detection | None:
        s = _stripped(data)
        if s and re.fullmatch(r"[.\-/|\s]+", s) and re.search(r"[.\-]", s):
            return Detection(0.8, "only dots, dashes and separators")
        return None


class A1Z26(Codec):
    info = PluginInfo(
        name="a1z26", aliases=("letter-numbers",), category=Category.CLASSICAL,
        description="A=1 ... Z=26. Numbers separated by space, comma or dash; '/' separates words. "
        "Encoding emits uppercase letters separated by '-', words by ' / '; case is not preserved.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        params=(STRICT, _UNKNOWN, Param("sep", _S, "-", "Encode: letter separator.")),
        auto_safe=True,
        detection_notes="Numbers 1-26 separated by non-digits; at least 3 numbers.",
        examples=(Example(b"8-5-12-12-15 / 23", b"HELLO W"),),
    )  # fmt: skip

    def _encode(self, data: bytes, strict: bool, unknown: str, sep: str) -> bytes:
        words = []
        for word in data.decode("utf-8").split():
            nums = []
            for ch in word.upper():
                if "A" <= ch <= "Z":
                    nums.append(str(ord(ch) - 64))
                elif unknown == "error":
                    raise EncodeError(f"{ch!r} is not a letter A-Z")
            if nums:
                words.append(sep.join(nums))
        return " / ".join(words).encode()

    def _decode(self, data: bytes, strict: bool, unknown: str, sep: str = "-") -> bytes:
        text = clean_ascii(data, True) if strict else data.decode("ascii", "replace")
        words = []
        for word in text.split("/"):
            letters = []
            for tok in re.split(r"[^0-9]+", word):
                if not tok:
                    continue
                n = int(tok) if len(tok) <= 3 else 999
                if 1 <= n <= 26:
                    letters.append(chr(64 + n))
                elif strict or unknown == "error":
                    raise DecodeError(f"{tok[:12]} is outside 1..26")
            words.append("".join(letters))
        return " ".join(w for w in words if w).encode()

    def detect(self, data: bytes) -> Detection | None:
        s = _stripped(data)
        if not s or not re.fullmatch(r"[0-9\s,\-/]+", s):
            return None
        toks = [t for t in re.split(r"[^0-9]+", s) if t]
        nums = [int(t) for t in toks if len(t) <= 2]
        if len(toks) >= 3 and len(nums) == len(toks) and all(1 <= n <= 26 for n in nums):
            return Detection(0.55, f"{len(nums)} numbers all in 1..26")
        return None
