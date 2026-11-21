"""Behavioural tests for every built-in operation."""

import bz2
import gzip
import lzma
import random
import unittest
import zlib

from cryptix.core.plugin import Decoder, Encoder
from cryptix.core.registry import Registry
from cryptix.errors import CryptixError, DecodeError, EncodeError, ParameterError

REG = Registry()
REG.discover(entry_points=False, user_dirs=False)


def dec(name, data, **p):
    return REG.get(name).decode(data if isinstance(data, bytes) else data.encode(), **p).data


def enc(name, data, **p):
    return REG.get(name).encode(data if isinstance(data, bytes) else data.encode(), **p).data


class VerifiedExamples(unittest.TestCase):
    """Every example declared by every plugin is executed in both directions."""

    def test_all_declared_examples(self):
        checked = 0
        for plugin in REG.all():
            for ex in plugin.info.examples:
                with self.subTest(plugin=plugin.info.name, encoded=ex.encoded):
                    self.assertEqual(plugin.decode(ex.encoded, **ex.params).data, ex.decoded)
                    if not ex.decode_only:
                        self.assertEqual(plugin.encode(ex.decoded, **ex.params).data, ex.encoded)
                    checked += 1
        self.assertGreater(checked, 30)

    def test_every_reversible_plugin_documents_an_example(self):
        missing = [p.info.name for p in REG.all()
                   if p.info.reversible and not p.info.examples
                   and p.info.name not in {"bzip2", "lzma"}]  # covered by stdlib cross-checks below
        self.assertEqual(missing, [])


class IndependentVectors(unittest.TestCase):
    """Vectors taken from specs / computed by independent arithmetic, not by this code."""

    def test_rfc4648(self):
        for plain, b64, b32, b32h, hx in [
            (b"", b"", b"", b"", b""),
            (b"f", b"Zg==", b"MY======", b"CO======", b"66"),
            (b"fo", b"Zm8=", b"MZXQ====", b"CPNG====", b"666f"),
            (b"foo", b"Zm9v", b"MZXW6===", b"CPNMU===", b"666f6f"),
            (b"foob", b"Zm9vYg==", b"MZXW6YQ=", b"CPNMUOG=", b"666f6f62"),
            (b"fooba", b"Zm9vYmE=", b"MZXW6YTB", b"CPNMUOJ1", b"666f6f6261"),
            (b"foobar", b"Zm9vYmFy", b"MZXW6YTBOI======", b"CPNMUOJ1E8======", b"666f6f626172"),
        ]:
            with self.subTest(plain=plain):
                self.assertEqual(enc("base64", plain), b64)
                self.assertEqual(dec("base64", b64), plain)
                self.assertEqual(enc("base32", plain), b32)
                self.assertEqual(dec("base32", b32), plain)
                self.assertEqual(enc("base32hex", plain), b32h)
                self.assertEqual(dec("base32hex", b32h), plain)
                self.assertEqual(enc("hex", plain), hx)
                self.assertEqual(dec("hex", hx), plain)

    def test_base58_bitcoin(self):
        self.assertEqual(enc("base58", b"Hello World!"), b"2NEpo7TZRRrLZSi2U")
        self.assertEqual(enc("base58", b"\x00\x00hello"), b"11Cn8eVZg"[:0] + b"11" + enc("base58", b"hello"))
        self.assertEqual(enc("base58", b"\x00"), b"1")
        self.assertEqual(dec("base58", "1"), b"\x00")
        self.assertEqual(dec("base58", "111"), b"\x00\x00\x00")
        for bad in ["0", "O", "I", "l", "abc0"]:
            with self.subTest(bad=bad), self.assertRaises(DecodeError):
                dec("base58", bad)

    def test_base36_base62_integers(self):
        self.assertEqual(enc("base36", b"\xff"), b"73")  # 255 = 7*36+3
        self.assertEqual(dec("base36", "73"), b"\xff")
        self.assertEqual(dec("base36", "ZZ"), dec("base36", "zz"))
        self.assertEqual(enc("base62", b"\x3d"), b"z")  # 61 -> last digit
        self.assertEqual(enc("base62", b"\x3e"), b"10")  # 62
        self.assertEqual(enc("base62", b"\x3d", variant="digits-lower-upper"), b"Z")
        self.assertEqual(dec("base62", "z"), b"=")

    def test_base_int_leading_zero_policy(self):
        self.assertEqual(enc("base36", b"\x00\x00\x01"), b"001")
        self.assertEqual(dec("base36", "001"), b"\x00\x00\x01")
        self.assertEqual(dec("base36", "001", zeros=False), b"\x01")  # pure integer view

    def test_base85_family(self):
        self.assertEqual(enc("ascii85", b"Hello"), b"87cURDZ")
        self.assertEqual(enc("ascii85", b"\x00\x00\x00\x00"), b"z")
        self.assertEqual(enc("ascii85", b"Man ", adobe=True), b"<~9jqo^~>")
        self.assertEqual(dec("ascii85", b"<~9jqo^~>"), b"Man ")
        # same bytes, different alphabets: these must NOT agree
        self.assertNotEqual(enc("base85", b"Hello"), enc("ascii85", b"Hello"))
        self.assertEqual(enc("base85", b"Hello"), b"NM&qnZv")
        # Z85 spec test vector
        self.assertEqual(enc("z85", bytes.fromhex("864FD26FB559F75B")), b"HelloWorld")
        self.assertEqual(dec("z85", "HelloWorld"), bytes.fromhex("864FD26FB559F75B"))
        with self.assertRaises(EncodeError):
            enc("z85", b"abc")
        with self.assertRaises(DecodeError):
            dec("z85", "Hell")  # 4 characters: not a multiple of 5
        with self.assertRaises(DecodeError):
            dec("z85", "~~~~~")  # outside the alphabet

    def test_binary_octal_decimal(self):
        self.assertEqual(enc("base2", b"A"), b"01000001")
        self.assertEqual(dec("base2", "01000001 01000010"), b"AB")
        self.assertEqual(dec("base2", "1000001 1000010", width=7), b"AB")  # 7-bit ASCII groups
        self.assertEqual(enc("base2", b"A", width=7), b"1000001")
        with self.assertRaises(EncodeError):
            enc("base2", b"\xff", width=7)
        self.assertEqual(enc("base8", b"A"), b"101")
        self.assertEqual(dec("base8", "110 145 154 154 157"), b"Hello")
        self.assertEqual(dec("base8", "110145154154157"), b"Hello")
        with self.assertRaises(DecodeError):
            dec("base8", "400")  # 0o400 = 256
        self.assertEqual(enc("base10", b"Hello"), b"72 101 108 108 111")
        self.assertEqual(dec("base10", "72,101;108 108\n111"), b"Hello")
        self.assertEqual(enc("base10", b"\x01\x00", mode="integer"), b"256")
        self.assertEqual(dec("base10", "256", mode="integer"), b"\x01\x00")
        self.assertEqual(dec("base10", "1", mode="integer", length=4), b"\x00\x00\x00\x01")
        self.assertEqual(dec("base10", "256", mode="integer", byteorder="little"), b"\x00\x01")

    def test_text_encodings(self):
        self.assertEqual(enc("url", "a b&c=é"), b"a%20b%26c%3D%C3%A9")
        self.assertEqual(enc("url", "a b", plus=True), b"a+b")
        self.assertEqual(dec("url", "a+b%20c", plus=True), b"a b c")
        self.assertEqual(dec("url", "100%"), b"100%")  # permissive: leave malformed '%'
        with self.assertRaises(DecodeError):
            dec("url", "100%", strict=True)
        self.assertEqual(dec("html", "&lt;&amp;&gt; &#65; &#x42; &eacute;"), "<&> A B é".encode())
        self.assertEqual(enc("html", "<a href=\"x\">&"), b"&lt;a href=&quot;x&quot;&gt;&amp;")
        self.assertEqual(dec("quoted-printable", "caf=C3=A9=\n!"), "café!".encode())
        self.assertEqual(dec("unicode-escape", r"\u0048\x69 \ud83d\ude00"), "Hi 😀".encode())
        self.assertEqual(enc("unicode-escape", "é😀"), b"\\u00e9\\U0001f600")

    def test_classical_and_morse(self):
        self.assertEqual(enc("rot13", "Hello"), b"Uryyb")
        self.assertEqual(dec("rotn", "Khoor", n=3), b"Hello")
        self.assertEqual(enc("rotn", "xyz XYZ", n=3), b"abc ABC")
        self.assertEqual(enc("rotn", "a1", n=-1, digits=True), b"z0")
        self.assertEqual(enc("rotn", "abc", n=26 * 5 + 1), b"bcd")
        self.assertEqual(enc("rot47", "Hello"), b"w6==@")
        self.assertEqual(enc("atbash", "Hello, World"), b"Svool, Dliow")
        self.assertEqual(enc("morse", "SOS"), b"... --- ...")
        self.assertEqual(enc("morse", "sos 1"), b"... --- ... / .----")
        self.assertEqual(dec("morse", ".... .. / - .... . .-. ."), b"HI THERE")
        self.assertEqual(dec("morse", "••• −−− •••"), b"SOS")
        with self.assertRaises(DecodeError):
            dec("morse", "......... .")
        self.assertEqual(dec("morse", "......... .", unknown="skip"), b"E")
        with self.assertRaises(EncodeError):
            enc("morse", "a~b")
        self.assertEqual(enc("morse", "a~b", unknown="skip"), b".- / -...".replace(b" / ", b" ")[:0] + b".- -...")
        self.assertEqual(dec("a1z26", "8 5 12 12 15"), b"HELLO")
        self.assertEqual(dec("a1z26", "8-5-12-12-15 / 23-15"), b"HELLO WO")
        self.assertEqual(enc("a1z26", "Hi there"), b"8-9 / 20-8-5-18-5")
        with self.assertRaises(DecodeError):
            dec("a1z26", "27")
        with self.assertRaises(DecodeError):
            dec("a1z26", "0")

    def test_byte_ops(self):
        self.assertEqual(enc("reverse", b"abc"), b"cba")
        self.assertEqual(enc("reverse", "héy", unit="chars"), "yéh".encode())
        self.assertEqual(enc("reverse", "héy"), "héy".encode()[::-1])
        with self.assertRaises(CryptixError):
            enc("reverse", b"\xff\xfe", unit="chars")
        # hand-computed: 'H'^0x43=0x0b 'e'^0x52=0x37 'l'^0x43=0x2f 'l'^0x52=0x3e 'o'^0x43=0x2c
        self.assertEqual(enc("xor", "Hello", key="hex:4352"), bytes([0x0B, 0x37, 0x2F, 0x3E, 0x2C]))
        self.assertEqual(enc("xor", b"\x00\x01", key="int:255"), b"\xff\xfe")
        self.assertEqual(enc("xor", b"", key=b"k"), b"")
        with self.assertRaises(CryptixError):
            enc("xor", b"abc", key=b"")
        with self.assertRaises(ParameterError):
            enc("xor", b"abc")  # key is required


class Compression(unittest.TestCase):
    PAYLOAD = b"The quick brown fox jumps over the lazy dog. " * 20

    def test_cross_check_with_stdlib(self):
        # our encoder -> stdlib decoder, and stdlib encoder -> our decoder
        self.assertEqual(zlib.decompress(enc("zlib", self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(gzip.decompress(enc("gzip", self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(zlib.decompress(enc("deflate", self.PAYLOAD), -15), self.PAYLOAD)
        self.assertEqual(bz2.decompress(enc("bzip2", self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(lzma.decompress(enc("lzma", self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(lzma.decompress(enc("lzma", self.PAYLOAD, format="alone")), self.PAYLOAD)
        self.assertEqual(dec("zlib", zlib.compress(self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(dec("gzip", gzip.compress(self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(dec("bzip2", bz2.compress(self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(dec("lzma", lzma.compress(self.PAYLOAD)), self.PAYLOAD)
        self.assertEqual(dec("lzma", lzma.compress(self.PAYLOAD, format=lzma.FORMAT_ALONE)), self.PAYLOAD)

    def test_gzip_is_reproducible(self):
        self.assertEqual(enc("gzip", self.PAYLOAD), enc("gzip", self.PAYLOAD))
        self.assertEqual(enc("gzip", b"x")[4:8], b"\x00\x00\x00\x00")  # mtime = 0

    def test_multi_member_gzip(self):
        two = gzip.compress(b"first ") + gzip.compress(b"second")
        self.assertEqual(dec("gzip", two), b"first second")

    def test_trailing_garbage(self):
        blob = zlib.compress(b"data") + b"JUNK"
        self.assertEqual(dec("zlib", blob), b"data")
        with self.assertRaises(DecodeError):
            dec("zlib", blob, strict=True)
        blob = bz2.compress(b"data") + b"JUNK"
        self.assertEqual(dec("bzip2", blob), b"data")
        with self.assertRaises(DecodeError):
            dec("bzip2", blob, strict=True)

    def test_truncated_and_garbage(self):
        for name, blob in [("zlib", zlib.compress(self.PAYLOAD)), ("gzip", gzip.compress(self.PAYLOAD)),
                           ("bzip2", bz2.compress(self.PAYLOAD)), ("lzma", lzma.compress(self.PAYLOAD))]:
            with self.subTest(name=name, kind="truncated"), self.assertRaises(DecodeError):
                dec(name, blob[: len(blob) // 2])
            with self.subTest(name=name, kind="garbage"), self.assertRaises(DecodeError):
                dec(name, b"this is not compressed data at all")

    def test_decompression_bomb_is_bounded(self):
        bomb = {"zlib": zlib.compress(bytes(5_000_000), 9), "gzip": gzip.compress(bytes(5_000_000)),
                "bzip2": bz2.compress(bytes(5_000_000)), "lzma": lzma.compress(bytes(5_000_000))}
        for name, blob in bomb.items():
            with self.subTest(name=name):
                self.assertLess(len(blob), 50_000)
                with self.assertRaises(DecodeError) as cm:
                    dec(name, blob, max_output=100_000)
                self.assertIn("limit", str(cm.exception))
                self.assertEqual(len(dec(name, blob, max_output=5_000_000)), 5_000_000)  # exact limit OK


class RoundTrips(unittest.TestCase):
    """Deterministic randomised round trips (swap in Hypothesis when it is installed)."""

    ARBITRARY = ["hex", "base2", "base8", "base10", "base32", "base32hex", "base36", "base58", "base62",
                 "base64", "base64url", "base85", "ascii85", "quoted-printable", "url", "zlib", "gzip",
                 "deflate", "bzip2", "lzma", "reverse", "rot13", "rot47", "atbash", "rotn"]

    def samples(self):
        rng = random.Random(20260101)
        out = [b"", b"\x00", b"\x00\x00\x00", b"\xff" * 5, b"\x00\x00hello", bytes(range(256))]
        for n in list(range(1, 40)) + [100, 1000]:
            out.append(bytes(rng.randrange(256) for _ in range(n)))
        # random data with leading zero bytes exercises the big-integer encodings
        out += [bytes(rng.randrange(3) for _ in range(n)) for n in range(1, 30)]
        return out

    def test_arbitrary_bytes(self):
        for name in self.ARBITRARY:
            for data in self.samples():
                with self.subTest(name=name, data=data[:12]):
                    encoded = enc(name, data)
                    self.assertEqual(dec(name, encoded), data)
                    self.assertEqual(dec(name, encoded, strict=True) if REG.get(name).info.accepts("strict")
                                     else dec(name, encoded), data)

    def test_base10_integer_roundtrip_with_length(self):
        rng = random.Random(5)
        for n in range(1, 60):
            data = bytes(rng.randrange(256) for _ in range(n))
            e = enc("base10", data, mode="integer")
            self.assertEqual(dec("base10", e, mode="integer", length=n), data)

    def test_z85(self):
        rng = random.Random(9)
        for n in range(0, 80, 4):
            data = bytes(rng.randrange(256) for _ in range(n))
            self.assertEqual(dec("z85", enc("z85", data)), data)

    def test_text_codecs(self):
        for text in ["", "plain", "héllo wörld", "<tag attr=\"v\">&amp;</tag>", "日本語 😀 mixed", "tab\tnl\nx", "back\\slash"]:
            for name in ["html", "unicode-escape"]:
                with self.subTest(name=name, text=text):
                    self.assertEqual(dec(name, enc(name, text)), text.encode())
        for text in ["HELLO WORLD 123", "SOS", "A"]:
            self.assertEqual(dec("morse", enc("morse", text)), text.encode())
        for text in ["HELLO WORLD", "A B C"]:
            self.assertEqual(dec("a1z26", enc("a1z26", text)), text.encode())

    def test_params_roundtrip(self):
        data = bytes(range(0, 256, 7))
        for name, p in [("base64", {"pad": False}), ("base64url", {"pad": False}), ("base32", {"pad": False}),
                        ("base36", {"zeros": False}), ("base62", {"variant": "digits-lower-upper"}),
                        ("hex", {"upper": True}), ("rotn", {"n": 7, "digits": True}), ("xor", {"key": "hex:a5"}),
                        ("xor", {"key": b"secret"}), ("ascii85", {"adobe": True}), ("url", {"plus": True})]:
            with self.subTest(name=name, p=p):
                d = data.lstrip(b"\x00") if name in ("base36", "base62") else data
                self.assertEqual(dec(name, enc(name, d, **p), **p), d)


class Tolerance(unittest.TestCase):
    def test_base64_permissive_vs_strict(self):
        self.assertEqual(dec("base64", "SGVsbG8"), b"Hello")  # missing padding
        self.assertEqual(dec("base64", "SGVs\nbG8gV29y\r\nbGQ="), b"Hello World")  # wrapped lines
        self.assertEqual(dec("base64", "  SGk=  \n"), b"Hi")
        for bad in ["SGVsbG8", "SGVs bG8=", "SGk", "SGl="]:  # last: non-canonical trailing bits
            with self.subTest(bad=bad), self.assertRaises(DecodeError):
                dec("base64", bad, strict=True)
        self.assertEqual(dec("base64", "SGk=", strict=True), b"Hi")
        self.assertEqual(dec("base64url", "_-8"), b"\xff\xef")
        self.assertEqual(dec("base64url", "_-8", strict=False), b"\xff\xef")

    def test_base64_rejects_wrong_alphabet_and_impossible_length(self):
        with self.assertRaises(DecodeError):
            dec("base64", "SGVs-G8=")  # '-' belongs to base64url
        with self.assertRaises(DecodeError):
            dec("base64url", "SGVs+G8=")
        with self.assertRaises(DecodeError):
            dec("base64", "A")  # 6 bits cannot make a byte
        with self.assertRaises(DecodeError):
            dec("base64", "SG=Vs")  # padding in the middle

    def test_hex_notations(self):
        for text in ["0x48 0x69", r"\x48\x69", "48:69", "48-69", "48 69", "4869\n", "48,69"]:
            with self.subTest(text=text):
                self.assertEqual(dec("hex", text), b"Hi")
        with self.assertRaises(DecodeError):
            dec("hex", "0x48 0x69", strict=True)
        with self.assertRaises(DecodeError):
            dec("hex", "486")
        with self.assertRaises(DecodeError):
            dec("hex", "48zz")

    def test_base32_case_and_padding(self):
        self.assertEqual(dec("base32", "mzxw6ytboi"), b"foobar")
        with self.assertRaises(DecodeError):
            dec("base32", "mzxw6ytboi", strict=True)
        with self.assertRaises(DecodeError):
            dec("base32", "M")
        with self.assertRaises(DecodeError):
            dec("base32", "MZXW1YTB")  # '1' not in alphabet

    def test_non_ascii_text_rejected_cleanly(self):
        for name in ["hex", "base64", "base32", "base58", "base85", "z85", "base2"]:
            with self.subTest(name=name), self.assertRaises(DecodeError):
                dec(name, "héllo".encode())


class MalformedInput(unittest.TestCase):
    """No decoder may leak a non-Cryptix exception on hostile input."""

    HOSTILE = [b"", b"\x00", b"\xff\xfe\xfd", b"!!!!@@@@", b"=" * 9, b"%", b"%zz", b"&#99999999999;",
               b"\\u", b"\\ud800", b"A" * 3, b"\x1f\x8b\x08", b"BZh9", b"\xfd7zXZ\x00", b"x\x9c",
               bytes(range(256)), b"9" * 5000, b" " * 10, b"\n", b"-----", b"<~", b"<~abc", b"z" * 7]

    def test_decoders_only_raise_cryptix_errors(self):
        for plugin in REG.all(Decoder):
            params = {"key": b"k"} if plugin.info.name == "xor" else {}
            for data in self.HOSTILE:
                for strict in ([False, True] if plugin.info.accepts("strict") else [False]):
                    kw = dict(params, **({"strict": strict} if plugin.info.accepts("strict") else {}))
                    with self.subTest(plugin=plugin.info.name, data=data[:10], strict=strict):
                        try:
                            plugin.decode(data, **kw)
                        except CryptixError:
                            pass

    def test_encoders_only_raise_cryptix_errors(self):
        for plugin in REG.all(Encoder):
            params = {"key": b"k"} if plugin.info.name == "xor" else {}
            for data in self.HOSTILE:
                with self.subTest(plugin=plugin.info.name, data=data[:10]):
                    try:
                        plugin.encode(data, **params)
                    except CryptixError:
                        pass

    def test_huge_decimal_does_not_crash(self):
        import sys

        old = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(0)
            big = enc("base10", bytes([1]) + bytes(5000), mode="integer")
            self.assertGreater(len(big), 4300)
            self.assertEqual(dec("base10", big, mode="integer"), bytes([1]) + bytes(5000))
        finally:
            sys.set_int_max_str_digits(old)


class Detection(unittest.TestCase):
    def conf(self, name, data):
        d = REG.get(name).detect(data)
        return d.confidence if d else 0.0

    def test_positive(self):
        self.assertGreaterEqual(self.conf("base64", b"SGVsbG8gV29ybGQ="), 0.8)
        self.assertGreaterEqual(self.conf("hex", b"48656c6c6f20776f726c64"), 0.5)
        self.assertGreaterEqual(self.conf("gzip", gzip.compress(b"x")), 0.9)
        self.assertGreaterEqual(self.conf("zlib", zlib.compress(b"x")), 0.7)
        self.assertGreaterEqual(self.conf("bzip2", bz2.compress(b"x")), 0.9)
        self.assertGreaterEqual(self.conf("lzma", lzma.compress(b"x")), 0.9)
        self.assertGreaterEqual(self.conf("base2", b"0100100001101001"), 0.7)
        self.assertGreaterEqual(self.conf("morse", b"... --- ..."), 0.7)
        self.assertGreaterEqual(self.conf("url", b"a%20b"), 0.5)
        self.assertGreaterEqual(self.conf("ascii85", b"<~87cURDZ~>"), 0.9)
        self.assertGreaterEqual(self.conf("base32", b"MZXW6YTBOI======"), 0.7)
        self.assertGreaterEqual(self.conf("a1z26", b"8 5 12 12 15"), 0.5)
        self.assertGreaterEqual(self.conf("unicode-escape", rb"\u0048\u0069"), 0.5)

    def test_negative(self):
        self.assertEqual(self.conf("base64", b"hello world, this is plain text!"), 0.0)
        self.assertEqual(self.conf("hex", b"hello"), 0.0)
        self.assertEqual(self.conf("gzip", b"plain"), 0.0)
        self.assertEqual(self.conf("base2", b"0102"), 0.0)
        self.assertEqual(self.conf("morse", b"hello"), 0.0)
        self.assertEqual(self.conf("base64", b"\xff\xfe\x00"), 0.0)

    def test_ambiguity_is_reflected(self):
        # a hex string is also valid base64: base64 must not outrank hex by much
        text = b"48656c6c6f20776f726c64"
        self.assertLess(self.conf("base64", text), 0.6)
        # all-digit hex is more likely a decimal number
        self.assertLess(self.conf("hex", b"12345678"), 0.3)
        # base64url must only claim data that actually uses its distinct characters
        self.assertEqual(self.conf("base64url", b"SGVsbG8="), 0.0)
        self.assertGreater(self.conf("base64url", b"_-8="), 0.5)

    def test_detect_never_raises(self):
        for plugin in REG.all(Decoder):
            for data in MalformedInput.HOSTILE:
                with self.subTest(plugin=plugin.info.name, data=data[:8]):
                    d = plugin.detect(data)
                    self.assertTrue(d is None or 0.0 <= d.confidence <= 1.0)


class Analysis(unittest.TestCase):
    def test_bytestats(self):
        r = REG.get("bytestats").analyze(b"AAAA")
        self.assertEqual(r.fields["entropy_bits_per_byte"], 0.0)
        self.assertEqual(r.fields["printable_ratio"], 1.0)
        r = REG.get("bytestats").analyze(bytes(range(256)))
        self.assertAlmostEqual(r.fields["entropy_bits_per_byte"], 8.0)
        self.assertFalse(r.fields["utf8_valid"])

    def test_magic(self):
        labels = lambda d: [f.label for f in REG.get("magic").scan(d)]  # noqa: E731
        self.assertIn("PNG image", labels(b"\x89PNG\r\n\x1a\n" + b"\0" * 8))
        self.assertIn("gzip", labels(gzip.compress(b"x")))
        self.assertIn("ELF executable", labels(b"\x7fELF\x02\x01"))
        self.assertIn("tar archive", labels(b"\0" * 257 + b"ustar\0"))
        self.assertEqual(labels(b"plain text"), [])

    def test_printable_scorer(self):
        s = REG.get("printable-ratio")
        self.assertEqual(s.score(b"hello\n"), 1.0)
        self.assertEqual(s.score(b"\x00\x01"), 0.0)
        self.assertEqual(s.score(b""), 0.0)


if __name__ == "__main__":
    unittest.main()
