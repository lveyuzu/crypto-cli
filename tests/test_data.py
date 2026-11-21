import os
import random
import unittest

from cryptix.core.data import (
    bytes_from_arg, bytes_from_stream, format_output, is_texty, parse_bytes_arg,
    parse_escaped, parse_hex, to_escaped,
)  # fmt: skip
from cryptix.errors import InputError


class EscapedTests(unittest.TestCase):
    def test_roundtrip_all_bytes(self):
        data = bytes(range(256))
        self.assertEqual(parse_escaped(to_escaped(data)), data)

    def test_roundtrip_random(self):
        rng = random.Random(7)
        for n in range(0, 80):
            data = bytes(rng.randrange(256) for _ in range(n))
            self.assertEqual(parse_escaped(to_escaped(data)), data)

    def test_known_parses(self):
        cases = {
            r"\x41\x42": b"AB", r"A\n": b"A\n", r"\101": b"A", r"\0": b"\x00", r"\\": b"\\",
            r"\u00e9": "é".encode(), r"\U0001f600": "😀".encode(), "plain é": "plain é".encode(),
            r"\x00\xff": b"\x00\xff", "a\\\nb": b"ab",
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(parse_escaped(text), want)

    def test_hex_then_letters_not_swallowed(self):
        # exactly two hex digits are consumed: \x41BC is 'A' + 'BC'
        self.assertEqual(parse_escaped(r"\x41BC"), b"ABC")

    def test_invalid(self):
        for text in ["\\", r"\q", r"\x4", r"\xzz", r"\u12", r"\777", r"\UFFFFFFFF", r"\ud800"]:
            with self.subTest(text=text), self.assertRaises(InputError):
                parse_escaped(text)

    def test_no_code_execution(self):
        # must be treated as data, never evaluated
        self.assertEqual(parse_escaped("__import__('os')"), b"__import__('os')")


class HexTests(unittest.TestCase):
    def test_forms(self):
        for text in ["4142", "41 42", "0x41 0x42", r"\x41\x42", "41:42", "41-42", "41,42", "4142\n"]:
            with self.subTest(text=text):
                self.assertEqual(parse_hex(text), b"AB")

    def test_errors(self):
        for text in ["414", "zz", "41 4"]:
            with self.subTest(text=text), self.assertRaises(InputError):
                parse_hex(text)


class InputFormatTests(unittest.TestCase):
    def test_arg_raw_preserves_invalid_utf8(self):
        arg = os.fsdecode(b"\xff\xfeabc")  # what argv looks like for non-UTF-8 bytes
        self.assertEqual(bytes_from_arg(arg, "raw"), b"\xff\xfeabc")
        with self.assertRaises(InputError):
            bytes_from_arg(arg, "utf8")

    def test_arg_latin1_vs_utf8(self):
        self.assertEqual(bytes_from_arg("é", "raw"), b"\xc3\xa9")
        self.assertEqual(bytes_from_arg("é", "latin1"), b"\xe9")
        with self.assertRaises(InputError):
            bytes_from_arg("€", "latin1")

    def test_stream_formats(self):
        self.assertEqual(bytes_from_stream(b"\x00\xff", "raw"), b"\x00\xff")
        self.assertEqual(bytes_from_stream(b"4869\n", "hex"), b"Hi")
        self.assertEqual(bytes_from_stream(b"\\x48i\n", "escaped"), b"Hi")  # one trailing newline dropped
        self.assertEqual(bytes_from_stream(b"\\x48i\\n\n", "escaped"), b"Hi\n")
        with self.assertRaises(InputError):
            bytes_from_stream(b"\xff", "utf8")

    def test_unknown_format(self):
        with self.assertRaises(InputError):
            bytes_from_arg("x", "nope")


class OutputFormatTests(unittest.TestCase):
    def test_formats(self):
        d = b"A\x00\xff\n"
        self.assertEqual(format_output(d, "raw"), d)
        self.assertEqual(format_output(d, "hex"), b"410Aff0a"[:0] + b"4100ff0a\n")
        self.assertEqual(format_output(d, "escaped"), b"A\\x00\\xff\\n\n")
        self.assertEqual(format_output(b"\xff", "latin1"), "ÿ\n".encode())
        self.assertEqual(format_output(b"a\xffb", "text"), "a\ufffdb\n".encode())

    def test_is_texty(self):
        self.assertTrue(is_texty(b"hello\nworld\t"))
        self.assertTrue(is_texty("héllo".encode()))
        self.assertFalse(is_texty(b"\x00abc"))
        self.assertFalse(is_texty(b"\xff\xfe"))
        self.assertFalse(is_texty(b"\x1b[31m"))


class BytesArgTests(unittest.TestCase):
    def test_prefixes(self):
        self.assertEqual(parse_bytes_arg("hex:41ff"), b"A\xff")
        self.assertEqual(parse_bytes_arg("b64:QUJD"), b"ABC")
        self.assertEqual(parse_bytes_arg("esc:\\x00A"), b"\x00A")
        self.assertEqual(parse_bytes_arg("int:65"), b"A")
        self.assertEqual(parse_bytes_arg("int:0x4142"), b"AB")
        self.assertEqual(parse_bytes_arg("str:hex:41"), b"hex:41")
        self.assertEqual(parse_bytes_arg("plain"), b"plain")
        self.assertEqual(parse_bytes_arg("unknown:prefix"), b"unknown:prefix")

    def test_errors(self):
        for bad in ["hex:zz", "b64:!!!", "int:-1", "int:abc"]:
            with self.subTest(bad=bad), self.assertRaises(InputError):
                parse_bytes_arg(bad)


if __name__ == "__main__":
    unittest.main()
