"""CLI tests. Subprocess tests are frontend-agnostic: they run whichever frontend is installed
(Typer when available, else the argparse fallback), so on a full install they exercise Typer."""

import io
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptix.cli import commands
from cryptix.cli.context import Context, Options, Streams
from cryptix.cli.io import InputSpec, OutputSpec
from cryptix.core.registry import Registry
from helpers import ROOT, cli_env, run_cli

REG = Registry()
REG.discover(entry_points=False, user_dirs=False)


def out(r):
    return r.stdout.decode("utf-8", "replace")


class Basic(unittest.TestCase):
    def test_decode_argument(self):
        r = run_cli("decode", "base64", "SGVsbG8gV29ybGQ=")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"Hello World", b""))

    def test_stdin_pipeline_and_chaining_processes(self):
        a = run_cli("decode", "hex", input=b"48656c6c6f\n")
        self.assertEqual(a.stdout, b"Hello")
        b = run_cli("encode", "base64", input=a.stdout)
        self.assertEqual(b.stdout, b"SGVsbG8=")
        c = run_cli("decode", "base64", "-", input=b.stdout)
        self.assertEqual(c.stdout, b"Hello")

    def test_binary_is_byte_exact_through_pipes(self):
        rng = random.Random(1)
        blob = bytes(rng.randrange(256) for _ in range(200_000)) + b"\x00\xff\r\n\x1b[31m"
        for op in ["base64", "base32", "base85", "hex", "zlib", "gzip", "bzip2", "lzma", "base58", "ascii85"]:
            with self.subTest(op=op):
                e = run_cli("encode", op, input=blob)
                self.assertEqual(e.returncode, 0, e.stderr)
                d = run_cli("decode", op, input=e.stdout)
                self.assertEqual(d.returncode, 0, d.stderr)
                self.assertEqual(d.stdout, blob)

    def test_no_decoration_in_binary_stdout(self):
        r = run_cli("decode", "hex", "1b5b33316d00ff")
        self.assertEqual(r.stdout, b"\x1b[31m\x00\xff")  # exact bytes, no newline, no markup
        self.assertEqual(r.stderr, b"")

    def test_file_input_and_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d, "in.txt"), Path(d, "out.bin")
            src.write_text("SGVsbG8=\n")
            r = run_cli("decode", "base64", "--file", str(src), "-o", str(dst))
            self.assertEqual((r.returncode, r.stdout), (0, b""))
            self.assertEqual(dst.read_bytes(), b"Hello")

    def test_input_formats(self):
        self.assertEqual(run_cli("encode", "hex", "-I", "hex", "00ff").stdout, b"00ff")
        self.assertEqual(run_cli("encode", "hex", "-I", "escaped", r"\x00\xffA").stdout, b"00ff41")
        self.assertEqual(run_cli("encode", "hex", "-I", "latin1", "é").stdout, b"e9")
        self.assertEqual(run_cli("encode", "hex", "é").stdout, b"c3a9")
        r = run_cli("decode", "hex", "zz")
        self.assertEqual(r.returncode, 3)

    def test_output_formats(self):
        self.assertEqual(run_cli("decode", "hex", "00ff41", "-O", "escaped").stdout, b"\\x00\\xffA\n")
        self.assertEqual(run_cli("decode", "hex", "00ff41", "-O", "hex").stdout, b"00ff41\n")
        self.assertEqual(run_cli("decode", "hex", "c3a9", "-O", "text").stdout, "é\n".encode())

    def test_params_strict_and_chain(self):
        self.assertEqual(run_cli("decode", "rotn", "Khoor", "-p", "n=3").stdout, b"Hello")
        self.assertEqual(run_cli("decode", "xor", "-p", "key=hex:4352", "-I", "hex", "0b372f3e2c").stdout, b"Hello")
        self.assertEqual(run_cli("decode", "base64", "SGk").returncode, 0)
        self.assertEqual(run_cli("decode", "base64", "SGk", "--strict").returncode, 3)
        r = run_cli("chain", "base64|hex|rotn(n=3)", "NTQ2NTc4NzQ=")
        self.assertEqual(r.stdout, b"Qbuq")
        r = run_cli("chain", "hex,base64", "--encode", "Hi")
        self.assertEqual(r.stdout, b"NDg2OQ==")  # hex first, then base64 of that text
        r = run_cli("chain", "hex , base64", "--encode", "Hi")
        self.assertEqual(r.stdout, b"NDg2OQ==")
        r = run_cli("chain", "xor(key='a,b')|hex", "-I", "hex", "0102")
        self.assertEqual(r.returncode, 3)  # runs; quoting survived parsing; hex rejects the xor output


class Errors(unittest.TestCase):
    def check(self, args, code, stderr_has, stdin=b""):
        r = run_cli(*args, input=stdin)
        self.assertEqual(r.returncode, code, r.stderr)
        self.assertEqual(r.stdout, b"", "errors must not write to stdout")
        self.assertIn(stderr_has.encode(), r.stderr)
        self.assertNotIn(b"Traceback", r.stderr)

    def test_exit_codes(self):
        self.check(["decode", "nope", "x"], 4, "unknown operation")
        self.check(["decode", "base46", "x"], 4, "base64")  # did-you-mean
        self.check(["decode", "base64", "!!!"], 3, "base64")
        self.check(["decode", "base64", "x", "-p", "bogus=1"], 2, "unknown parameter")
        self.check(["decode", "base64", "x", "-p", "novalue"], 2, "key=value")
        self.check(["decode", "xor", "x"], 2, "missing required parameter")
        self.check(["decode", "base64", "--file", "/nonexistent/file"], 5, "cannot read")
        self.check(["decode", "base64", "eA==", "-o", "/nonexistent/dir/out"], 5, "cannot write")
        self.check(["decode", "base64", "x", "--file", "y"], 2, "not both")
        self.check(["decode", "hex", "-I", "hex", "zz"], 2, "hex")
        self.check(["encode", "gzip-nope", "x"], 4, "unknown operation")
        self.check(["chain", "base64|nope", "x"], 4, "unknown operation")
        self.check(["chain", "base64|", "x"], 2, "empty step")
        self.check(["chain", "base64(n=", "x"], 2, "unbalanced")
        self.check(["list", "-c", "nonsense"], 2, "unknown category")
        self.check(["explain", "nope"], 4, "unknown operation")

    def test_wrong_role(self):
        self.check(["decode", "bytestats", "x"], 2, "cannot decode")

    def test_usage_error_exit_code(self):
        r = run_cli("decode")  # missing OPERATION
        self.assertEqual(r.returncode, 2)

    def test_no_input_decodes_empty_stdin(self):
        r = run_cli("decode", "hex", input=b"")
        self.assertEqual((r.returncode, r.stdout), (0, b""))

    def test_quiet_suppresses_warnings_only(self):
        r = run_cli("decode", "rot13", "x", "--strict", "-q")  # rot13 has no strict mode
        self.assertEqual((r.returncode, r.stderr), (0, b""))
        r = run_cli("decode", "rot13", "x", "--strict")
        self.assertIn(b"no strict mode", r.stderr)
        self.assertEqual(r.stdout, b"k")

    def test_errors_still_shown_when_quiet(self):
        r = run_cli("decode", "hex", "zz", "-q")
        self.assertEqual(r.returncode, 3)
        self.assertTrue(r.stderr)


class JsonAndVerbose(unittest.TestCase):
    def test_json_shape(self):
        for argv in (["--json", "decode", "base64", "SGk="], ["decode", "base64", "SGk=", "--json"]):
            j = json.loads(out(run_cli(*argv)))
            self.assertEqual(j["operation"], "base64")
            self.assertEqual((j["ok"], j["length"], j["hex"], j["text"], j["utf8_valid"]), (True, 2, "4869", "Hi", True))

    def test_json_binary(self):
        j = json.loads(out(run_cli("--json", "decode", "hex", "ff00")))
        self.assertIsNone(j["text"])
        self.assertFalse(j["utf8_valid"])
        self.assertEqual(j["escaped"], "\\xff\\x00")

    def test_json_chain_steps(self):
        j = json.loads(out(run_cli("--json", "chain", "base64|hex", "NDg2OQ==")))
        self.assertEqual([s["operation"] for s in j["steps"]], ["base64", "hex"])
        self.assertEqual(j["text"], "Hi")

    def test_json_with_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            j = json.loads(out(run_cli("--json", "decode", "hex", "4869", "-o", f"{d}/o")))
            self.assertTrue(j["ok"])
            self.assertEqual(Path(d, "o").read_bytes(), b"Hi")

    def test_verbose_goes_to_stderr(self):
        r = run_cli("-v", "decode", "hex", "4869")
        self.assertEqual(r.stdout, b"Hi")
        self.assertIn(b"hex: decoded 4 -> 2 bytes", r.stderr)

    def test_no_color_has_no_ansi(self):
        for argv in (["--no-color", "list"], ["list"]):
            self.assertNotIn(b"\x1b[", run_cli(*argv).stdout)
        r = run_cli("list", env=cli_env(NO_COLOR="1"))
        self.assertNotIn(b"\x1b[", r.stdout)


class Introspection(unittest.TestCase):
    def test_list(self):
        r = run_cli("list")
        self.assertEqual(r.returncode, 0)
        for name in ["base64", "hex", "z85", "xor", "gzip", "morse", "magic"]:
            self.assertIn(name, out(r))
        names = out(run_cli("-q", "list", "-c", "compression")).split()
        self.assertEqual(names, ["bzip2", "deflate", "gzip", "lzma", "zlib"])
        self.assertEqual(out(run_cli("-q", "list", "-r", "detector")).split(), ["magic"])
        self.assertEqual(run_cli("list", "-s", "no-such-thing-xyz").returncode, 1)
        j = json.loads(out(run_cli("--json", "list", "-c", "base")))
        self.assertTrue(all(e["category"] == "base" for e in j))
        self.assertIn("base64url", [e["name"] for e in j])

    def test_explain_every_operation(self):
        names = out(run_cli("-q", "list")).split()
        self.assertGreaterEqual(len(names), 30)
        for n in names:
            with self.subTest(op=n):
                r = run_cli("explain", n)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(n, out(r))
                json.loads(out(run_cli("--json", "explain", n)))

    def test_explain_content(self):
        t = out(run_cli("explain", "base62"))
        for s in ["variant", "digits-lower-upper", "reversible", "cost", "examples:", "detection"]:
            self.assertIn(s, t)
        self.assertEqual(run_cli("explain", "b64").returncode, 0)  # alias

    def test_explain_examples_are_runnable_as_printed(self):
        # the documented command line really produces the documented output
        for plugin in REG.all():
            for ex in plugin.info.examples[:1]:
                if "\\" in ex.encoded.decode("latin1") and plugin.info.name == "url":
                    continue
                from cryptix.core.data import to_escaped
                argv = ["decode", plugin.info.name]
                for k, v in ex.params.items():
                    argv += ["-p", f"{k}={v}"]
                argv += ["--input-format", "escaped", to_escaped(ex.encoded), "-O", "escaped"]
                with self.subTest(op=plugin.info.name):
                    r = run_cli(*argv)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(out(r).rstrip("\n"), to_escaped(ex.decoded))

    def test_version_and_plugins(self):
        self.assertIn("cryptix 0.2.0", out(run_cli("version")))
        self.assertEqual(out(run_cli("-q", "version")).strip(), "0.2.0")
        self.assertEqual(json.loads(out(run_cli("--json", "version")))["cryptix"], "0.2.0")
        self.assertIn("builtin", out(run_cli("plugins")))
        self.assertEqual(json.loads(out(run_cli("--json", "plugins")))["load_errors"], [])

    def test_help_has_examples(self):
        for argv in (["--help"], ["decode", "--help"], ["chain", "--help"]):
            r = run_cli(*argv)
            self.assertEqual(r.returncode, 0)
            self.assertIn("cryptix decode base64", out(r), argv)


class Pipes(unittest.TestCase):
    def test_broken_pipe_is_quiet(self):
        with tempfile.TemporaryDirectory() as d:
            big = Path(d, "big.hex")
            big.write_text("41" * 3_000_000)
            p = subprocess.Popen([sys.executable, "-m", "cryptix", "decode", "hex", "-f", str(big)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=cli_env())
            assert p.stdout is not None
            first = p.stdout.read(10)
            p.stdout.close()  # like `| head -c 10`
            assert p.stderr is not None
            err = p.stderr.read()
            p.stderr.close()
            p.wait(timeout=60)
            self.assertEqual(first, b"A" * 10)
            self.assertNotIn(b"Traceback", err)
            self.assertNotIn(b"BrokenPipe", err)

    def test_huge_integer_mode(self):
        blob = b"\x01" + bytes(20_000)  # 48k-digit integer: needs the lifted int/str limit
        e = run_cli("encode", "base10", "-p", "mode=integer", input=blob)
        self.assertEqual(e.returncode, 0, e.stderr)
        d = run_cli("decode", "base10", "-p", "mode=integer", input=e.stdout)
        self.assertEqual(d.stdout, blob)


class TerminalBehaviour(unittest.TestCase):
    """stdout-is-a-tty behaviour, exercised in-process with fake streams."""

    def ctx(self, tty, stdin=b""):
        s = Streams(io.BytesIO(stdin), io.BytesIO(), io.StringIO(), stdin_tty=False, stdout_tty=tty)
        return Context(Options(), s, REG), s

    def test_tty_text_gets_newline(self):
        c, s = self.ctx(True)
        self.assertEqual(commands.cmd_decode(c, "hex", InputSpec("4869"), OutputSpec(), [], False), 0)
        self.assertEqual(s.stdout.getvalue(), b"Hi\n")

    def test_tty_binary_is_escaped_not_dumped(self):
        c, s = self.ctx(True)
        commands.cmd_decode(c, "hex", InputSpec("1b5b00ff"), OutputSpec(), [], False)
        self.assertEqual(s.stdout.getvalue(), b"\\x1b[\\x00\\xff\n")
        self.assertIn("binary output", s.stderr.getvalue())

    def test_tty_explicit_raw_is_honoured(self):
        c, s = self.ctx(True)
        commands.cmd_decode(c, "hex", InputSpec("00ff"), OutputSpec("raw"), [], False)
        self.assertEqual(s.stdout.getvalue(), b"\x00\xff")

    def test_pipe_is_raw(self):
        c, s = self.ctx(False)
        commands.cmd_decode(c, "hex", InputSpec("4869"), OutputSpec(), [], False)
        self.assertEqual(s.stdout.getvalue(), b"Hi")

    def test_stdin_tty_without_input_is_usage_error(self):
        s = Streams(io.BytesIO(), io.BytesIO(), io.StringIO(), stdin_tty=True, stdout_tty=False)
        c = Context(Options(), s, REG)
        self.assertEqual(commands.cmd_decode(c, "hex", InputSpec(), OutputSpec(), [], False), 2)
        self.assertIn("no input", s.stderr.getvalue())
        self.assertEqual(s.stdout.getvalue(), b"")

    def test_internal_errors_are_reported_not_raised(self):
        c, s = self.ctx(False)
        c.registry = Registry()

        from cryptix.core.plugin import Category, Codec, PluginInfo

        class Buggy(Codec):
            info = PluginInfo(name="buggy", category=Category.OTHER, description="d", reversible=True)
            def _encode(self, d): raise RuntimeError("bug")
            def _decode(self, d): raise RuntimeError("bug")

        c.registry.register(Buggy)
        self.assertEqual(commands.cmd_decode(c, "buggy", InputSpec("x"), OutputSpec(), [], False), 70)
        self.assertIn("internal error", s.stderr.getvalue())


class ExamplePlugin(unittest.TestCase):
    SRC = ROOT / "examples" / "plugins" / "dna_codec.py"

    def env(self, d):
        e = cli_env(CRYPTIX_PLUGIN_PATH=str(d))
        e.pop("CRYPTIX_NO_PLUGINS")
        return e

    def test_registry_loads_example(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "dna_codec.py").write_text(self.SRC.read_text())
            r = Registry()
            r.discover(builtins=False, entry_points=False, user_dirs=[Path(d)])
            self.assertEqual(r.errors, [])
            self.assertEqual(r.get("dna").encode(b"Hi").data, b"CAGACGGC")
            self.assertEqual(r.get("dna-bases").decode(b"cagacggc").data, b"Hi")
            # table T=00 G=01 C=10 A=11: G,T,C,T -> 01 00 10 00 -> 0x48 = "H"
            self.assertEqual(r.get("dna").decode(b"GTCT", mapping="TGCA").data, b"H")

    def test_cli_discovers_example_without_touching_dispatcher(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "dna_codec.py").write_text(self.SRC.read_text())
            Path(d, "broken.py").write_text("raise RuntimeError('boom')\n")
            env = self.env(d)
            self.assertEqual(run_cli("encode", "dna", "Hi", env=env).stdout, b"CAGACGGC")
            self.assertEqual(run_cli("decode", "dna", "CAGACGGC", env=env).stdout, b"Hi")
            self.assertEqual(run_cli("chain", "dna|base64", "--encode", "Hi", env=env).returncode, 0)
            self.assertIn("dna", out(run_cli("-q", "list", "-s", "dna", env=env)))
            self.assertIn("LOAD ERROR", out(run_cli("plugins", env=env)))
            self.assertIn("user-file", out(run_cli("explain", "dna", env=env)))
            # a broken sibling plugin must not break unrelated commands
            self.assertEqual(run_cli("decode", "hex", "4869", env=env).stdout, b"Hi")
            self.assertEqual(run_cli("decode", "dna", "ACGX", env=env).returncode, 3)
            self.assertEqual(run_cli("decode", "dna", "ACG", env=env).returncode, 3)
            self.assertEqual(run_cli("decode", "dna", "ACGT", "-p", "mapping=AAAA", env=env).returncode, 2)


if __name__ == "__main__":
    unittest.main()
