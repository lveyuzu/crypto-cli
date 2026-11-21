"""`cryptix auto` through the real CLI (frontend-agnostic) plus terminal-behaviour tests."""

import base64
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from cryptix.cli import commands
from cryptix.cli.context import Context, Options, Streams
from cryptix.cli.io import InputSpec, OutputSpec
from cryptix.core.registry import Registry
from cryptix.search.engine import DEFAULTS
from helpers import cli_env, run_cli

REG = Registry()
REG.discover(entry_points=False, user_dirs=False)
FLAG = b"flag{layers_of_encoding}"
HEX_B64 = base64.b64encode(FLAG.hex().encode())  # decode chain: base64 -> hex


def out(r):
    return r.stdout.decode("utf-8", "replace")


class AutoBasics(unittest.TestCase):
    def test_human_report(self):
        r = run_cli("auto", HEX_B64.decode())
        self.assertEqual((r.returncode, r.stderr), (0, b""))
        t = out(r)
        for s in ["flag{layers_of_encoding}", "chain:   base64 -> hex", "replay:  cryptix chain 'base64|hex'", "KNOWN MATCH", "#1"]:
            self.assertIn(s, t)

    def test_quiet_prints_only_the_flag(self):
        r = run_cli("-q", "auto", HEX_B64.decode())
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, FLAG + b"\n", b""))
        r = run_cli("auto", HEX_B64.decode(), "-q")
        self.assertEqual(r.stdout, FLAG + b"\n")

    def test_quiet_without_flag_exits_nonzero_and_prints_nothing(self):
        for text in ["hello world", "SGVsbG8gV29ybGQ=", "zzzz"]:  # nothing / decodable but no flag
            with self.subTest(text=text):
                r = run_cli("-q", "auto", text)
                self.assertEqual((r.returncode, r.stdout), (1, b""))

    def test_no_result_diagnostic_goes_to_stderr(self):
        r = run_cli("auto", "zzzz")
        self.assertEqual((r.returncode, r.stdout), (1, b""))
        self.assertIn(b"no plausible decoding found", r.stderr)

    def test_decodable_without_flag_lists_candidate(self):
        r = run_cli("auto", "SGVsbG8gV29ybGQ=")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Hello World", out(r))
        self.assertNotIn("MATCH", out(r))

    def test_stdin_and_file(self):
        self.assertEqual(run_cli("-q", "auto", input=HEX_B64 + b"\n").stdout, FLAG + b"\n")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "challenge.txt")
            p.write_bytes(HEX_B64)
            self.assertEqual(run_cli("-q", "auto", "--file", str(p)).stdout, FLAG + b"\n")
            self.assertEqual(run_cli("-q", "auto", "-f", "/nonexistent").returncode, 5)

    def test_input_formats(self):
        self.assertEqual(run_cli("-q", "auto", "-I", "hex", HEX_B64.hex()).stdout, FLAG + b"\n")

    def test_no_progress_noise_when_not_a_terminal(self):
        r = run_cli("auto", HEX_B64.decode())
        self.assertNotIn(b"\r", r.stderr + r.stdout)
        self.assertNotIn(b"searching", r.stderr)


class AutoTargets(unittest.TestCase):
    def test_custom_prefix_regex_known(self):
        data = base64.b64encode(b"HACKME{unknown_prefix_flag}").decode()
        self.assertEqual(run_cli("-q", "auto", data, "--flag-prefix", "HACKME").stdout, b"HACKME{unknown_prefix_flag}\n")
        data = base64.b64encode(b"ticket corp-1234-abc ok").decode()
        r = run_cli("-q", "auto", data, "--flag-regex", r"corp-[0-9]{4}-[a-z]+")
        self.assertEqual(r.stdout, b"corp-1234-abc\n")
        data = base64.b64encode(b"the answer is 42").decode()
        r = run_cli("-q", "auto", data, "--known", "answer is")
        self.assertIn(b"answer is 42", r.stdout)
        r = run_cli("-q", "auto", base64.b64encode(b"x \x00\xde\xad\xbe\xef\x01\x02\x03\x04 y").decode(), "--flag-regex", r"\xde\xad\xbe\xef.{4}")
        self.assertEqual(r.returncode, 0)

    def test_known_accepts_hex_prefix(self):
        data = base64.b64encode(b"magic:\x00\x01\x02 end").decode()
        r = run_cli("auto", data, "--known", "hex:000102", "--no-default-flags")
        self.assertEqual(r.returncode, 0)
        self.assertIn("FRAGMENT MATCH", out(r))

    def test_no_default_flags(self):
        data = HEX_B64.decode()
        self.assertEqual(run_cli("-q", "auto", data, "--no-default-flags").returncode, 1)
        self.assertEqual(run_cli("-q", "auto", data, "--no-default-flags", "--flag-prefix", "flag").returncode, 0)

    def test_invalid_options_are_usage_errors(self):
        for argv in (["--flag-regex", "(unclosed"], ["--strategy", "bogus"], ["--max-output", "lots"], ["--depth", "0"],
                     ["--only", "no-such-op"], ["--time-limit", "0"]):
            with self.subTest(argv=argv):
                r = run_cli("auto", "SGk=", *argv)
                self.assertIn(r.returncode, (2, 4), r.stderr)  # 2 = usage, 4 = unknown operation
                self.assertEqual(r.stdout, b"")
                self.assertNotIn(b"Traceback", r.stderr)


class AutoOutput(unittest.TestCase):
    def test_json(self):
        j = json.loads(out(run_cli("--json", "auto", HEX_B64.decode())))
        self.assertTrue(j["flag_found"])
        c = j["candidates"][0]
        self.assertEqual((c["rank"], c["depth"], c["chain_spec"], c["text"]), (1, 2, "base64|hex", FLAG.decode()))
        self.assertEqual([s["op"] for s in c["chain"]], ["base64", "hex"])
        self.assertEqual(c["flags"][0]["kind"], "known")
        self.assertTrue(all(s["evidence"] for s in c["chain"]))
        self.assertIn("flag", c["score_parts"])
        self.assertEqual(j["stats"]["stop_reason"], "flag found")
        # no result: still valid JSON, exit 1
        r = run_cli("--json", "auto", "zzzz")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(out(r))["candidates"], [])

    def test_top_and_explain(self):
        r = run_cli("auto", "SGVsbG8gV29ybGQ=", "--explain")
        for s in ["why:", "1. base64 [strict", "score:", "textness="]:
            self.assertIn(s, out(r))
        many = run_cli("--json", "auto", HEX_B64.decode(), "--exhaustive", "-n", "1")
        self.assertEqual(len(json.loads(out(many))["candidates"]), 1)

    def test_output_file_and_raw_pipeline(self):
        with tempfile.TemporaryDirectory() as d:
            r = run_cli("auto", HEX_B64.decode(), "-o", f"{d}/best.bin")
            self.assertEqual((r.returncode, r.stdout), (0, b""))
            self.assertEqual(Path(d, "best.bin").read_bytes(), FLAG)
        r = run_cli("auto", HEX_B64.decode(), "-O", "raw")
        self.assertEqual((r.stdout, r.stderr), (FLAG, b""))  # byte exact, report not mixed into stdout
        self.assertEqual(run_cli("auto", HEX_B64.decode(), "-O", "hex").stdout, FLAG.hex().encode() + b"\n")
        self.assertEqual(run_cli("auto", "zzzz", "-O", "raw").returncode, 1)

    def test_binary_result(self):
        import gzip

        png = b"\x89PNG\r\n\x1a\n" + bytes(range(200))
        blob = base64.b64encode(gzip.compress(png))
        r = run_cli("auto", blob.decode())
        self.assertIn("PNG image", out(r))
        self.assertIn("chain:   base64 -> gzip", out(r))
        self.assertEqual(run_cli("auto", "-O", "raw", input=blob).stdout, png)

    def test_limits_through_cli(self):
        deep = base64.b64encode(base64.b64encode(base64.b64encode(FLAG))).decode()
        self.assertEqual(run_cli("-q", "auto", deep, "--depth", "2").returncode, 1)
        self.assertEqual(run_cli("-q", "auto", deep, "--depth", "3").stdout, FLAG + b"\n")
        self.assertEqual(run_cli("-q", "auto", deep, "--max-nodes", "1").returncode, 1)
        for strat in ("best-first", "beam", "bfs"):
            self.assertEqual(run_cli("-q", "auto", deep, "--strategy", strat).stdout, FLAG + b"\n", strat)

    def test_only_exclude(self):
        self.assertEqual(run_cli("-q", "auto", HEX_B64.decode(), "--only", "base64,hex").returncode, 0)
        self.assertEqual(run_cli("-q", "auto", HEX_B64.decode(), "--exclude", "hex").returncode, 1)

    def test_help_documents_auto(self):
        t = out(run_cli("auto", "--help"))
        for s in ["--depth", "--beam", "--max-nodes", "--time-limit", "--flag-regex", "--flag-prefix", "--known",
                  "--exhaustive", "--explain", "--strategy"]:
            self.assertIn(s, t)
        self.assertIn(f"{DEFAULTS.max_depth}", t)


class TerminalBehaviour(unittest.TestCase):
    def streams(self, err_tty):
        return Streams(io.BytesIO(), io.BytesIO(), io.StringIO(), stdin_tty=False, stdout_tty=False, stderr_tty=err_tty)

    def args(self, **kw):
        base = dict(depth=8, beam=16, max_nodes=5000, time_limit=30.0, max_output="16M", strategy="best-first",
                    top=5, min_score=0.3, min_confidence=0.05)
        base.update(kw)
        return commands.AutoArgs(**base)

    def test_progress_shown_only_on_stderr_tty(self):
        for tty, expect in ((True, True), (False, False)):
            s = self.streams(tty)
            ctx = Context(Options(), s, REG)
            code = commands.cmd_auto(ctx, InputSpec(HEX_B64.decode()), OutputSpec(), self.args())
            self.assertEqual(code, 0)
            self.assertEqual("searching..." in s.stderr.getvalue(), expect)
            if expect:
                self.assertTrue(s.stderr.getvalue().endswith("\r\x1b[K"))  # progress line cleared afterwards
            self.assertNotIn(b"searching", s.stdout.getvalue())

    def test_progress_suppressed_by_quiet_and_json(self):
        for opts in (Options(quiet=True), Options(json=True)):
            s = self.streams(True)
            commands.cmd_auto(Context(opts, s, REG), InputSpec(HEX_B64.decode()), OutputSpec(), self.args())
            self.assertNotIn("searching", s.stderr.getvalue())


class CtrlC(unittest.TestCase):
    def test_sigint_returns_partial_results_and_130(self):
        plugin = textwrap.dedent('''
            import time
            from cryptix.core.plugin import Category, Codec, DataKind, Detection, PluginInfo
            class Grow(Codec):
                info = PluginInfo(name="grow", category=Category.TEXT, description="slow, endless",
                                  reversible=True, auto_safe=True, input_type=DataKind.TEXT)
                def _encode(self, data): return data
                def _decode(self, data):
                    time.sleep(0.05)
                    return data + b"x"
                def detect(self, data): return Detection(1.0, "always")
        ''')
        with tempfile.TemporaryDirectory() as d:
            Path(d, "grow.py").write_text(plugin)
            env = cli_env(CRYPTIX_PLUGIN_PATH=d)
            env.pop("CRYPTIX_NO_PLUGINS")
            p = subprocess.Popen([sys.executable, "-m", "cryptix", "auto", "SGVsbG8gV29ybGQ=", "--depth", "1000",
                                  "--max-nodes", "100000", "--time-limit", "60"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            time.sleep(1.5)
            p.send_signal(signal.SIGINT)
            stdout, stderr = p.communicate(timeout=20)
            self.assertEqual(p.returncode, 130, stderr)
            self.assertIn(b"interrupted", stderr)
            self.assertNotIn(b"Traceback", stderr)
            self.assertIn(b"stopped: interrupted", stdout)  # partial report still printed


if __name__ == "__main__":
    unittest.main()
