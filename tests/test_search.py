"""Auto-decoder tests: scoring layers, flag matching, search engine, limits, regressions."""

import base64
import bz2
import gzip
import itertools
import lzma
import random
import time
import unittest
import zlib

from cryptix.core.plugin import Category, Codec, DataKind, Detection, PluginInfo
from cryptix.core.registry import Registry
from cryptix.errors import UsageError
from cryptix.search.engine import AutoDecoder, SearchConfig, explain_path, names_set, parse_size
from cryptix.search.flags import FlagMatcher, hint_forms
from cryptix.search.language import english_score
from cryptix.search.scoring import CandidateScorer, signature_names, textness

REG = Registry()
REG.discover(entry_points=False, user_dirs=False)
FLAG = b"flag{layers_of_encoding}"
LOSSY = {"morse", "a1z26"}  # these encoders discard case, so exact-recovery regressions exclude them


def layer(data: bytes, *ops: str) -> bytes:
    for op in ops:
        if op == "z85":
            data += b" " * (-len(data) % 4)
        data = REG.get(op).encode(data).data
    return data


def auto(data: bytes, matcher: FlagMatcher | None = None, **cfg) -> "SearchResult":  # noqa: F821
    return AutoDecoder(REG, SearchConfig(**cfg), matcher).run(data)


def strong_flags(res):
    return [f for n in res.flag_nodes for f in n.score.flags if f.kind != "generic"]


class LanguageTests(unittest.TestCase):
    def test_english_vs_not(self):
        for s in [b"Hello World", b"The quick brown fox jumps over the lazy dog",
                  b"Congratulations, you have found the secret message hidden in this file."]:
            self.assertGreater(english_score(s), 0.5, s)
        for s in [b"Uryyb Jbeyq, guvf vf n frperg zrffntr", b"48656c6c6f20576f726c64", b"12345678901234567890",
                  b"U29tZSBiYXNlNjQgdGV4dCB0aGF0IGlzIGxvbmc=", bytes(range(256)), b"", b"ab"]:
            self.assertLess(english_score(s), 0.25, s)

    def test_caesar_shift_scores_below_plaintext(self):
        plain = b"We will meet at the old bridge tomorrow morning before the rain starts"
        shifted = bytes((b - 97 + 3) % 26 + 97 if 97 <= b <= 122 else b for b in plain)
        self.assertGreater(english_score(plain), english_score(shifted) + 0.4)


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.s = CandidateScorer(FlagMatcher())

    def sc(self, data, **kw):
        return self.s.score(data, **kw)

    def test_flag_dominates(self):
        self.assertGreater(self.sc(FLAG).total, self.sc(b"The quick brown fox jumps over the lazy dog").total + 5)

    def test_plaintext_beats_still_encoded(self):
        hexed = layer(b"Hello there, this is a message", "hex")
        self.assertGreater(self.sc(b"Hello there, this is a message", potential=0.0).total,
                           self.sc(hexed, potential=0.6).total)

    def test_non_english_text_is_still_text(self):
        for text in ["Привет, мир! Это тестовое сообщение.", "こんにちは世界、これはテストです。", "Ceci est un message secret"]:
            self.assertGreater(textness(text.encode()), 0.95, text)
            self.assertGreater(self.sc(text.encode()).total, 0.35, text)  # text, though no English bonus
            self.assertGreater(self.sc(text.encode()).total, self.sc(bytes(range(200, 256)) * 3).total + 0.25)

    def test_binary_and_random(self):
        rnd = random.Random(1)
        noise = bytes(rnd.randrange(256) for _ in range(512))
        self.assertLess(self.sc(noise).total, 0.1)
        self.assertEqual(self.sc(noise).parts["random_penalty"], -0.15)
        png = b"\x89PNG\r\n\x1a\n" + noise[:100]
        self.assertGreater(self.sc(png).total, self.sc(noise).total + 0.1)
        self.assertEqual(self.sc(png).signatures, ("PNG image",))

    def test_signatures(self):
        self.assertEqual(signature_names(b"\x1f\x8b\x08\x00" + b"\0" * 20)[0], ("gzip",))
        self.assertEqual(signature_names(zlib.compress(b"hello world, hello world"))[0], ("zlib stream",))
        self.assertEqual(signature_names(b"BM")[1], 0.2)  # weak 2-byte magic
        self.assertEqual(signature_names(b"plain")[0], ())

    def test_complexity_penalty(self):
        a, b = self.sc(b"hello world again", depth=1), self.sc(b"hello world again", depth=4, cost=4)
        self.assertGreater(a.total, b.total)

    def test_short_outputs_damped(self):
        self.assertLess(textness(b"ab"), textness(b"abcdefgh"))
        self.assertEqual(textness(b""), 0.0)

    def test_priority_caps_generic_flag(self):
        generic = self.s.score(b"zork{abcdefg}")
        self.assertTrue(generic.flags and generic.flags[0].kind == "generic")
        self.assertLess(self.s.priority(generic, 0.0), 2.0)  # ranking uses the full strength, priority does not


class FlagMatcherTests(unittest.TestCase):
    def test_defaults(self):
        m = FlagMatcher()
        for data, kind in [(b"xx flag{abc_123} yy", "known"), (b"CTF{Up_per}", "known"), (b"picoCTF{x_y_z}", "known"),
                           (b"zork{abcd_efg}", "generic")]:
            with self.subTest(data=data):
                self.assertEqual(m.scan(data)[0].kind, kind)
        for data in [b"hello world", b"no braces here", b"a{b}", b"body{color:red;margin:0}", b"x{" + b"a" * 300]:
            with self.subTest(data=data):
                self.assertEqual([f for f in m.scan(data) if f.kind == "known"], [])

    def test_generic_rejects_punctuation_soup(self):
        self.assertEqual(FlagMatcher().scan(b'$tJf"aGagp;u8{#$%^&*()_+!!}'), [])

    def test_custom_regex_prefix_fragment(self):
        m = FlagMatcher(regexes=[r"corp-[0-9]{4}-[a-z]+"], prefixes=["HACKME"], fragments=[b"secret is"], defaults=False)
        data = b"x corp-1234-abc y HACKME{win_now} and the secret is 42\nnext line"
        kinds = {f.kind: f for f in m.scan(data)}
        self.assertEqual(kinds["custom"].data, b"corp-1234-abc")
        self.assertEqual(kinds["prefix"].data, b"HACKME{win_now}")
        self.assertIn(b"secret is 42", kinds["fragment"].data)
        self.assertEqual(m.scan(b"flag{default_off}"), [])  # defaults disabled
        self.assertTrue(m.has_targets)
        self.assertFalse(FlagMatcher().has_targets)

    def test_prefix_with_brace_and_binary_regex(self):
        self.assertEqual(FlagMatcher(prefixes=["X{"], defaults=False).scan(b"X{a}")[0].data, b"X{a}")
        m = FlagMatcher(regexes=[rb"\xde\xad\xbe\xef.{4}"], defaults=False)
        self.assertEqual(m.scan(b"\x00\xde\xad\xbe\xef\x01\x02\x03\x04\xff")[0].data, b"\xde\xad\xbe\xef\x01\x02\x03\x04")

    def test_invalid_regex_is_usage_error(self):
        with self.assertRaises(UsageError):
            FlagMatcher(regexes=["(unclosed"])

    def test_bounded_scanning_windows(self):
        m = FlagMatcher(scan_limit=1 << 20)
        big = bytearray(b"\x00" * (12 << 20))
        big[6 << 20 : (6 << 20) + len(FLAG)] = FLAG  # in the middle: outside both windows
        t = time.time()
        self.assertEqual(m.scan(bytes(big)), [])
        big[-len(FLAG) - 5 : -5] = FLAG
        self.assertEqual(m.scan(bytes(big))[0].data, FLAG)  # tail window
        big[100 : 100 + len(FLAG)] = FLAG
        self.assertEqual(len(m.scan(bytes(big))), 2)  # head + tail
        self.assertLess(time.time() - t, 5.0)

    def test_match_cap(self):
        many = b" ".join(b"flag{item_%d}" % i for i in range(500))
        self.assertLessEqual(len(FlagMatcher(max_matches=7).scan(many)), 7)

    def test_hint_forms_appear_at_every_base64_alignment(self):
        rnd = random.Random(2)
        for frag in [b"flag{", b"CTF{", b"secret is", b"HTB{x"]:
            forms = hint_forms(frag)["base64"]
            for k in range(6):  # alignment 0,1,2 and repeats
                for _ in range(10):
                    blob = bytes(rnd.randrange(256) for _ in range(k)) + frag + bytes(rnd.randrange(256) for _ in range(7))
                    enc = base64.b64encode(blob)
                    self.assertTrue(any(f in enc for f in forms), (frag, k))

    def test_other_hint_forms(self):
        f = hint_forms(b"flag{")
        self.assertIn(b"666c61677b", f["hex"])
        self.assertIn(b"synt{", f["rot13"])
        self.assertIn(b"{galf", f["reversed"])
        self.assertIn(b"01100110", f["binary"][0])
        m = FlagMatcher()
        self.assertTrue(m.hints(b"zzzz" + b"666c61677b" + b"zzzz"))
        self.assertEqual(m.hints(b"nothing to see"), [])


class SyntheticChallenges(unittest.TestCase):
    CASES = [
        ("base64",), ("hex", "base64"), ("gzip", "base64", "hex"), ("base32", "base64"),
        ("zlib", "base85", "base64"), ("bzip2", "base64"), ("lzma", "base32hex"), ("url", "base64"),
        ("base64", "base64", "base64", "base64", "base64", "base64"), ("base58", "hex"),
        ("base2", "base64"), ("ascii85", "zlib", "hex"), ("html", "base64url"), ("reverse", "base64"),
        ("rot13", "base64"), ("base64", "reverse", "hex"), ("atbash", "base32"), ("rot47", "base64"),
    ]  # fmt: skip

    def test_multilayer_recovery_and_exact_chain(self):
        for ops in self.CASES:
            with self.subTest(ops=ops):
                res = auto(layer(FLAG, *ops))
                self.assertTrue(res.flag_found, ops)
                best = max(res.flag_nodes, key=lambda n: n.score.total)
                self.assertEqual(best.score.flags[0].data, FLAG)
                self.assertEqual(best.data, FLAG)
                # the reported chain, replayed through the real decoders, reproduces the output
                data = layer(FLAG, *ops)
                for op in best.chain:
                    data = REG.get(op).decode(data).data
                self.assertEqual(data, FLAG)
                self.assertLessEqual(best.depth, len(ops))

    def test_flag_embedded_in_sentence(self):
        res = auto(layer(b"The flag is flag{inside_a_sentence} so keep reading.", "base64", "hex"))
        self.assertEqual(strong_flags(res)[0].data, b"flag{inside_a_sentence}")

    def test_wrapped_and_noisy_encodings(self):
        wrapped = b"\n".join(base64.b64encode(FLAG * 4)[i : i + 76] for i in range(0, len(base64.b64encode(FLAG * 4)), 76))
        self.assertTrue(auto(wrapped).flag_found)
        self.assertTrue(auto(layer(FLAG, "hex").upper() + b"\n").flag_found)
        self.assertTrue(auto(base64.b64encode(FLAG).rstrip(b"=")).flag_found)  # missing padding
        self.assertTrue(auto(b"0x" + layer(FLAG, "hex")).flag_found)  # 0x prefix tolerated

    def test_plaintext_input_is_depth_zero(self):
        res = auto(b"hello flag{already_plain} there")
        self.assertEqual(res.candidates[0].depth, 0)
        self.assertEqual(res.candidates[0].chain, [])
        self.assertEqual(res.stats.nodes_generated, 0)

    def test_exhaustive_two_layer_regression(self):
        """Every ordered pair of auto-safe operations (that make a realistic challenge) is recovered."""
        names = [p.info.name for p in REG.decoders() if p.info.auto_safe and p.info.name not in LOSSY]
        blind = {"rot13", "reverse", "atbash", "rot47"}
        binary = {"zlib", "gzip", "bzip2", "lzma"}
        plains = [FLAG, b"The flag is flag{inside_a_sentence} so keep reading."]
        failures, total = [], 0
        for ops in itertools.product(names, repeat=2):
            if ops[0] in blind and ops[1] in blind:
                continue
            if ops[0] in binary and ops[1] in {"rot13", "atbash", "rot47"}:
                continue  # letter ciphers over compressed bytes are not a realistic challenge
            for plain in plains:
                try:
                    data = layer(plain, *ops)
                except Exception:
                    continue  # operation cannot encode this input (e.g. html over binary)
                if data == plain:
                    continue
                total += 1
                res = auto(data, time_limit=10)
                if not any(f.data in plain for f in strong_flags(res)):
                    failures.append((ops, plain[:10]))
        self.assertGreater(total, 1000)
        self.assertEqual(failures, [])

    def test_seeded_random_deep_chains(self):
        rng = random.Random(11)
        ops_pool = [p.info.name for p in REG.decoders() if p.info.auto_safe and p.info.name not in LOSSY]
        blind = {"rot13", "reverse", "atbash", "rot47"}
        ok = total = 0
        for _ in range(250):
            ops = [rng.choice(ops_pool) for _ in range(rng.choice([3, 4, 5]))]
            if any(a in blind and b in blind for a, b in zip(ops, ops[1:])):
                continue
            if any(o in {"rot13", "atbash", "rot47"} and any(p in {"zlib", "gzip", "bzip2", "lzma"} for p in ops[:i])
                   for i, o in enumerate(ops)):
                continue
            try:
                data = layer(FLAG, *ops)
            except Exception:
                continue
            total += 1
            res = auto(data, time_limit=10)
            ok += any(f.data in FLAG for f in strong_flags(res))
        self.assertGreater(total, 150)
        self.assertGreaterEqual(ok / total, 0.95, f"{ok}/{total}")

    def test_non_english_plaintext(self):
        for text in ["Привет, мир! Это тестовое сообщение для кодирования.", "こんにちは世界、これはエンコードのテストです。"]:
            res = auto(layer(text.encode(), "base64", "hex"))
            self.assertEqual(res.candidates[0].data, text.encode(), text)
            self.assertFalse(res.flag_found)

    def test_binary_plaintext_and_signature(self):
        png = b"\x89PNG\r\n\x1a\n" + bytes(random.Random(4).randrange(256) for _ in range(300))
        res = auto(layer(png, "gzip", "base64"))
        self.assertEqual(res.candidates[0].data, png)
        self.assertEqual(res.candidates[0].score.signatures, ("PNG image",))
        self.assertEqual(res.candidates[0].chain, ["base64", "gzip"])

    def test_binary_flag_via_custom_regex(self):
        secret = b"\x00\x01\xde\xad\xbe\xef\x10\x20\x30\x40\xff"
        res = auto(layer(secret, "zlib", "base64"), FlagMatcher(regexes=[rb"\xde\xad\xbe\xef.{4}"], defaults=False))
        self.assertEqual(strong_flags(res)[0].data, b"\xde\xad\xbe\xef\x10\x20\x30\x40")

    def test_custom_prefix_and_known_plaintext(self):
        data = layer(b"HACKME{unknown_prefix_flag}", "base32", "hex")
        res = auto(data, FlagMatcher(prefixes=["HACKME"]))
        self.assertEqual(strong_flags(res)[0].data, b"HACKME{unknown_prefix_flag}")
        res = auto(layer(b"the answer is 42, definitely", "base64"), FlagMatcher(fragments=[b"answer is"]))
        self.assertTrue(res.flag_found)
        self.assertIn(b"answer is 42", res.flag_nodes[0].score.flags[0].data)

    def test_morse_and_a1z26_layers(self):
        for op, expect in (("morse", b"SECRET MESSAGE"), ("a1z26", b"SECRET MESSAGE")):
            with self.subTest(op=op):
                res = auto(layer(b"SECRET MESSAGE", op))
                self.assertEqual(res.candidates[0].chain, [op])
                self.assertEqual(res.candidates[0].data, expect)
        res = auto(layer(layer(b"FLAG IS HERE", "morse"), "base64"))
        self.assertEqual(res.candidates[0].data, b"FLAG IS HERE")

    def test_plain_rot13_text_without_any_flag(self):
        res = auto(b"Uryyb Jbeyq, guvf vf n frperg zrffntr sbe lbh")
        self.assertEqual(res.candidates[0].chain, ["rot13"])
        self.assertIn(b"Hello World", res.candidates[0].data)

    def test_blind_transform_then_structural(self):
        # base64 of a *reversed* string needs: base64, reverse (speculative probe pays off)
        res = auto(layer(b"hello this is plain readable english text", "reverse", "base64"))
        self.assertEqual(res.candidates[0].data, b"hello this is plain readable english text")

    def test_reversed_binary_blob_is_found(self):
        res = auto(layer(FLAG, "zlib", "reverse", "ascii85"))
        self.assertTrue(res.flag_found)


class RankingAndExplanation(unittest.TestCase):
    def test_candidates_distinct_ranked_and_non_dominated(self):
        res = auto(layer(b"Some readable text with the word secret inside", "base64", "hex"), stop_on_flag=False)
        self.assertEqual([n.score.total for n in res.candidates], sorted((n.score.total for n in res.candidates), reverse=True))
        for a, b in itertools.permutations(res.candidates, 2):
            self.assertFalse(a.is_ancestor_of(b))
        self.assertEqual(len({n.data for n in res.candidates}), len(res.candidates))
        self.assertTrue(all(n.depth >= 1 for n in res.candidates))

    def test_explainable_path(self):
        best = auto(layer(FLAG, "gzip", "base64")).candidates[0]
        lines = explain_path(best)
        self.assertEqual(len(lines), 2)
        self.assertIn("base64", lines[0])
        self.assertIn("gzip", lines[1])
        self.assertIn("confidence", lines[0])
        self.assertTrue(all(s.evidence for s in best.steps))
        self.assertEqual([n.depth for n in best.path()], [0, 1, 2])
        self.assertEqual(best.chain_spec, "base64|gzip")

    def test_strict_vs_permissive_is_recorded(self):
        flag = b"flag{pad_me_x}"  # 14 bytes -> base64 needs one '=' of padding
        self.assertTrue(base64.b64encode(flag).endswith(b"="))
        strict = auto(base64.b64encode(flag)).candidates[0].steps[0]
        loose = auto(base64.b64encode(flag).rstrip(b"=")).candidates[0].steps[0]
        self.assertEqual((strict.mode, loose.mode), ("strict", "permissive"))

    def test_no_adjacent_repeat_of_self_inverse_ops(self):
        res = auto(b"Uryyb Jbeyq guvf vf frperg", stop_on_flag=False, max_depth=6)
        for n in itertools.chain(res.candidates, res.flag_nodes):
            for a, b in zip(n.chain, n.chain[1:]):
                self.assertFalse(a == b and REG.get(a).info.self_inverse, n.chain)

    def test_undecodable_input_reports_nothing(self):
        rnd = random.Random(8)
        res = auto(bytes(rnd.randrange(256) for _ in range(2000)))
        self.assertEqual((res.candidates, res.flag_found), ([], False))
        self.assertEqual(res.stats.stop_reason, "exhausted")


# ------------------------------------------------------------------- limits / safety
def fake_registry(*classes):
    r = Registry()
    for c in classes:
        r.register(c)
    return r


class Swap(Codec):  # reversible case swap that is NOT declared self-inverse: only dedup can stop the loop
    info = PluginInfo(name="swapcase", category=Category.TEXT, description="d", reversible=True, auto_safe=True,
                      input_type=DataKind.TEXT)

    def _encode(self, data): return data.swapcase()
    def _decode(self, data): return data.swapcase()
    def detect(self, data): return Detection(0.9, "always")


class Grow(Codec):  # unbounded, slow, always applicable: only limits can stop it
    info = PluginInfo(name="grow", category=Category.TEXT, description="d", reversible=True, auto_safe=True,
                      input_type=DataKind.TEXT)
    delay = 0.02

    def _encode(self, data): return data
    def _decode(self, data):
        time.sleep(self.delay)
        return data + b"x"
    def detect(self, data): return Detection(1.0, "always")


class Boom(Codec):
    info = PluginInfo(name="boom", category=Category.TEXT, description="d", reversible=True, auto_safe=True,
                      input_type=DataKind.TEXT)

    def _encode(self, data): return data
    def _decode(self, data): raise RuntimeError("plugin bug")
    def detect(self, data): raise RuntimeError("detector bug")


class TwoWays(Codec):
    def _encode(self, data): return data
    def detect(self, data): return Detection(0.9, "always") if data.startswith(b"amb:") else None


def two_ways():
    class A(TwoWays):
        info = PluginInfo(name="way-a", category=Category.TEXT, description="d", reversible=True, auto_safe=True, input_type=DataKind.TEXT)
        def _decode(self, data): return b"flag{answer_from_a}"

    class B(TwoWays):
        info = PluginInfo(name="way-b", category=Category.TEXT, description="d", reversible=True, auto_safe=True, input_type=DataKind.TEXT)
        def _decode(self, data): return b"flag{answer_from_b}"

    return fake_registry(A, B)


class LimitsAndSafety(unittest.TestCase):
    def test_cycles_terminate_via_dedup(self):
        res = AutoDecoder(fake_registry(Swap), SearchConfig(max_depth=50)).run(b"AbCdEfGh text")
        self.assertEqual(res.stats.stop_reason, "exhausted")
        self.assertEqual(res.stats.nodes_generated, 1)
        self.assertEqual(res.stats.pruned["duplicate state"], 1)

    def test_depth_limit(self):
        data = layer(FLAG, *["base64"] * 6)
        self.assertFalse(auto(data, max_depth=3).flag_found)
        self.assertTrue(auto(data, max_depth=6).flag_found)
        self.assertTrue(auto(data, max_depth=8).flag_found)

    def test_node_limit(self):
        res = AutoDecoder(fake_registry(Grow), SearchConfig(max_nodes=10, max_depth=100, time_limit=30)).run(b"seed text")
        self.assertEqual(res.stats.stop_reason, "node limit")
        self.assertLessEqual(res.stats.nodes_generated, 10)

    def test_time_limit(self):
        t = time.time()
        res = AutoDecoder(fake_registry(Grow), SearchConfig(time_limit=0.3, max_nodes=10**6, max_depth=10**6)).run(b"seed")
        self.assertEqual(res.stats.stop_reason, "time limit")
        self.assertLess(time.time() - t, 2.0)
        self.assertGreater(res.stats.nodes_generated, 3)

    def test_max_output_and_decompression_bomb(self):
        bomb = base64.b64encode(gzip.compress(bytes(60 << 20), 9))
        self.assertLess(len(bomb), 200_000)
        t = time.time()
        res = auto(bomb, max_output=1 << 20)
        self.assertLess(time.time() - t, 10)
        self.assertTrue(all(len(n.data) <= 1 << 20 for n in res.candidates))
        self.assertGreaterEqual(res.stats.pruned.get("decode failed", 0), 1)
        # with a big enough limit the same input does decode
        ok = auto(base64.b64encode(gzip.compress(bytes(3 << 20), 1)), max_output=4 << 20)
        self.assertTrue(any(len(n.data) == 3 << 20 for n in ok.candidates) or ok.stats.nodes_generated >= 2)

    def test_memory_limit(self):
        res = AutoDecoder(fake_registry(Grow), SearchConfig(max_memory=200, max_nodes=10**6, max_depth=100, time_limit=5)).run(b"seed " * 10)
        self.assertEqual(res.stats.stop_reason, "memory limit")

    def test_ctrl_c_returns_partial_results(self):
        def progress(stats, best):
            raise KeyboardInterrupt

        res = AutoDecoder(REG, SearchConfig(), progress=progress).run(layer(FLAG, "hex", "base64"))
        self.assertTrue(res.interrupted)
        self.assertEqual(res.stats.stop_reason, "interrupted")

    def test_progress_callback(self):
        calls = []
        AutoDecoder(REG, SearchConfig(), progress=lambda s, b: calls.append((s.nodes_generated, b))).run(layer(FLAG, "hex", "base64"))
        self.assertGreaterEqual(len(calls), 1)

    def test_faulty_plugins_do_not_abort_search(self):
        r = fake_registry(Boom, *[type(REG.get(n)) for n in ("base64", "hex")])
        res = AutoDecoder(r, SearchConfig()).run(layer(FLAG, "hex", "base64"))
        self.assertTrue(res.flag_found)
        self.assertGreaterEqual(res.stats.plugin_errors, 1)

    def test_large_input_is_handled(self):
        big = b"A" * (6 << 20) + b" " + FLAG
        t = time.time()
        res = auto(big, FlagMatcher(scan_limit=1 << 20))
        self.assertTrue(res.flag_found)  # tail window
        self.assertLess(time.time() - t, 20)

    def test_early_termination_vs_exhaustive(self):
        data = layer(FLAG, "hex", "base64")
        quick, full = auto(data), auto(data, stop_on_flag=False)
        self.assertEqual(quick.stats.stop_reason, "flag found")
        self.assertLessEqual(quick.stats.nodes_generated, full.stats.nodes_generated)

    def test_multiple_solutions(self):
        reg = two_ways()
        first = AutoDecoder(reg, SearchConfig()).run(b"amb:data")
        self.assertEqual(len(first.flag_nodes), 1)
        both = AutoDecoder(reg, SearchConfig(stop_on_flag=False)).run(b"amb:data")
        self.assertEqual({n.data for n in both.flag_nodes}, {b"flag{answer_from_a}", b"flag{answer_from_b}"})
        self.assertEqual(len(both.candidates), 2)

    def test_only_and_exclude(self):
        data = layer(FLAG, "hex", "base64")
        self.assertTrue(auto(data, only=frozenset({"base64", "hex"})).flag_found)
        self.assertFalse(auto(data, only=frozenset({"base64"})).flag_found)
        self.assertFalse(auto(data, exclude=frozenset({"hex"})).flag_found)
        with self.assertRaises(Exception):
            auto(data, only=frozenset({"no-such-op"}))

    def test_expensive_and_non_auto_safe_ops_are_never_implicit(self):
        engine = AutoDecoder(REG, SearchConfig())
        names = {p.info.name for p in engine.decoders}
        self.assertNotIn("xor", names)     # requires a key
        self.assertNotIn("rotn", names)    # not auto-safe (a dedicated solver arrives in Milestone 3)
        self.assertNotIn("deflate", names)  # no signature: would be tried blindly on everything
        self.assertIn("base64", names)

    def test_config_validation(self):
        for bad in [dict(strategy="nope"), dict(max_depth=0), dict(beam_width=0), dict(time_limit=0)]:
            with self.assertRaises(UsageError):
                SearchConfig(**bad).validate()
        self.assertEqual(parse_size("512k"), 512 * 1024)
        self.assertEqual(parse_size("16M"), 16 << 20)
        self.assertEqual(parse_size("123"), 123)
        with self.assertRaises(UsageError):
            parse_size("lots")
        self.assertEqual(names_set(["a,b", "c"]), frozenset({"a", "b", "c"}))
        self.assertIsNone(names_set(None))


class Strategies(unittest.TestCase):
    def test_all_strategies_solve_and_agree(self):
        for ops in [("hex", "base64"), ("zlib", "base85", "base64")]:
            data = layer(FLAG, *ops)
            for strategy in ("best-first", "beam", "bfs"):
                with self.subTest(ops=ops, strategy=strategy):
                    res = auto(data, strategy=strategy)
                    self.assertEqual(strong_flags(res)[0].data, FLAG)

    def test_beam_width_bounds_exploration(self):
        data = layer(FLAG, "base64", "base64", "base64", "base64")
        narrow = auto(data, strategy="beam", beam_width=1, stop_on_flag=False, max_depth=5)
        wide = auto(data, strategy="beam", beam_width=16, stop_on_flag=False, max_depth=5)
        self.assertLessEqual(narrow.stats.nodes_generated, wide.stats.nodes_generated)
        self.assertTrue(narrow.flag_found)


class ScorerPlugin(unittest.TestCase):
    def test_registered_scorer(self):
        s = REG.get("english-frequency")
        self.assertGreater(s.score(b"Hello World"), 0.5)
        self.assertLess(s.score(b"zzqx"), 0.2)


# keep unused-import linters honest about modules used only for fixtures
_ = (bz2, lzma)

if __name__ == "__main__":
    unittest.main()
