import os
import tempfile
import textwrap
import types
import unittest
from pathlib import Path

from cryptix.core.plugin import (
    Analyzer, Candidate, Category, Codec, Cost, DataKind, Decoder, Detector, Encoder,
    Param, ParamType, PluginInfo, Report, Scorer, Solver,
)  # fmt: skip
from cryptix.core.registry import RegistrationError, Registry
from cryptix.errors import ParameterError, UnknownPluginError


def make_codec(name="t-codec", aliases=(), reversible=True, base=Codec):
    class C(base):  # type: ignore[valid-type,misc]
        info = PluginInfo(name=name, aliases=aliases, category=Category.OTHER, description="d",
                          reversible=reversible)

        def _encode(self, data, **p):
            return data + b"E"

        def _decode(self, data, **p):
            return data[:-1]

    return C


class DummySolver(Solver):  # test fixture: proves the Solver interface registers and runs
    info = PluginInfo(name="dummy-solver", category=Category.CLASSICAL, description="fixture",
                      params=(Param("n", ParamType.INT, 2),), cost=Cost.CHEAP)

    def _solve(self, data, n):
        return [Candidate(data * n, 1.0, "repeat", exact=False)]


class RegisterTests(unittest.TestCase):
    def test_register_get_alias_case_insensitive(self):
        r = Registry()
        cls = make_codec("alpha", aliases=("a1",))
        r.register(cls)
        for name in ["alpha", "ALPHA", "a1", " A1 "]:
            self.assertIsInstance(r.get(name), cls)
        self.assertIn("a1", r)
        self.assertEqual(len(r), 1)

    def test_instances_are_cached(self):
        r = Registry()
        r.register(make_codec("alpha"))
        self.assertIs(r.get("alpha"), r.get("alpha"))

    def test_reregistering_same_class_is_noop_but_duplicate_name_fails(self):
        r = Registry()
        c = make_codec("alpha")
        r.register(c)
        r.register(c)
        with self.assertRaises(RegistrationError):
            r.register(make_codec("alpha"))

    def test_invalid_name_alias_collision_and_missing_info(self):
        r = Registry()
        with self.assertRaises(RegistrationError):
            r.register(make_codec("Bad Name"))
        r.register(make_codec("alpha", aliases=("x",)))
        with self.assertRaises(RegistrationError):
            r.register(make_codec("beta", aliases=("x",)))
        with self.assertRaises(RegistrationError):
            r.register(make_codec("alpha2", aliases=("alpha",)))

        class NoInfo(Codec):
            def _encode(self, d, **p): return d
            def _decode(self, d, **p): return d

        with self.assertRaises(RegistrationError):
            r.register(NoInfo)
        # a subclass inheriting `info` must not silently double-register
        with self.assertRaises(RegistrationError):
            r.register(type("Sub", (make_codec("gamma"),), {}))

    def test_reversible_flag_must_match_roles(self):
        r = Registry()
        with self.assertRaises(RegistrationError):
            r.register(make_codec("lying", reversible=False))

    def test_unknown_name_suggests(self):
        r = Registry()
        r.register(make_codec("base64"))
        with self.assertRaises(UnknownPluginError) as cm:
            r.get("base46")
        self.assertIn("base64", str(cm.exception))

    def test_unregister(self):
        r = Registry()
        r.register(make_codec("alpha", aliases=("a",)))
        r.unregister("a")
        self.assertNotIn("alpha", r)
        self.assertNotIn("a", r)

    def test_all_roles_and_filters(self):
        r = Registry()
        r.register(DummySolver)
        r.register(make_codec("c1"))

        class An(Analyzer):
            info = PluginInfo(name="an", category=Category.ANALYSIS, description="d")
            def _analyze(self, data, **p): return Report("t", {"n": len(data)})

        class Sc(Scorer):
            info = PluginInfo(name="sc", category=Category.SCORING, description="d")
            def score(self, data): return 0.5

        class De(Detector):
            info = PluginInfo(name="de", category=Category.DETECTION, description="d")
            def scan(self, data): return []

        for c in (An, Sc, De):
            r.register(c)
        self.assertEqual([p.info.name for p in r.all(Solver)], ["dummy-solver"])
        self.assertEqual([p.info.name for p in r.all(Encoder)], ["c1"])
        self.assertEqual([p.info.name for p in r.all(Decoder)], ["c1"])
        self.assertEqual([p.info.name for p in r.all(category=Category.ANALYSIS)], ["an"])
        self.assertEqual(r.get("dummy-solver").solve(b"ab", n=3)[0].data, b"ababab")
        self.assertEqual(r.get("an").analyze(b"abc").fields["n"], 3)
        self.assertEqual(r.get("sc").score(b""), 0.5)
        self.assertEqual(set(DummySolver.roles()), {"solver"})
        self.assertEqual(set(make_codec("c2").roles()), {"encoder", "decoder"})


class ParamTests(unittest.TestCase):
    def setUp(self):
        self.info = PluginInfo(
            name="p", category=Category.OTHER, description="d",
            params=(
                Param("n", ParamType.INT, 1), Param("flag", ParamType.BOOL, False),
                Param("key", ParamType.BYTES, None, required=True),
                Param("mode", ParamType.STR, "a", choices=("a", "b")),
            ),
        )  # fmt: skip

    def test_coercion_and_defaults(self):
        p = self.info.resolve_params({"n": "0x10", "flag": "yes", "key": "hex:00ff"})
        self.assertEqual(p, {"n": 16, "flag": True, "key": b"\x00\xff", "mode": "a"})
        self.assertEqual(self.info.resolve_params({"key": b"k", "n": 5})["n"], 5)

    def test_errors(self):
        bad = [{}, {"key": "k", "n": "abc"}, {"key": "k", "flag": "maybe"},
               {"key": "k", "mode": "z"}, {"key": "k", "nope": 1}, {"key": "k", "n": True}]
        for given in bad:
            with self.subTest(given=given), self.assertRaises(ParameterError):
                self.info.resolve_params(given)


class DiscoveryTests(unittest.TestCase):
    def test_builtin_discovery_loads_cleanly(self):
        r = Registry()
        r.discover(entry_points=False, user_dirs=False)
        self.assertEqual(r.errors, [])
        self.assertGreaterEqual(len(r), 30)
        # idempotent
        n = len(r)
        r.discover(entry_points=False, user_dirs=False)
        self.assertEqual(len(r), n)
        for name in r.names():
            self.assertEqual(r.source_of(name), "builtin")

    def test_load_object_variants(self):
        r = Registry()
        self.assertEqual(r.load_object(make_codec("one"), "t"), 1)
        self.assertEqual(r.load_object([make_codec("two"), make_codec("three")], "t"), 2)
        self.assertEqual(r.load_object(lambda reg: reg.register(make_codec("four")), "t"), 1)
        mod = types.ModuleType("fake_mod")
        cls = make_codec("five")
        cls.__module__ = "fake_mod"
        mod.Five = cls
        self.assertEqual(r.load_object(mod, "t"), 1)
        self.assertEqual({"one", "two", "three", "four", "five"}, set(r.names()))
        with self.assertRaises(RegistrationError):
            r.load_object(42, "t")

    def test_user_dir_plugins_and_failure_isolation(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "good.py").write_text(textwrap.dedent('''
                from cryptix.core.plugin import Category, Codec, PluginInfo
                class Shout(Codec):
                    info = PluginInfo(name="shout", category=Category.TEXT, description="upper", reversible=True)
                    def _encode(self, data): return data.upper()
                    def _decode(self, data): return data.lower()
            '''))
            Path(d, "broken.py").write_text("raise RuntimeError('boom')\n")
            Path(d, "_private.py").write_text("raise RuntimeError('must be skipped')\n")
            Path(d, "notpython.txt").write_text("ignored")
            r = Registry()
            r.discover(builtins=False, entry_points=False, user_dirs=[Path(d)])
            self.assertEqual(r.get("shout").encode(b"abc").data, b"ABC")
            self.assertTrue(r.source_of("shout").startswith("user-file:"))
            self.assertEqual(len(r.errors), 1)
            self.assertIn("broken.py", r.errors[0][0])
            self.assertIn("boom", r.errors[0][1])

    def test_missing_user_dir_is_fine(self):
        r = Registry()
        r.discover(builtins=False, entry_points=False, user_dirs=[Path("/nonexistent/cryptix")])
        self.assertEqual((len(r), r.errors), (0, []))

    def test_no_plugins_env_disables_external_sources(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "p.py").write_text("raise RuntimeError('should not run')\n")
            old = {k: os.environ.get(k) for k in ("CRYPTIX_NO_PLUGINS", "CRYPTIX_PLUGIN_PATH")}
            os.environ["CRYPTIX_NO_PLUGINS"] = "1"
            os.environ["CRYPTIX_PLUGIN_PATH"] = d
            try:
                r = Registry()
                r.discover()
                self.assertEqual(r.errors, [])
            finally:
                for k, v in old.items():
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


if __name__ == "__main__":
    unittest.main()
