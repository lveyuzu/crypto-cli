# Cryptix roadmap and honest status

Last updated: end of **Milestone 1**. Nothing is listed as implemented unless it has tests that were run.

## Implemented and tested

**Foundation**
- `src/` layout, `pyproject.toml` (setuptools), MIT license; `pip install .` verified offline (`--no-deps`) and the console script runs.
- Plugin system: `Encoder`, `Decoder`, `Codec`, `Cipher`, `Analyzer`, `Solver`, `Scorer`, `Detector` interfaces; `PluginInfo` declares name, category, description, input/output type, reversibility, parameters, cost class, auto-search safety, aliases, detection notes and verified examples.
- Registry with alias/did-you-mean lookup, role/category filters, registration validation, failure-isolated discovery from built-ins, entry-point *objects* (class, module, iterable, callable), and user plugin directories (`$CRYPTIX_PLUGIN_PATH`, default `~/.config/cryptix/plugins`). `CRYPTIX_NO_PLUGINS=1` disables external code.
- Working example plugin (`examples/plugins/dna_codec.py`), loaded and exercised through the real CLI in tests.
- Bytes-canonical I/O: input formats `raw`, `utf8`, `latin1`, `hex`, `escaped`; output formats `raw`, `hex`, `escaped`, `text`, `latin1`; stdin/stdout/files/`-o`; byte-exact through pipes (200 kB random blobs through 10 codecs); no decoration on piped stdout; terminal output of binary data is shown escaped instead of dumped; BrokenPipe handled silently; Ctrl+C exits 130.
- CLI commands: `decode`, `encode`, `chain`, `list`, `explain`, `plugins`, `version`; `--json`, `--quiet`, `--no-color`/`NO_COLOR`, `-v`; documented exit codes (0/1/2/3/4/5/70/130).

**Operations (34 plugins)**
- Base: `hex`, `base2` (any bit width 1-8), `base8` (per-byte octal), `base10` (byte list or big integer), `base32`, `base32hex`, `base36`, `base58` (Bitcoin), `base62` (two alphabet orderings), `base64`, `base64url`, `base85` (git/Python b85), `ascii85` (+Adobe), `z85`. Base64/32 permissive mode repairs missing padding; strict mode demands canonical input. Verified against RFC 4648 vectors and the Z85 spec vector.
- Text: `url`, `html`, `quoted-printable`, `unicode-escape` (with surrogate pairs), `rot13`, `rotn`, `rot47`, `atbash`, `morse`, `a1z26`.
- Bytes: `reverse` (bytes or UTF-8 chars), `xor` (repeating key; hex/int/escaped/base64/text key syntax).
- Compression: `gzip` (multi-member), `zlib`, `deflate` (raw), `bzip2`, `lzma`/xz/alone. Output-size bounded (decompression bombs), truncation and trailing-garbage handling, cross-checked against the stdlib.
- Basic analysis plugins: `bytestats`, `printable-ratio`, `magic` (30 signatures).
- Every plugin's declared examples are executed in both directions by the test suite; every decoder/encoder is fuzzed with hostile inputs and may only raise `CryptixError`; every `detect()` is checked never to raise.

## Implemented but needs improvement

- **Typer frontend is unverified.** Typer, Rich, pytest, Hypothesis, Ruff and mypy could not be installed in the development sandbox (no network). `cli/typer_app.py` only passes `py_compile`. All logic lives in `cli/commands.py`, which *is* tested through the stdlib argparse fallback frontend; the subprocess tests in `tests/test_cli.py` are frontend-agnostic and will exercise Typer on a machine that has it. **First thing to do on a real dev machine: `pytest`, and fix any Typer binding issue.**
- **Rich table rendering is unverified** (only used on a colour-capable TTY; plain-text path is tested).
- **Ruff, mypy and pytest have not been run.** Tests are `unittest.TestCase` classes (so they run under both runners) and pass with `python -m unittest`. Type hints are present but not checked; line-length/style not linted.
- **No Hypothesis tests yet**: round-trips use a seeded `random.Random` instead.
- **Shell completion** comes from Typer's built-in `--install-completion` (unverified); operation names are not completed dynamically.
- **Entry-point discovery** is tested through `Registry.load_object`, not through a really installed third-party distribution.
- `detect()` heuristics exist for most decoders and are unit-tested, but are only consumed by the auto-decoder (Milestone 2); they are not yet user-visible. Confidence values are hand-tuned and will be recalibrated against the Milestone 2 corpus.
- `auto_safe` flags are provisional until the auto-decoder exists.
- Whole files are read into memory (no streaming yet).
- Test suite is slow (~70 s) because most CLI tests spawn processes.
- `base10` integer mode cannot represent an empty input or leading zero bytes unless `length` is given (documented).
- Base64 "missing padding" is handled inside `base64`/`base64url` (permissive mode, `pad=false`) rather than a separate plugin.

## Not implemented

**Milestone 2**: `auto` command, search engine (best-first/beam/BFS), layered scoring (flag regex, printable, UTF-8, English frequency, n-grams, entropy, signatures, validity, complexity penalty), node limits, time limits, cycle detection, dedup, explainable paths, known-plaintext hints, `--quiet` flag output with exit codes, progress indicators.

**Milestone 3**: `crack`; Caesar/ROT-N/Affine/Vigenere/Atbash/Rail Fence/Columnar/substitution solvers; chi-squared, IoC, Kasiski, Hamming distance, n-gram analysis; `xor analyze|single|repeat|apply`; key visualisation.

**Milestone 4**: `rsa analyze|inverse|factor|decrypt`; GCD/egcd/modinv/modexp/nth root/Miller-Rabin/Fermat/trial division/Wiener/small-e/common modulus/CRT.

**Milestone 5 (remaining operations)**: Base45, Base91, Base92, Base100, RFC 1924 Base85; ASCII, UTF-16/32 LE/BE, Latin-1 as explicit codecs; octal-escape, decimal-code, hex-code char encodings; Bacon, NATO, Braille, tap code, Polybius, Rail Fence, Columnar; bit/byte rotations, reverse bits, endianness/nibble swap, add/sub mod 256, NOT/AND/OR, interleave, slicing, chunking, padding removal, null stripping, case transforms; JSON string unescape; safe Python bytes-literal parsing; `hash` command (identification and verification); `inspect` command (hexdump, histogram, repeated blocks, interactive view); lazy plugin loading.

**Milestone 6**: CONTRIBUTING.md, benchmarks, multi-distro install testing, `uv tool install` verification, CLI UX pass, shell-completion verification.
