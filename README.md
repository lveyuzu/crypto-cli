# Cryptix

Extensible, terminal-native toolkit for CTF cryptography and encoding analysis on Linux.

> **Status: Milestone 2 of 6.** The plugin architecture, byte-exact I/O, 35 operations and the **automatic
> decoder (`cryptix auto`)** work and are tested. Classical-cipher solvers, XOR analysis, RSA, hash and
> inspect tools are **not built yet**; see [ROADMAP.md](ROADMAP.md) for exactly what is and is not done.

## Install

```sh
pipx install .          # or: uv tool install .
```

Requires Python 3.12+. Runtime dependencies: `typer`, `rich`. The core (registry, codecs, I/O) uses only the
standard library; if Typer is missing, `cryptix` falls back to a built-in argparse frontend with identical commands.

Development setup (any distro; nothing is distro-specific at runtime):

| Distro | Packages |
|---|---|
| Fedora | `sudo dnf install python3.12 python3-pip pipx` |
| Debian / Ubuntu | `sudo apt install python3 python3-venv pipx` (needs Python >= 3.12; Ubuntu 24.04+) |
| Arch | `sudo pacman -S python python-pipx` |

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                  # or: PYTHONPATH=src:tests python -m unittest discover -s tests
```

## Automatic decoding

```sh
cryptix auto 'NjY2YzYxNjc3YjZjNjE3OTY1NzI3MzVmNmY2NjVmNjU2ZTYzNmY2NDY5NmU2NzdkMGE='                      # find the chain: prints ranked candidates
cryptix auto --file challenge.txt --depth 8 --top 5
cryptix -q auto --flag-prefix HTB --file blob.txt     # only the flag on stdout; exit 1 if none
cryptix auto blob.txt -O raw > out.bin                # emit the best candidate's bytes (pipelines)
cryptix auto x --known 'password is' --explain        # known plaintext, per-step evidence and score parts
cryptix auto x --flag-regex 'corp-[0-9]{4}' --exhaustive --json
```

```
$ cryptix auto 'NjY2YzYxNjc3YjZjNjE3OTY1NzI3MzVmNmY2NjVmNjU2ZTYzNmY2NDY5NmU2NzdkMGE='
searched 7 states (2 expanded, 7 decode attempts) in 0.00s; stopped: flag found

#1  score 8.47  depth 2  [KNOWN MATCH]
    chain:   base64 -> hex
    replay:  cryptix chain 'base64|hex' ...
    match:   flag{layers_of_encoding}   (known-prefix{...})
    output:  25 bytes: flag{layers_of_encoding}\n
```

How it works: a bounded best-first (or beam/BFS) search over states (bytes). Each decoder's `detect()` proposes
applicable operations with a confidence; results are scored by layered, explainable heuristics (flag/known-plaintext
match, text-ness, English plausibility, entropy, file signatures, decoder validity, chain length), deduplicated, and
ranked. Only cheap, `auto_safe` operations are run implicitly. Limits: `--depth`, `--beam`, `--max-nodes`,
`--time-limit`, `--max-output`; Ctrl+C prints what was found so far. Matches from `--flag-regex`, `--flag-prefix`,
`--known` and the built-in `flag{...}`-style patterns stop the search at the first settled hit (`--exhaustive` continues).
Exit codes: `0` a candidate was found (with `-q`: a flag), `1` nothing found.

Measured on the synthetic corpus in `benchmarks/auto_corpus.py` (not real-world data; see ROADMAP caveats):
every ordered pair of operations (1,893 chains) recovered, random 1-5 layer chains 99-100%, median 1-3 ms per search.

## Usage

```sh
cryptix decode base64 'SGVsbG8gV29ybGQ='
echo -n 48656c6c6f | cryptix decode hex | cryptix encode base64
cryptix chain 'base64|hex|rotn(n=3)' 'NTQ2NTc4NzQ='        # decode steps left to right
cryptix chain 'hex,base64' --encode 'Hi'                   # encode steps left to right
cryptix decode xor -p key=hex:4352 -I hex 0b372f3e2c       # XOR with a repeating key
cryptix decode gzip --file blob.gz -o blob.out             # binary in, binary out
cryptix --json decode base64 SGk=                          # structured output
cryptix list -c base                                       # browse operations
cryptix explain base62                                     # parameters, detection rules, examples
```

| Option | Meaning |
|---|---|
| `INPUT` / `-f FILE` / stdin | input text, file, or pipe (`-` forces stdin) |
| `-I raw\|utf8\|latin1\|hex\|escaped` | how input text maps to bytes (default `raw`) |
| `-O raw\|hex\|escaped\|text\|latin1`, `-o FILE` | output representation / destination |
| `-p key=value` (repeatable) | operation parameter; BYTES params accept `hex:` `b64:` `esc:` `int:` `str:` prefixes |
| `--strict` | strict parsing where the operation supports it (default is tolerant) |
| `-q`, `--json`, `--no-color`, `-v` | quiet, JSON, no colour (also `NO_COLOR`), diagnostics on stderr |

Raw bytes are the only internal representation. Piped stdout is byte-exact with no added newline. On a terminal,
text gets a trailing newline and binary data is shown escaped (override with `-O raw`). Diagnostics only go to stderr.

**Exit codes:** `0` ok, `1` no result, `2` usage/parameter/input-format error, `3` data cannot be decoded/encoded,
`4` unknown operation, `5` I/O error, `70` internal error, `130` interrupted.

## Plugins

Drop a `.py` file into `~/.config/cryptix/plugins/` (or `$CRYPTIX_PLUGIN_PATH`) or ship a package with a
`cryptix.plugins` entry point. See [PLUGINS.md](PLUGINS.md) and `examples/plugins/dna_codec.py`.
User plugins are arbitrary local Python code; set `CRYPTIX_NO_PLUGINS=1` to disable them.

Cryptix makes no network requests, has no telemetry and runs no background services.
