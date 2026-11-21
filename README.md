# Cryptix

Extensible, terminal-native toolkit for CTF cryptography and encoding analysis on Linux.

> **Status: Milestone 1 of 6.** The plugin architecture, byte-exact I/O, and 34 encoding/compression/cipher
> operations work and are tested. The automatic decoder, solvers, XOR analysis, RSA and hash tools are
> **not built yet**; see [ROADMAP.md](ROADMAP.md) for exactly what is and is not done.

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
