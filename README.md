# Cryptix

CLI tool for CTF crypto and encoding stuff. Written in Python.

Still a WIP. 35 operations, chaining, plugins and automatic decoding work now. Classical cipher cracking, RSA, hash tools, etc. aren't implemented yet.

See [ROADMAP.md](ROADMAP.md) for progress.

## Install

Requires Python 3.12+.

```bash
pipx install .
```

or `uv tool install .`

For development:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## Usage

```bash
# decode base64
cryptix decode base64 SGVsbG8gV29ybGQ=

# encode/decode with pipes
echo -n 48656c6c6f | cryptix decode hex | cryptix encode base64

# chain operations
cryptix chain 'base64|hex|rotn(n=3)' NTQ2NTc4NzQ=

# xor
cryptix decode xor -p key=hex:4352 -I hex 0b372f3e2c

# decode files
cryptix decode gzip --file blob.gz -o blob.out

# list available operations
cryptix list

# info about an operation
cryptix explain base62
```

## Auto decoder

Tries to figure out the encoding and decode it automatically. Also works with multiple layers.

```bash
# basic auto decoding
cryptix auto 'NjY2YzYxNjc3YjZjNjE3OTY1NzI3MzVmNmY2NjVmNjU2ZTYzNmY2NDY5NmU2NzdkMGE='

# decode a file
cryptix auto --file challenge.txt

# increase search depth
cryptix auto --file challenge.txt --depth 8 --top 5

# find flags
cryptix -q auto --flag-prefix HTB --file blob.txt

# custom flag pattern
cryptix auto x --flag-regex 'corp-[0-9]{4}' --exhaustive

# known plaintext
cryptix auto x --known 'password is' --explain

# JSON output
cryptix --json auto --file challenge.txt
```

Uses a search algorithm to try different decoding chains and rank possible results. Has depth, time and memory limits so it doesn't run forever.

Tested on a synthetic dataset. Real CTF challenges might be less predictable.

Run `cryptix auto --help` for more options.

## Plugins

Put Python plugins in `~/.config/cryptix/plugins/` or use `CRYPTIX_PLUGIN_PATH`.

There's an example in `examples/plugins/dna_codec.py`.

More info in [PLUGINS.md](PLUGINS.md).

## Notes

- 35 operations so far
- Auto decoder supports layered encodings
- Supports raw bytes, files and stdin
- No network requests or telemetry
- Linux-focused, should work elsewhere too
- Currently on milestone 2/6
- Still working on it
