# Writing a Cryptix plugin

A plugin is a class with an `info = PluginInfo(...)` attribute that implements one or more role interfaces from
`cryptix.core.plugin`. Discovery registers every concrete plugin class that **defines its own `info`**, so no
central list or CLI change is needed: `list`, `explain`, `decode`, `encode` and `chain` pick it up automatically.

| Role | Implement | Public method (provided) |
|---|---|---|
| `Encoder` | `_encode(data, **params) -> bytes` | `encode()` |
| `Decoder` | `_decode(data, **params) -> bytes`, optional `detect(data)` | `decode()` |
| `Codec` / `Cipher` | both of the above (`reversible=True`) | |
| `Analyzer` | `_analyze(data, **params) -> Report` | `analyze()` |
| `Solver` | `_solve(data, **params) -> list[Candidate]` | `solve()` |
| `Scorer` | `score(data) -> float` in 0..1 | |
| `Detector` | `scan(data) -> list[Finding]` | |

The public methods resolve parameters (coercion, defaults, unknown/missing checks), convert stdlib failures
(`ValueError`, `binascii.Error`, `zlib.error`, `UnicodeError`...) into `DecodeError`/`EncodeError`, and wrap results.
Raise `DecodeError`, `EncodeError` or `ParameterError` yourself for domain errors.

## Minimal example

```python
from cryptix.core.plugin import Category, Codec, DataKind, Example, PluginInfo

class Shout(Codec):
    info = PluginInfo(
        name="shout", category=Category.TEXT, description="Uppercase / lowercase.",
        input_type=DataKind.TEXT, output_type=DataKind.TEXT, reversible=True,
        examples=(Example(b"HELLO", b"hello"),),     # executed by the test-suite in both directions
    )
    def _encode(self, data: bytes) -> bytes: return data.upper()
    def _decode(self, data: bytes) -> bytes: return data.lower()
```

## Rules

- `name`: `[a-z0-9][a-z0-9_.+-]*`, unique; `aliases` must not collide. `reversible` must equal "has both Encoder and Decoder".
- Data is **bytes**. Never round-trip through `str` unless the operation is genuinely text-level (then require valid UTF-8 and say so).
- Declare every parameter as a `Param` (`INT`, `STR`, `BOOL`, `BYTES`, optional `choices`). Add a `strict` BOOL if you tolerate sloppy input by default.
- Set `cost` honestly (`TRIVIAL` ... `EXPENSIVE`). `auto_safe=True` makes the operation eligible for `cryptix auto`; it must be cheap (`cost <= CHEAP`), take no required parameters, and either have a meaningful `detect()` or be declared `blind`.
- `blind=True`: no structural signature exists (rot13, reverse...). `auto` then judges the operation only by whether its output looks better (more English-like, newly recognisable as an encoding, or gaining a file signature), and tries it only on text that is not yet English.
- `self_inverse=True`: applying it twice is the identity. `auto` never applies it twice in a row.
- `detect()` must be fast, side-effect free, never raise, and return a *calibrated* confidence: ambiguous formats (hex vs base64) should score low.
- Bound resource use (output size, iterations); input is untrusted.
- Provide at least one `Example`; `decode_only=True` when the encoder is not canonical.

## Distribution

1. **Single file**: copy to `~/.config/cryptix/plugins/` (or a directory in `$CRYPTIX_PLUGIN_PATH`, `os.pathsep`-separated). Files starting with `_` are skipped. A file that fails to import is reported by `cryptix plugins` and does not affect others.
2. **Package**: in `pyproject.toml`
   ```toml
   [project.entry-points."cryptix.plugins"]
   shout = "my_pkg.shout:Shout"      # a class, a module, an iterable of classes, or a register(registry) callable
   ```
