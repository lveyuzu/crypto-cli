"""Input resolution and output emission (binary-safe)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptix.cli.context import Context
from cryptix.core.data import bytes_from_arg, bytes_from_stream, format_output, is_texty, to_escaped
from cryptix.errors import CryptixIOError, UsageError


@dataclass
class InputSpec:
    text: str | None = None  # positional argument ("-" means stdin)
    file: str | None = None
    fmt: str = "raw"


@dataclass
class OutputSpec:
    fmt: str | None = None  # None = automatic
    path: str | None = None


def read_input(ctx: Context, spec: InputSpec) -> bytes:
    if spec.text is not None and spec.file is not None:
        raise UsageError("give either INPUT or --file, not both")
    if spec.file is not None:
        try:
            raw = Path(spec.file).read_bytes() if spec.file != "-" else ctx.streams.stdin.read()
        except OSError as exc:
            raise CryptixIOError(f"cannot read {spec.file}: {exc.strerror or exc}") from exc
        return bytes_from_stream(raw, spec.fmt)
    if spec.text is not None and spec.text != "-":
        return bytes_from_arg(spec.text, spec.fmt)
    if ctx.streams.stdin_tty and spec.text is None:
        raise UsageError("no input: give INPUT, use --file, or pipe data on stdin")
    return bytes_from_stream(ctx.streams.stdin.read(), spec.fmt)


def emit(ctx: Context, data: bytes, out: OutputSpec) -> None:
    """Write result bytes to the destination.

    stdout rules: raw bytes are written untouched when piped. On a terminal, binary
    data is shown as an escaped preview (never dumped raw) unless the user explicitly
    asked for ``--output-format raw``; text gets a trailing newline.
    """
    if out.path:
        try:
            Path(out.path).write_bytes(format_output(data, out.fmt or "raw"))
        except OSError as exc:
            raise CryptixIOError(f"cannot write {out.path}: {exc.strerror or exc}") from exc
        ctx.info(f"wrote {len(data)} bytes to {out.path}")
        return
    fmt = out.fmt
    if fmt is None:
        if ctx.streams.stdout_tty:
            if is_texty(data):
                ctx.write_stdout(data if data.endswith(b"\n") or not data else data + b"\n")
            else:
                ctx.warn(
                    f"binary output ({len(data)} bytes) shown escaped; use -o FILE, "
                    "--output-format raw|hex to override"
                )
                ctx.write_stdout(to_escaped(data).encode("ascii") + b"\n")
            return
        fmt = "raw"
    ctx.write_stdout(format_output(data, fmt))
