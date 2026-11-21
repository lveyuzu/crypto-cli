"""Command handlers. Pure functions of (Context, arguments) -> exit code.

Both the Typer and the argparse frontends call these; neither contains logic.
"""

from __future__ import annotations

import binascii
import platform
import sys
from collections.abc import Callable, Sequence
from typing import Any

from cryptix import __version__
from cryptix.cli.chain import Step, parse_chain
from cryptix.cli.context import Context
from cryptix.cli.io import InputSpec, OutputSpec, emit, read_input
from cryptix.cli.render import print_table
from cryptix.core.data import to_escaped
from cryptix.core.plugin import Category, Decoder, Encoder, Plugin, TransformResult
from cryptix.errors import CryptixError, UsageError


# ---------------------------------------------------------------- helpers
def run_guarded(ctx: Context, fn: Callable[[], int]) -> int:
    """Run a handler, converting exceptions into messages + exit codes."""
    try:
        return fn()
    except CryptixError as exc:
        ctx.error(str(exc))
        return exc.exit_code
    except BrokenPipeError:
        return 0  # downstream closed the pipe (e.g. `| head`); not an error
    except KeyboardInterrupt:
        ctx.streams.stderr.write("\ncryptix: interrupted\n")
        return 130
    except Exception as exc:  # genuine bug: show a hint, traceback only with -v
        ctx.error(f"internal error: {type(exc).__name__}: {exc}")
        if ctx.opts.verbose:
            import traceback

            traceback.print_exc(file=ctx.streams.stderr)
        return 70


def parse_kv(items: Sequence[str] | None) -> dict[str, str]:
    params: dict[str, str] = {}
    for item in items or ():
        key, eq, value = item.partition("=")
        if not eq or not key:
            raise UsageError(f"parameter {item!r} must look like key=value")
        params[key] = value
    return params


def _require(plugin: Plugin, role: type[Plugin], verb: str) -> None:
    if not isinstance(plugin, role):
        raise UsageError(
            f"'{plugin.info.name}' cannot {verb} (roles: {', '.join(plugin.roles()) or 'none'})"
        )


def _with_strict(ctx: Context, plugin: Plugin, params: dict[str, Any], strict: bool) -> dict[str, Any]:
    if strict:
        if plugin.info.accepts("strict"):
            params.setdefault("strict", True)
        else:
            ctx.warn(f"'{plugin.info.name}' has no strict mode; ignoring --strict")
    return params


def _result_json(data: bytes, notes: Sequence[str]) -> dict[str, Any]:
    try:
        text: str | None = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return {
        "length": len(data),
        "hex": binascii.hexlify(data).decode(),
        "text": text,
        "utf8_valid": text is not None,
        "escaped": to_escaped(data),
        "notes": list(notes),
    }


def _output(ctx: Context, data: bytes, out: OutputSpec, header: dict[str, Any], notes: Sequence[str]) -> None:
    for note in notes:
        ctx.info(note)
    if ctx.opts.json:
        if out.path:
            emit(ctx, data, out)
        ctx.write_json({**header, "ok": True, **_result_json(data, notes)})
    else:
        emit(ctx, data, out)


# --------------------------------------------------------- decode / encode
def cmd_decode(ctx: Context, op: str, inp: InputSpec, out: OutputSpec, params: Sequence[str], strict: bool) -> int:
    def run() -> int:
        plugin = ctx.registry.get(op)
        _require(plugin, Decoder, "decode")
        assert isinstance(plugin, Decoder)
        p = _with_strict(ctx, plugin, dict(parse_kv(params)), strict)
        data = read_input(ctx, inp)
        res = plugin.decode(data, **p)
        ctx.info(f"{plugin.info.name}: decoded {len(data)} -> {len(res.data)} bytes")
        _output(ctx, res.data, out, {"operation": plugin.info.name, "direction": "decode"}, res.notes)
        return 0

    return run_guarded(ctx, run)


def cmd_encode(ctx: Context, op: str, inp: InputSpec, out: OutputSpec, params: Sequence[str], strict: bool) -> int:
    def run() -> int:
        plugin = ctx.registry.get(op)
        _require(plugin, Encoder, "encode")
        assert isinstance(plugin, Encoder)
        p = _with_strict(ctx, plugin, dict(parse_kv(params)), strict)
        data = read_input(ctx, inp)
        res = plugin.encode(data, **p)
        ctx.info(f"{plugin.info.name}: encoded {len(data)} -> {len(res.data)} bytes")
        _output(ctx, res.data, out, {"operation": plugin.info.name, "direction": "encode"}, res.notes)
        return 0

    return run_guarded(ctx, run)


# ------------------------------------------------------------------- chain
def cmd_chain(ctx: Context, spec: str, inp: InputSpec, out: OutputSpec, encode: bool, strict: bool) -> int:
    def run() -> int:
        steps: list[Step] = parse_chain(spec)
        role = Encoder if encode else Decoder
        plugins = []
        for step in steps:  # validate the whole chain before touching the input
            plugin = ctx.registry.get(step.name)
            _require(plugin, role, "encode" if encode else "decode")
            plugins.append(plugin)
        data = read_input(ctx, inp)
        trail: list[dict[str, Any]] = []
        notes: list[str] = []
        for step, plugin in zip(steps, plugins, strict=True):
            params = _with_strict(ctx, plugin, dict(step.params), strict)
            before = len(data)
            res: TransformResult = (
                plugin.encode(data, **params) if encode else plugin.decode(data, **params)  # type: ignore[attr-defined]
            )
            data = res.data
            ctx.info(f"step {len(trail) + 1}: {plugin.info.name} {before} -> {len(data)} bytes")
            notes.extend(f"{plugin.info.name}: {n}" for n in res.notes)
            trail.append({"operation": plugin.info.name, "params": step.params, "length": len(data)})
        _output(ctx, data, out, {"direction": "encode" if encode else "decode", "steps": trail}, notes)
        return 0

    return run_guarded(ctx, run)


# ------------------------------------------------------------ introspection
def _info_dict(p: Plugin, source: str) -> dict[str, Any]:
    i = p.info
    return {
        "name": i.name,
        "aliases": list(i.aliases),
        "category": i.category.value,
        "roles": list(p.roles()),
        "description": i.description,
        "input_type": i.input_type.value,
        "output_type": i.output_type.value,
        "reversible": i.reversible,
        "cost": i.cost.name.lower(),
        "auto_safe": i.auto_safe,
        "detection": i.detection_notes,
        "source": source,
        "params": [
            {"name": q.name, "type": q.type.value, "default": _jsonable(q.default),
             "required": q.required, "choices": list(q.choices), "help": q.help}
            for q in i.params
        ],  # fmt: skip
    }


def _jsonable(v: Any) -> Any:
    return v.hex() if isinstance(v, bytes) else v


def cmd_list(ctx: Context, category: str | None, role: str | None, search: str | None) -> int:
    def run() -> int:
        cat = None
        if category:
            try:
                cat = Category(category)
            except ValueError:
                raise UsageError(f"unknown category {category!r}; choose from {', '.join(c.value for c in Category)}") from None
        plugins = ctx.registry.all(category=cat)
        if role:
            plugins = [p for p in plugins if role in p.roles()]
        if search:
            s = search.lower()
            plugins = [p for p in plugins if s in p.info.name or s in p.info.description.lower()
                       or any(s in a for a in p.info.aliases)]  # fmt: skip
        if ctx.opts.json:
            ctx.write_json([_info_dict(p, ctx.registry.source_of(p.info.name)) for p in plugins])
        elif ctx.opts.quiet:
            ctx.write_stdout(("\n".join(p.info.name for p in plugins) + ("\n" if plugins else "")).encode())
        else:
            rows = [
                [p.info.name, p.info.category.value, ",".join(r[:3] for r in p.roles()),
                 p.info.cost.name.lower(), "yes" if p.info.auto_safe else "no", _short(p.info.description)]
                for p in plugins
            ]  # fmt: skip
            print_table(ctx, f"{len(plugins)} operations", ["name", "category", "roles", "cost", "auto", "description"], rows)
        return 0 if plugins else 1

    return run_guarded(ctx, run)


def _short(text: str, width: int = 60) -> str:
    first = text.split(". ")[0].rstrip(".")
    if len(first) < 20:  # too terse to be a useful summary: use the following sentence too
        first = ". ".join(text.split(". ")[:2]).rstrip(".")
    return first if len(first) <= width else first[: width - 1] + "…"


def cmd_explain(ctx: Context, name: str) -> int:
    def run() -> int:
        p = ctx.registry.get(name)
        i = p.info
        if ctx.opts.json:
            d = _info_dict(p, ctx.registry.source_of(i.name))
            d["examples"] = [
                {"encoded": to_escaped(e.encoded), "decoded": to_escaped(e.decoded), "params": dict(e.params)}
                for e in i.examples
            ]
            ctx.write_json(d)
            return 0
        lines = [
            f"{i.name} - {i.category.value}",
            "",
            _wrap(i.description),
            "",
            f"  roles:        {', '.join(p.roles())}",
            f"  aliases:      {', '.join(i.aliases) or '-'}",
            f"  types:        {i.input_type.value} -> {i.output_type.value} (primary direction)",
            f"  reversible:   {'yes' if i.reversible else 'no'}",
            f"  cost:         {i.cost.name.lower()}",
            f"  auto-search:  {'safe' if i.auto_safe else 'not used implicitly'}",
            f"  source:       {ctx.registry.source_of(i.name)}",
            f"  detection:    {i.detection_notes}",
        ]
        if i.params:
            lines += ["", "parameters (pass with -p name=value):"]
            for q in i.params:
                extra = f"  choices: {', '.join(map(str, q.choices))}" if q.choices else ""
                dflt = "required" if q.required else f"default {_jsonable(q.default)!r}"
                lines.append(f"  {q.name} ({q.type.value}, {dflt}){extra}")
                if q.help:
                    lines.append(f"      {q.help}")
        if i.examples:
            lines += ["", "examples:"]
            for e in i.examples:
                flags = "".join(f" -p {k}={v}" for k, v in e.params.items())
                lines.append(f"  cryptix decode {i.name}{flags} --input-format escaped '{to_escaped(e.encoded)}'")
                lines.append(f"      -> {to_escaped(e.decoded)}")
        ctx.write_stdout(("\n".join(lines) + "\n").encode("utf-8"))
        return 0

    return run_guarded(ctx, run)


def _wrap(text: str, width: int = 78) -> str:
    import textwrap

    return "\n".join(textwrap.wrap(text, width))


def cmd_plugins(ctx: Context) -> int:
    def run() -> int:
        sources: dict[str, list[str]] = {}
        for n in ctx.registry.names():
            sources.setdefault(ctx.registry.source_of(n), []).append(n)
        if ctx.opts.json:
            ctx.write_json({"sources": sources, "load_errors": [{"source": s, "error": e} for s, e in ctx.registry.errors]})
        else:
            out = []
            for src in sorted(sources):
                out.append(f"{src}: {len(sources[src])} operation(s)")
                if src != "builtin" or ctx.opts.verbose:
                    out.extend(f"    {n}" for n in sources[src])
            for src, err in ctx.registry.errors:
                out.append(f"LOAD ERROR {src}: {err}")
            ctx.write_stdout(("\n".join(out) + "\n").encode())
        return 0

    return run_guarded(ctx, run)


def cmd_version(ctx: Context) -> int:
    def run() -> int:
        info = {"cryptix": __version__, "python": platform.python_version(), "platform": sys.platform}
        if ctx.opts.json:
            ctx.write_json(info)
        elif ctx.opts.quiet:
            ctx.write_stdout(f"{__version__}\n".encode())
        else:
            ctx.write_stdout(f"cryptix {__version__} (python {info['python']}, {info['platform']})\n".encode())
        return 0

    return run_guarded(ctx, run)
