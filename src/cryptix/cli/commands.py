"""Command handlers. Pure functions of (Context, arguments) -> exit code.

Both the Typer and the argparse frontends call these; neither contains logic.
"""

from __future__ import annotations

import binascii
import platform
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptix import __version__
from cryptix.cli.chain import Step, parse_chain
from cryptix.cli.context import Context
from cryptix.cli.io import InputSpec, OutputSpec, emit, read_input
from cryptix.cli.render import print_table
from cryptix.core.data import is_texty, parse_bytes_arg, to_escaped
from cryptix.core.plugin import Category, Decoder, Encoder, Plugin, TransformResult
from cryptix.errors import CryptixError, UsageError
from cryptix.search.engine import AutoDecoder, Node, SearchConfig, SearchResult, SearchStats, explain_path, names_set, parse_size
from cryptix.search.flags import FlagMatcher


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


# -------------------------------------------------------------------- auto
@dataclass
class AutoArgs:
    depth: int
    beam: int
    max_nodes: int
    time_limit: float
    max_output: str
    strategy: str
    top: int
    min_score: float
    min_confidence: float
    flag_regex: Sequence[str] = field(default_factory=list)
    flag_prefix: Sequence[str] = field(default_factory=list)
    known: Sequence[str] = field(default_factory=list)
    no_default_flags: bool = False
    exhaustive: bool = False
    only: Sequence[str] | None = None
    exclude: Sequence[str] = field(default_factory=list)
    explain: bool = False


def _preview(data: bytes, width: int = 100) -> str:
    if is_texty(data[:4096]):
        s = data.decode("utf-8", "replace").replace("\r", "").replace("\n", "\\n")
        return s if len(s) <= width else s[: width - 1] + "…"
    return f"binary, first bytes: {data[:24].hex()}{'…' if len(data) > 24 else ''}"


def _node_json(rank: int, n: Node, full_hex_limit: int = 1 << 20) -> dict[str, Any]:
    d = n.data
    try:
        text: str | None = d.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return {
        "rank": rank,
        "score": round(n.score.total, 4),
        "depth": n.depth,
        "chain": [{"op": s.op, "mode": s.mode, "confidence": round(s.confidence, 3),
                   "in_len": s.in_len, "out_len": s.out_len, "evidence": s.evidence} for s in n.steps],
        "chain_spec": n.chain_spec,
        "flags": [{"kind": f.kind, "pattern": f.pattern, "text": f.text, "start": f.start, "end": f.end}
                  for f in n.score.flags],
        "signatures": list(n.score.signatures),
        "hints": list(n.score.hints),
        "score_parts": dict(n.score.parts),
        "length": len(d),
        "text": text,
        "utf8_valid": text is not None,
        "hex": d[:full_hex_limit].hex(),
        "hex_truncated": len(d) > full_hex_limit,
    }  # fmt: skip


def _stats_json(s: SearchStats) -> dict[str, Any]:
    return {"nodes_generated": s.nodes_generated, "nodes_expanded": s.nodes_expanded,
            "decode_attempts": s.decode_attempts, "pruned": dict(s.pruned), "elapsed_s": round(s.elapsed, 4),
            "stop_reason": s.stop_reason, "plugin_errors": s.plugin_errors}  # fmt: skip


def _render_auto(ctx: Context, res: SearchResult, a: AutoArgs) -> str:
    s = res.stats
    lines = [f"searched {s.nodes_generated} states ({s.nodes_expanded} expanded, {s.decode_attempts} decode "
             f"attempts) in {s.elapsed:.2f}s; stopped: {s.stop_reason}", ""]
    shown = res.candidates[: a.top]
    for i, n in enumerate(shown, 1):
        best = n.score.flags[0] if n.score.flags else None
        tag = f"  [{best.kind.upper()} MATCH]" if best else (f"  [{n.score.signatures[0]}]" if n.score.signatures else "")
        lines.append(f"#{i}  score {n.score.total:.2f}  depth {n.depth}{tag}")
        lines.append(f"    chain:   {' -> '.join(n.chain) or '(input is already plaintext)'}")
        if n.chain:
            lines.append(f"    replay:  cryptix chain '{n.chain_spec}' ...")
        if best:
            lines.append(f"    match:   {_preview(best.data, 200)}   ({best.pattern})")
        lines.append(f"    output:  {len(n.data)} bytes: {_preview(n.data)}")
        if n.score.hints:
            lines.append(f"    hints:   {'; '.join(n.score.hints)}")
        if a.explain:
            lines += ["    why:"] + [f"      {x}" for x in explain_path(n)]
            lines.append("      score: " + ", ".join(f"{k}={v}" for k, v in n.score.parts.items() if v))
        lines.append("")
    if len(res.candidates) > len(shown):
        lines.append(f"({len(res.candidates) - len(shown)} more candidates; use --top N)")
    return "\n".join(lines).rstrip() + "\n"


def cmd_auto(ctx: Context, inp: InputSpec, out: OutputSpec, a: AutoArgs) -> int:
    def run() -> int:
        data = read_input(ctx, inp)
        cfg = SearchConfig(
            max_depth=a.depth, beam_width=a.beam, max_nodes=a.max_nodes, time_limit=a.time_limit,
            max_output=parse_size(a.max_output), strategy=a.strategy, min_score=a.min_score,
            min_confidence=a.min_confidence, stop_on_flag=not a.exhaustive,
            only=names_set(a.only), exclude=names_set(a.exclude) or frozenset(),
        )  # fmt: skip
        matcher = FlagMatcher(a.flag_regex, a.flag_prefix, [parse_bytes_arg(k) for k in a.known],
                              defaults=not a.no_default_flags)  # fmt: skip
        show_progress = ctx.streams.stderr_tty and not ctx.opts.quiet and not ctx.opts.json

        def progress(st: SearchStats, best: float) -> None:
            ctx.streams.stderr.write(f"\rsearching... {st.nodes_generated} states, best score {best:.2f}   ")
            ctx.streams.stderr.flush()

        res = AutoDecoder(ctx.registry, cfg, matcher, progress if show_progress else None).run(data)
        if show_progress:
            ctx.streams.stderr.write("\r\033[K")
        code = 130 if res.interrupted else 0
        if res.interrupted:
            ctx.warn("interrupted: showing results found so far")

        best_flag = None
        if res.flag_nodes:
            node = max(res.flag_nodes, key=lambda n: n.score.total)
            best_flag = (node, node.score.flags[0])

        if ctx.opts.quiet:  # only the flag; nonzero exit if there is none
            if best_flag is None:
                return code or 1
            ctx.write_stdout(best_flag[1].data + b"\n")
            return code

        top = best_flag[0] if best_flag else (res.candidates[0] if res.candidates else None)
        if out.path or out.fmt:  # pipeline mode: emit the best candidate's bytes, report on stderr
            if top is None:
                ctx.error("no plausible decoding found")
                return code or 1
            emit(ctx, top.data, out)
            if ctx.opts.verbose:
                ctx.streams.stderr.write(_render_auto(ctx, res, a))
            return code
        if ctx.opts.json:
            ctx.write_json({
                "flag_found": best_flag is not None,
                "stats": _stats_json(res.stats),
                "candidates": [_node_json(i, n) for i, n in enumerate(res.candidates[: a.top], 1)],
            })  # fmt: skip
            return code or (0 if res.candidates else 1)
        if not res.candidates:  # a diagnostic, not a result: stderr, with exit code 1 as the signal
            ctx.streams.stderr.write(
                f"cryptix: no plausible decoding found (searched {res.stats.nodes_generated} states "
                f"in {res.stats.elapsed:.2f}s; stopped: {res.stats.stop_reason})\n"
            )
            return code or 1
        ctx.write_stdout(_render_auto(ctx, res, a).encode("utf-8"))
        return code

    return run_guarded(ctx, run)
