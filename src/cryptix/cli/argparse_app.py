"""Zero-dependency frontend (stdlib argparse). Used when Typer is not installed.

Identical commands and options to the Typer frontend; both only bind arguments to
:mod:`cryptix.cli.commands`. Shell completion is provided by Typer only.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from cryptix import __version__
from cryptix.cli import commands
from cryptix.cli.context import Context, Options
from cryptix.cli.io import InputSpec, OutputSpec
from cryptix.core.data import INPUT_FORMATS, OUTPUT_FORMATS
from cryptix.search.engine import DEFAULTS, STRATEGIES

EXAMPLES = """\
examples:
  cryptix auto 'ZmxhZ3toZWxsb30='                       # find the decoding chain automatically
  cryptix auto --file challenge.txt --depth 8 --top 5
  cryptix auto -q --flag-prefix HTB blob.txt             # print only the flag; exit 1 if none
  cryptix decode base64 'SGVsbG8gV29ybGQ='
  echo -n 48656c6c6f | cryptix decode hex | cryptix encode base64
  cryptix decode xor -p key=hex:4352 --input-format hex 0b372f3e2c
  cryptix chain 'base64|hex|rotn(n=3)' --file challenge.txt
  cryptix decode gzip --file blob.gz -o blob.out
"""


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("global options")
    # SUPPRESS: a flag given before the subcommand must not be reset by the subparser's default.
    sup = argparse.SUPPRESS
    g.add_argument("-q", "--quiet", action="store_true", default=sup, help="only the requested result; no diagnostics")
    g.add_argument("--json", action="store_true", default=sup, help="machine-readable JSON on stdout")
    g.add_argument("--no-color", action="store_true", default=sup, help="disable colors (also honours NO_COLOR)")
    g.add_argument("-v", "--verbose", action="count", default=sup, help="diagnostics on stderr")
    return p


def _io_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", nargs="?", help="input text ('-' or omitted: read stdin)")
    p.add_argument("-f", "--file", help="read input from FILE ('-' = stdin)")
    p.add_argument("-I", "--input-format", choices=INPUT_FORMATS, default="raw", help="how to read INPUT (default raw)")
    p.add_argument("-O", "--output-format", choices=OUTPUT_FORMATS, default=None, help="output representation (default: raw bytes when piped)")
    p.add_argument("-o", "--output", help="write result to FILE instead of stdout")


class _IntermixedParser(argparse.ArgumentParser):
    """Subcommand parser allowing options between positionals (`decode xor -p k=v INPUT`)."""

    _intermixed_active = False

    def parse_known_args(self, args=None, namespace=None):  # type: ignore[no-untyped-def,override]
        # parse_known_intermixed_args() calls parse_known_args() itself: guard against recursion.
        if self._intermixed_active:
            return super().parse_known_args(args, namespace)
        self._intermixed_active = True
        try:
            return self.parse_known_intermixed_args(args, namespace)
        finally:
            self._intermixed_active = False


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    root = argparse.ArgumentParser(
        prog="cryptix",
        description="Extensible CTF cryptanalysis and encoding toolkit.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    root.add_argument("--version", action="version", version=f"cryptix {__version__}")
    sub = root.add_subparsers(dest="command", metavar="COMMAND", parser_class=_IntermixedParser)

    for name, help_ in (("decode", "decode INPUT with one operation"), ("encode", "encode INPUT with one operation")):
        p = sub.add_parser(name, parents=[common], help=help_, epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
        p.add_argument("op", metavar="OPERATION", help="operation name or alias (see `cryptix list`)")
        _io_args(p)
        p.add_argument("-p", "--param", action="append", default=[], metavar="K=V", help="operation parameter (repeatable)")
        p.add_argument("--strict", action="store_true", help="strict parsing where supported")

    p = sub.add_parser("chain", parents=[common], help="apply several operations in sequence", epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("spec", help="e.g. 'base64|hex|rotn(n=3)' (| or , separated)")
    _io_args(p)
    p.add_argument("--encode", action="store_true", help="apply encoders instead of decoders")
    p.add_argument("--strict", action="store_true")

    p = sub.add_parser("auto", parents=[common], help="automatically search for the decoding chain", epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    _io_args(p)
    g = p.add_argument_group("search limits")
    g.add_argument("-d", "--depth", type=int, default=DEFAULTS.max_depth, help=f"maximum chain length (default {DEFAULTS.max_depth})")
    g.add_argument("-b", "--beam", type=int, default=DEFAULTS.beam_width, help=f"beam width / children kept per node (default {DEFAULTS.beam_width})")
    g.add_argument("--max-nodes", type=int, default=DEFAULTS.max_nodes, help=f"maximum states generated (default {DEFAULTS.max_nodes})")
    g.add_argument("-t", "--time-limit", type=float, default=DEFAULTS.time_limit, help=f"seconds (default {DEFAULTS.time_limit:g})")
    g.add_argument("--max-output", default="16M", help="largest intermediate result, e.g. 4096, 512k, 16M (default 16M)")
    g.add_argument("--strategy", choices=STRATEGIES, default=DEFAULTS.strategy)
    g.add_argument("--only", action="append", metavar="OPS", help="restrict to these operations (comma separated, repeatable)")
    g.add_argument("--exclude", action="append", default=[], metavar="OPS", help="never use these operations")
    g = p.add_argument_group("targets")
    g.add_argument("--flag-regex", action="append", default=[], metavar="REGEX", help="custom flag regex (repeatable)")
    g.add_argument("--flag-prefix", action="append", default=[], metavar="PREFIX", help="custom flag prefix, matches PREFIX{...} (repeatable)")
    g.add_argument("--known", action="append", default=[], metavar="TEXT", help="known plaintext fragment (hex:/b64:/esc: prefixes allowed; repeatable)")
    g.add_argument("--no-default-flags", action="store_true", help="only use the targets given above")
    g.add_argument("--exhaustive", action="store_true", help="do not stop at the first flag; keep searching")
    g = p.add_argument_group("results")
    g.add_argument("-n", "--top", type=int, default=5, help="candidates to show (default 5)")
    g.add_argument("--min-score", type=float, default=DEFAULTS.min_score, help="hide candidates scoring below this")
    g.add_argument("--min-confidence", type=float, default=DEFAULTS.min_confidence, help="ignore detections below this confidence")
    g.add_argument("--explain", action="store_true", help="show per-step evidence and score breakdown")

    p = sub.add_parser("list", parents=[common], help="list operations")
    p.add_argument("-c", "--category")
    p.add_argument("-r", "--role", choices=["encoder", "decoder", "cipher", "analyzer", "solver", "scorer", "detector"])
    p.add_argument("-s", "--search", help="substring of name/alias/description")

    p = sub.add_parser("explain", parents=[common], help="show details, parameters and examples of an operation")
    p.add_argument("name")

    sub.add_parser("plugins", parents=[common], help="show plugin sources and load errors")
    sub.add_parser("version", parents=[common], help="show version information")
    return root


def run(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    if not ns.command:
        parser.print_help()
        return 2
    # Shared Action objects (via parents=) mean defaults can't live on the parser: read with fallbacks.
    ctx = Context(Options(
        quiet=getattr(ns, "quiet", False), json=getattr(ns, "json", False),
        no_color=getattr(ns, "no_color", False), verbose=getattr(ns, "verbose", 0),
    ))
    if ns.command == "auto":
        args = commands.AutoArgs(
            depth=ns.depth, beam=ns.beam, max_nodes=ns.max_nodes, time_limit=ns.time_limit,
            max_output=ns.max_output, strategy=ns.strategy, top=ns.top, min_score=ns.min_score,
            min_confidence=ns.min_confidence, flag_regex=ns.flag_regex, flag_prefix=ns.flag_prefix,
            known=ns.known, no_default_flags=ns.no_default_flags, exhaustive=ns.exhaustive,
            only=ns.only, exclude=ns.exclude, explain=ns.explain,
        )  # fmt: skip
        return commands.cmd_auto(ctx, InputSpec(ns.input, ns.file, ns.input_format), OutputSpec(ns.output_format, ns.output), args)
    if ns.command in ("decode", "encode", "chain"):
        inp = InputSpec(ns.input, ns.file, ns.input_format)
        out = OutputSpec(ns.output_format, ns.output)
        if ns.command == "decode":
            return commands.cmd_decode(ctx, ns.op, inp, out, ns.param, ns.strict)
        if ns.command == "encode":
            return commands.cmd_encode(ctx, ns.op, inp, out, ns.param, ns.strict)
        return commands.cmd_chain(ctx, ns.spec, inp, out, ns.encode, ns.strict)
    if ns.command == "list":
        return commands.cmd_list(ctx, ns.category, ns.role, ns.search)
    if ns.command == "explain":
        return commands.cmd_explain(ctx, ns.name)
    if ns.command == "plugins":
        return commands.cmd_plugins(ctx)
    return commands.cmd_version(ctx)
