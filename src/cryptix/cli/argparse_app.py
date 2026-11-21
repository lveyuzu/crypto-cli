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

EXAMPLES = """\
examples:
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
