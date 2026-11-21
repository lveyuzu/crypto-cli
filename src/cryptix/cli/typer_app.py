"""Typer frontend (the primary one). NOTE: written against Typer >= 0.12.

No logic lives here: every command builds a Context, then calls cryptix.cli.commands.
"""

from typing import Annotated, Optional

import typer

from cryptix import __version__
from cryptix.cli import commands
from cryptix.cli.context import Context, Options
from cryptix.cli.io import InputSpec, OutputSpec
from cryptix.core.data import INPUT_FORMATS, OUTPUT_FORMATS
from cryptix.search.engine import DEFAULTS, STRATEGIES

EXAMPLES = (
    "Examples:\n\n"
    "  cryptix auto 'ZmxhZ3toZWxsb30='\n\n"
    "  cryptix auto -q --flag-prefix HTB --file blob.txt\n\n"
    "  cryptix decode base64 'SGVsbG8gV29ybGQ='\n\n"
    "  echo -n 48656c6c6f | cryptix decode hex | cryptix encode base64\n\n"
    "  cryptix chain 'base64|hex|rotn(n=3)' --file challenge.txt\n"
)

app = typer.Typer(
    name="cryptix",
    help="Extensible CTF cryptanalysis and encoding toolkit.",
    epilog=EXAMPLES,
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode=None,
)

Quiet = Annotated[bool, typer.Option("--quiet", "-q", help="Only the requested result; no diagnostics.")]
Json = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]
NoColor = Annotated[bool, typer.Option("--no-color", help="Disable colors (also honours NO_COLOR).")]
Verbose = Annotated[int, typer.Option("--verbose", "-v", count=True, help="Diagnostics on stderr.")]
File = Annotated[Optional[str], typer.Option("--file", "-f", help="Read input from FILE ('-' = stdin).")]
InFmt = Annotated[str, typer.Option("--input-format", "-I", help=f"One of: {', '.join(INPUT_FORMATS)}.")]
OutFmt = Annotated[Optional[str], typer.Option("--output-format", "-O", help=f"One of: {', '.join(OUTPUT_FORMATS)}.")]
OutFile = Annotated[Optional[str], typer.Option("--output", "-o", help="Write result to FILE.")]
Params = Annotated[Optional[list[str]], typer.Option("--param", "-p", help="Operation parameter K=V (repeatable).")]
Strict = Annotated[bool, typer.Option("--strict", help="Strict parsing where supported.")]
InputArg = Annotated[Optional[str], typer.Argument(help="Input text ('-' or omitted: read stdin).")]


def _ctx(quiet: bool, json_: bool, no_color: bool, verbose: int) -> Context:
    return Context(Options(quiet=quiet, json=json_, no_color=no_color, verbose=verbose))


def _exit(code: int) -> None:
    raise typer.Exit(code)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"cryptix {__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: Annotated[bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")] = False,
) -> None:
    pass


@app.command("decode", epilog=EXAMPLES)
def decode(
    op: Annotated[str, typer.Argument(metavar="OPERATION", help="Operation name or alias (see `cryptix list`).")],
    input: InputArg = None, file: File = None, input_format: InFmt = "raw", output_format: OutFmt = None,
    output: OutFile = None, param: Params = None, strict: Strict = False,
    quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0,
) -> None:
    """Decode INPUT with one operation."""
    _exit(commands.cmd_decode(_ctx(quiet, json, no_color, verbose), op, InputSpec(input, file, input_format),
                              OutputSpec(output_format, output), param or [], strict))


@app.command("encode", epilog=EXAMPLES)
def encode(
    op: Annotated[str, typer.Argument(metavar="OPERATION", help="Operation name or alias.")],
    input: InputArg = None, file: File = None, input_format: InFmt = "raw", output_format: OutFmt = None,
    output: OutFile = None, param: Params = None, strict: Strict = False,
    quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0,
) -> None:
    """Encode INPUT with one operation."""
    _exit(commands.cmd_encode(_ctx(quiet, json, no_color, verbose), op, InputSpec(input, file, input_format),
                              OutputSpec(output_format, output), param or [], strict))


@app.command("chain", epilog=EXAMPLES)
def chain(
    spec: Annotated[str, typer.Argument(help="e.g. 'base64|hex|rotn(n=3)' (| or , separated).")],
    input: InputArg = None, file: File = None, input_format: InFmt = "raw", output_format: OutFmt = None,
    output: OutFile = None, encode: Annotated[bool, typer.Option("--encode", help="Apply encoders instead of decoders.")] = False,
    strict: Strict = False, quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0,
) -> None:
    """Apply several operations in sequence."""
    _exit(commands.cmd_chain(_ctx(quiet, json, no_color, verbose), spec, InputSpec(input, file, input_format),
                             OutputSpec(output_format, output), encode, strict))


@app.command("auto", epilog=EXAMPLES)
def auto(
    input: InputArg = None, file: File = None, input_format: InFmt = "raw", output_format: OutFmt = None,
    output: OutFile = None,
    depth: Annotated[int, typer.Option("--depth", "-d", help="Maximum chain length.")] = DEFAULTS.max_depth,
    beam: Annotated[int, typer.Option("--beam", "-b", help="Beam width / children kept per node.")] = DEFAULTS.beam_width,
    max_nodes: Annotated[int, typer.Option("--max-nodes", help="Maximum states generated.")] = DEFAULTS.max_nodes,
    time_limit: Annotated[float, typer.Option("--time-limit", "-t", help="Seconds.")] = DEFAULTS.time_limit,
    max_output: Annotated[str, typer.Option("--max-output", help="Largest intermediate result, e.g. 512k, 16M.")] = "16M",
    strategy: Annotated[str, typer.Option("--strategy", help=f"One of: {', '.join(STRATEGIES)}.")] = DEFAULTS.strategy,
    only: Annotated[Optional[list[str]], typer.Option("--only", help="Restrict to these operations (comma separated).")] = None,
    exclude: Annotated[Optional[list[str]], typer.Option("--exclude", help="Never use these operations.")] = None,
    flag_regex: Annotated[Optional[list[str]], typer.Option("--flag-regex", help="Custom flag regex (repeatable).")] = None,
    flag_prefix: Annotated[Optional[list[str]], typer.Option("--flag-prefix", help="Custom flag prefix: PREFIX{...} (repeatable).")] = None,
    known: Annotated[Optional[list[str]], typer.Option("--known", help="Known plaintext fragment (hex:/b64:/esc: allowed).")] = None,
    no_default_flags: Annotated[bool, typer.Option("--no-default-flags", help="Only use the targets given.")] = False,
    exhaustive: Annotated[bool, typer.Option("--exhaustive", help="Keep searching after the first flag.")] = False,
    top: Annotated[int, typer.Option("--top", "-n", help="Candidates to show.")] = 5,
    min_score: Annotated[float, typer.Option("--min-score", help="Hide candidates below this score.")] = DEFAULTS.min_score,
    min_confidence: Annotated[float, typer.Option("--min-confidence", help="Ignore detections below this.")] = DEFAULTS.min_confidence,
    explain: Annotated[bool, typer.Option("--explain", help="Show per-step evidence and score breakdown.")] = False,
    quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0,
) -> None:
    """Automatically search for the decoding chain (prints only the flag with -q)."""
    args = commands.AutoArgs(
        depth=depth, beam=beam, max_nodes=max_nodes, time_limit=time_limit, max_output=max_output,
        strategy=strategy, top=top, min_score=min_score, min_confidence=min_confidence,
        flag_regex=flag_regex or [], flag_prefix=flag_prefix or [], known=known or [],
        no_default_flags=no_default_flags, exhaustive=exhaustive, only=only, exclude=exclude or [], explain=explain,
    )
    _exit(commands.cmd_auto(_ctx(quiet, json, no_color, verbose), InputSpec(input, file, input_format),
                            OutputSpec(output_format, output), args))


@app.command("list")
def list_(
    category: Annotated[Optional[str], typer.Option("--category", "-c")] = None,
    role: Annotated[Optional[str], typer.Option("--role", "-r", help="encoder, decoder, cipher, analyzer, solver, scorer, detector")] = None,
    search: Annotated[Optional[str], typer.Option("--search", "-s", help="Substring of name/alias/description.")] = None,
    quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0,
) -> None:
    """List operations."""
    _exit(commands.cmd_list(_ctx(quiet, json, no_color, verbose), category, role, search))


@app.command("explain")
def explain(
    name: Annotated[str, typer.Argument(help="Operation name or alias.")],
    quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0,
) -> None:
    """Show details, parameters and examples of an operation."""
    _exit(commands.cmd_explain(_ctx(quiet, json, no_color, verbose), name))


@app.command("plugins")
def plugins(quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0) -> None:
    """Show plugin sources and load errors."""
    _exit(commands.cmd_plugins(_ctx(quiet, json, no_color, verbose)))


@app.command("version")
def version(quiet: Quiet = False, json: Json = False, no_color: NoColor = False, verbose: Verbose = 0) -> None:
    """Show version information."""
    _exit(commands.cmd_version(_ctx(quiet, json, no_color, verbose)))
