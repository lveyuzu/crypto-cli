"""Console entry point: Typer when available, stdlib argparse otherwise.

Set CRYPTIX_FRONTEND=argparse to force the fallback.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    # Cryptix is a number-theory tool: lift CPython's 4300-digit int<->str limit.
    sys.set_int_max_str_digits(0)
    use_typer = os.environ.get("CRYPTIX_FRONTEND") != "argparse" and importlib.util.find_spec("typer") is not None
    try:
        if use_typer:
            from cryptix.cli.typer_app import app

            app(args=list(argv) if argv is not None else None, prog_name="cryptix")
            return 0
        from cryptix.cli.argparse_app import run

        return run(argv)
    except SystemExit as exc:  # argparse errors/help, typer.Exit
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        sys.stderr.write("\ncryptix: interrupted\n")
        return 130
