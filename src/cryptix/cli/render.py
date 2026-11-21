"""Human-readable rendering. Rich is optional: used only for tables on a color-capable
terminal; everything else (pipes, --no-color, NO_COLOR, tests) uses plain text."""

from __future__ import annotations

import io
from collections.abc import Sequence

from cryptix.cli.context import Context


def plain_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = lambda cells: "  ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()  # noqa: E731
    return "\n".join([line(headers), line(["-" * w for w in widths]), *(line(r) for r in rows)])


def print_table(ctx: Context, title: str, headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    if ctx.color:
        try:
            from rich.console import Console
            from rich.table import Table

            buf = io.StringIO()
            console = Console(file=buf, force_terminal=True, width=None)
            table = Table(title=title)
            for h in headers:
                table.add_column(h)
            for r in rows:
                table.add_row(*r)
            console.print(table)
            ctx.write_stdout(buf.getvalue().encode("utf-8"))
            return
        except ImportError:
            pass
    ctx.write_stdout((plain_table(headers, rows) + "\n").encode("utf-8"))
