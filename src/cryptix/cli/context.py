"""Execution context shared by all command handlers (frontend-independent)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, BinaryIO, TextIO

from cryptix.core.registry import Registry, get_registry


@dataclass
class Options:
    quiet: bool = False
    json: bool = False
    no_color: bool = False
    verbose: int = 0


@dataclass
class Streams:
    stdin: BinaryIO
    stdout: BinaryIO
    stderr: TextIO
    stdin_tty: bool = False
    stdout_tty: bool = False
    stderr_tty: bool = False

    @classmethod
    def from_process(cls) -> Streams:
        return cls(
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr,
            stdin_tty=sys.stdin.isatty(),
            stdout_tty=sys.stdout.isatty(),
            stderr_tty=sys.stderr.isatty(),
        )


@dataclass
class Context:
    opts: Options = field(default_factory=Options)
    streams: Streams = field(default_factory=Streams.from_process)
    registry: Registry = field(default_factory=get_registry)

    @property
    def color(self) -> bool:
        return not (self.opts.no_color or os.environ.get("NO_COLOR")) and self.streams.stdout_tty

    # -- diagnostics always go to stderr ---------------------------------
    def info(self, msg: str) -> None:
        if self.opts.verbose and not self.opts.quiet:
            self.streams.stderr.write(f"cryptix: {msg}\n")

    def warn(self, msg: str) -> None:
        if not self.opts.quiet:
            self.streams.stderr.write(f"cryptix: warning: {msg}\n")

    def error(self, msg: str) -> None:
        self.streams.stderr.write(f"cryptix: error: {msg}\n")

    # -- stdout ----------------------------------------------------------
    def write_stdout(self, data: bytes) -> None:
        self.streams.stdout.write(data)
        self.streams.stdout.flush()

    def write_json(self, obj: Any) -> None:
        text = json.dumps(obj, indent=None if self.opts.quiet else 2, ensure_ascii=False)
        self.write_stdout(text.encode("utf-8") + b"\n")
