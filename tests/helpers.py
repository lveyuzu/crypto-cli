"""Shared test helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def cli_env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env["CRYPTIX_NO_PLUGINS"] = "1"  # hermetic: ignore the developer's own plugins
    env.pop("NO_COLOR", None)
    env.update(extra)
    return env


def run_cli(*args: str, input: bytes | None = None, env: dict[str, str] | None = None
            ) -> subprocess.CompletedProcess[bytes]:
    """Run `python -m cryptix ...` exactly as a user would (whichever frontend is installed)."""
    return subprocess.run(
        [sys.executable, "-m", "cryptix", *args],
        input=input, capture_output=True, env=env or cli_env(), timeout=60, check=False,
    )
