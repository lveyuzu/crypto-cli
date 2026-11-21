"""Basic analyzer, scorer and detector plugins (the full scoring stack arrives in Milestone 2)."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from cryptix.core.magic import is_zlib_header, match_signatures
from cryptix.core.plugin import (
    Analyzer, Category, Cost, DataKind, Detector, Finding, PluginInfo, Report, Scorer,
)  # fmt: skip


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    return ok / len(data)


class ByteStats(Analyzer):
    info = PluginInfo(
        name="bytestats", category=Category.ANALYSIS,
        description="Length, Shannon entropy, printable-ASCII ratio, NUL ratio, UTF-8 validity.",
        input_type=DataKind.BYTES, output_type=DataKind.STRUCTURED, cost=Cost.TRIVIAL,
    )  # fmt: skip

    def _analyze(self, data: bytes, **params: Any) -> Report:
        try:
            data.decode("utf-8")
            utf8 = True
        except UnicodeDecodeError:
            utf8 = False
        return Report(
            "Byte statistics",
            {
                "length": len(data),
                "entropy_bits_per_byte": round(shannon_entropy(data), 4),
                "printable_ratio": round(printable_ratio(data), 4),
                "null_ratio": round(data.count(0) / len(data), 4) if data else 0.0,
                "utf8_valid": utf8,
                "distinct_bytes": len(set(data)),
            },
        )


class PrintableScorer(Scorer):
    info = PluginInfo(
        name="printable-ratio", category=Category.SCORING,
        description="Fraction of bytes that are printable ASCII or tab/CR/LF (0..1).",
        input_type=DataKind.BYTES, output_type=DataKind.STRUCTURED,
    )  # fmt: skip

    def score(self, data: bytes) -> float:
        return printable_ratio(data)


class MagicDetector(Detector):
    info = PluginInfo(
        name="magic", category=Category.DETECTION,
        description="Identify well-known file signatures (images, archives, executables, compression).",
        input_type=DataKind.BYTES, output_type=DataKind.STRUCTURED,
    )  # fmt: skip

    def scan(self, data: bytes) -> list[Finding]:
        findings = []
        for sig in match_signatures(data):
            conf = 0.35 if len(sig.magic) <= 2 else 0.9
            findings.append(Finding(sig.name, conf, f"magic {sig.magic!r} at offset {sig.offset}"))
        if not findings and is_zlib_header(data):
            findings.append(Finding("zlib stream", 0.6, "valid RFC 1950 header"))
        return findings
