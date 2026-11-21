"""Flag / known-plaintext recognition.

Scanning is bounded: data larger than ``scan_limit`` is scanned only at its head and
tail (``scan_limit/2`` each), and at most ``max_matches`` matches are collected.
The built-in patterns are linear-time. NOTE: a *user-supplied* regex runs with the stdlib
``re`` engine, which has no timeout, so a pathological pattern can still be slow on large
input; the window bound limits the damage but cannot eliminate it.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cryptix.errors import UsageError

MiB = 1024 * 1024

KNOWN_PREFIXES = (
    "flag", "ctf", "picoctf", "htb", "thm", "csaw", "hitcon", "dicectf", "ductf", "uiuctf",
    "lactf", "tjctf", "rctf", "wolvctf", "bsides", "cyctf", "sctf", "hackthebox", "inctf",
)  # fmt: skip

# strengths feed the scorer: a user-specified target outranks a heuristic guess
STRENGTH = {"custom": 10.0, "prefix": 10.0, "fragment": 8.0, "known": 8.0, "generic": 4.0}


@dataclass(frozen=True)
class FlagMatch:
    kind: str  # custom | prefix | fragment | known | generic
    pattern: str
    data: bytes  # the matched bytes (for fragments: the surrounding printable run)
    start: int
    end: int

    @property
    def strength(self) -> float:
        return STRENGTH[self.kind]

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


def _compile(pattern: bytes, flags: int = 0) -> re.Pattern[bytes]:
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise UsageError(f"invalid flag regex {pattern!r}: {exc}") from exc


_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_ROT47 = bytes((33 + (b - 33 + 47) % 94) if 33 <= b <= 126 else b for b in range(256))


def _b64_forms(f: bytes) -> list[bytes]:
    """Substrings of the base64 text that appear for ``f`` at each of the 3 alignments.

    Characters whose bits depend on neighbouring (unknown) bytes are dropped.
    """
    out = []
    for k, lead in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\x00" * k + f).rstrip(b"=")
        drop_tail = 1 if (k + len(f)) % 3 else 0
        core = enc[lead : len(enc) - drop_tail]
        if len(core) >= 4:
            out.append(core)
    return out


def hint_forms(fragment: bytes) -> dict[str, list[bytes]]:
    """Encoded appearances of a known fragment (for prioritising promising branches)."""
    forms: dict[str, list[bytes]] = {
        "hex": [fragment.hex().encode(), fragment.hex().upper().encode()],
        "base64": _b64_forms(fragment),
        "binary": ["".join(format(b, "08b") for b in fragment).encode()],
        "rot13": [fragment.translate(_ROT13)],
        "rot47": [fragment.translate(_ROT47)],
        "reversed": [fragment[::-1]],
    }
    return {k: [f for f in v if f and f != fragment] for k, v in forms.items() if v}


class FlagMatcher:
    def __init__(
        self,
        regexes: Iterable[str | bytes] = (),
        prefixes: Iterable[str | bytes] = (),
        fragments: Iterable[bytes] = (),
        defaults: bool = True,
        scan_limit: int = 8 * MiB,
        max_matches: int = 20,
    ) -> None:
        self.scan_limit = scan_limit
        self.max_matches = max_matches
        self._patterns: list[tuple[str, str, re.Pattern[bytes]]] = []
        for rx in regexes:
            raw = rx if isinstance(rx, bytes) else rx.encode("utf-8")
            self._patterns.append(("custom", raw.decode("latin-1"), _compile(raw)))
        self.prefixes: list[bytes] = []
        for pre in prefixes:
            raw = pre if isinstance(pre, bytes) else pre.encode("utf-8")
            raw = raw.rstrip(b"{")
            self.prefixes.append(raw)
            self._patterns.append(("prefix", raw.decode("latin-1") + "{...}",
                                   _compile(re.escape(raw) + rb"\{[^\n{}]{1,300}\}")))  # fmt: skip
        self.fragments = [f for f in fragments if f]
        if defaults:
            alt = "|".join(KNOWN_PREFIXES).encode()
            self._patterns.append(("known", "known-prefix{...}",
                                   _compile(rb"\b(?:" + alt + rb")\{[^\n{}]{1,300}\}", re.I)))  # fmt: skip
            self._patterns.append(("generic", "word{...}",
                                   _compile(rb"\b[A-Za-z][A-Za-z0-9_]{1,14}\{[A-Za-z0-9_][A-Za-z0-9_\-!?.@:,=+/ ]{3,200}?\}")))  # fmt: skip
        self._hints = self._build_hints()

    @property
    def has_targets(self) -> bool:
        """True if the user supplied an explicit target (regex, prefix or fragment)."""
        return any(k in ("custom", "prefix") for k, _, _ in self._patterns) or bool(self.fragments)

    def _windows(self, n: int) -> list[tuple[int, int]]:
        if n <= self.scan_limit:
            return [(0, n)]
        half = self.scan_limit // 2
        return [(0, half), (n - half, n)]

    def scan(self, data: bytes) -> list[FlagMatch]:
        found: dict[tuple[int, int], FlagMatch] = {}
        for lo, hi in self._windows(len(data)):
            for kind, name, rx in self._patterns:
                for m in rx.finditer(data, lo, hi):
                    found.setdefault((m.start(), m.end()), FlagMatch(kind, name, m.group(), m.start(), m.end()))
                    if len(found) >= self.max_matches:
                        return sorted(found.values(), key=lambda f: -f.strength)
            for frag in self.fragments:
                pos = data.find(frag, lo, hi)
                while pos != -1 and len(found) < self.max_matches:
                    s, e = pos, pos + len(frag)
                    while s > 0 and pos - s < 100 and 32 <= data[s - 1] < 127:
                        s -= 1
                    while e < len(data) and e - pos - len(frag) < 100 and 32 <= data[e] < 127:
                        e += 1
                    found.setdefault((s, e), FlagMatch("fragment", frag.decode("latin-1"), data[s:e], s, e))
                    pos = data.find(frag, pos + len(frag), hi)
        return sorted(found.values(), key=lambda f: -f.strength)

    # -- hints: the *encoded* appearance of something we are looking for -------------
    def _build_hints(self) -> list[tuple[str, bytes]]:
        seeds = [*self.fragments, *(p + b"{" for p in self.prefixes), b"flag{", b"CTF{", b"ctf{"]
        out: list[tuple[str, bytes]] = []
        for seed in dict.fromkeys(seeds):
            for enc, forms in hint_forms(seed).items():
                out.extend((f"{enc} form of {seed.decode('latin-1')!r}", f) for f in forms)
        return out

    def hints(self, data: bytes) -> list[str]:
        windows = self._windows(len(data))
        hits = []
        for label, form in self._hints:
            if any(data.find(form, lo, hi) != -1 for lo, hi in windows):
                hits.append(label)
        return hits


def ranked_flag_text(matches: Sequence[FlagMatch]) -> FlagMatch | None:
    return matches[0] if matches else None
