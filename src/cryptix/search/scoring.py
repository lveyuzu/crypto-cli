"""Layered candidate scoring.

Layers (each reported separately so results are explainable):

 1. flag        flag-pattern / known-plaintext match (dominates the total when present)
 2. textness    printable-character ratio, UTF-8 aware (non-English text scores fine)
 3. english     letter frequency + common words + n-grams (a bonus, never a requirement)
 4. entropy     low entropy supports text; very high entropy with no signature is a dead end
 5. signature   file magic bytes (PNG, ZIP, ELF, compression containers ...)
 6. validity    how convincingly the producing decoder applied (detect confidence, strict parse)
 7. encoded     penalty if the output still *looks encoded* but not like English (not final yet)
 8. complexity  small penalty per step, so shorter chains win ties

``potential`` (best detection confidence of any further decoder) is computed by the engine and
passed in: it both drives the encoded-penalty and the search priority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from cryptix.core.magic import is_zlib_header, match_signatures
from cryptix.plugins.analysis import shannon_entropy
from cryptix.search.flags import FlagMatch, FlagMatcher
from cryptix.search.language import english_score

SAMPLE = 64 * 1024

W_TEXT, W_ENGLISH, W_ENTROPY, W_SIGNATURE, W_VALIDITY = 0.30, 0.25, 0.08, 0.20, 0.10
P_ENCODED, P_RANDOM, P_DEPTH, P_COST = 0.25, 0.15, 0.02, 0.01


@dataclass(frozen=True)
class Score:
    total: float
    parts: Mapping[str, float]
    flags: tuple[FlagMatch, ...] = ()
    signatures: tuple[str, ...] = ()
    hints: tuple[str, ...] = field(default=())

    @property
    def english(self) -> float:
        return self.parts.get("english", 0.0)

    @property
    def textness(self) -> float:
        return self.parts.get("textness", 0.0)


def textness(data: bytes) -> float:
    """Fraction of the sample that is printable text (UTF-8 aware), length-damped."""
    if not data:
        return 0.0
    sample = data[:SAMPLE]
    try:
        text = sample.decode("utf-8")
        ratio = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r") / len(text)
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 3 and len(data) > SAMPLE:  # cut mid-character by the sample
            return textness(sample[: exc.start])
        ratio = 0.6 * sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (9, 10, 13)) / len(sample)
    return ratio * min(1.0, len(data) / 8)


def signature_names(data: bytes) -> tuple[tuple[str, ...], float]:
    hits = match_signatures(data[:600])
    strong = [s for s in hits if len(s.magic) >= 3]
    if strong:
        return tuple(s.name for s in strong), 1.0
    if is_zlib_header(data) and len(data) > 8:
        return ("zlib stream",), 0.6
    if hits:
        return tuple(s.name for s in hits), 0.2
    return (), 0.0


class CandidateScorer:
    def __init__(self, matcher: FlagMatcher) -> None:
        self.matcher = matcher

    def score(
        self, data: bytes, *, depth: int = 0, cost: int = 0, validity: float = 0.0, potential: float = 0.0
    ) -> Score:
        flags = tuple(self.matcher.scan(data))
        hints = tuple(self.matcher.hints(data)) if not flags else ()
        sample = data[:SAMPLE]
        text = textness(data)
        eng = english_score(sample) if text > 0.5 else 0.0
        entropy = shannon_entropy(sample)
        fit = 1.0 if entropy <= 5.2 else max(0.0, (7.0 - entropy) / 1.8)
        sig_names, sig = signature_names(data)
        flag = max((f.strength for f in flags), default=0.0)
        encoded = P_ENCODED * potential * (1.0 - eng) * (1.0 if text > 0.5 else 0.5)
        random_pen = P_RANDOM if (len(data) >= 32 and entropy > 7.5 and not sig_names and not flags) else 0.0
        parts = {
            "flag": flag,
            "textness": round(text, 4),
            "english": round(eng, 4),
            "entropy_bits": round(entropy, 3),
            "entropy_fit": round(fit * text, 4),
            "signature": sig,
            "validity": round(validity, 4),
            "still_encoded_penalty": round(-encoded, 4),
            "random_penalty": -random_pen,
            "complexity_penalty": round(-(P_DEPTH * depth + P_COST * cost), 4),
        }
        total = (
            flag + W_TEXT * text + W_ENGLISH * eng + W_ENTROPY * fit * text
            + W_SIGNATURE * sig + W_VALIDITY * validity - encoded - random_pen
            - P_DEPTH * depth - P_COST * cost
        )  # fmt: skip
        return Score(max(0.0, total), parts, flags, sig_names, hints)

    @staticmethod
    def priority(score: Score, potential: float) -> float:
        """Search priority: promising = good now, or likely to decode into something good."""
        flag = score.parts.get("flag", 0.0)
        # A heuristic (generic) hit must not dominate the frontier and starve real branches:
        # strong hits end the search anyway, so capping the flag term costs nothing.
        return score.total - flag + min(flag, 1.0) + 0.45 * potential + (0.4 if score.hints else 0.0)
