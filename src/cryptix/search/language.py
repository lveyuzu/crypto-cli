"""Compact English plausibility scoring.

This is deliberately small and dependency-free: letter-frequency cosine similarity, coverage by
the most common English words, and coverage by the most frequent bigrams/trigrams. It is a
*plausibility* signal for short CTF strings, not a full language model (no quadgram corpus is
bundled). English-ness is only one scoring layer: non-English text and binary data are
recognised by other layers.
"""

from __future__ import annotations

import math
import re

_FREQ = dict(zip("etaoinsrhdlucmfywgpbvkxqjz", (
    12.02, 9.10, 8.12, 7.68, 7.31, 6.95, 6.28, 6.02, 5.92, 4.32, 3.98, 2.88, 2.71, 2.61, 2.30,
    2.11, 2.09, 2.03, 1.82, 1.49, 1.11, 0.69, 0.17, 0.11, 0.10, 0.07), strict=True))  # fmt: skip
_EN_VEC = [_FREQ[c] for c in "abcdefghijklmnopqrstuvwxyz"]
_EN_NORM = math.sqrt(sum(x * x for x in _EN_VEC))

BIGRAMS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve "
    "co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur".split()
)
TRIGRAMS = frozenset(
    "the and ing ent ion her for tha nth int ere tio ter est ers ati hat ate all eth hes ver his "
    "oft ith fth sth oth res ont ted ere con ive per".split()
)
WORDS = frozenset(
    """the be to of and a in that have i it for not on with he as you do at this but his by from they
    we say her she or an will my one all would there their what so up out if about who get which go me
    when make can like time no just him know take people into year your good some could them see other
    than then now look only come its over think also back after use two how our work first well way even
    new want because any these give day most us is are was were been has had did said each tell does
    set three need house where much before right too mean old same boy follow came show also around
    form small found still between name should home big end put read hand port large spell add land here
    must high such why ask men went kind need picture try again animal point mother world near build self
    earth father head stand own page should country found answer school grow study learn plant cover food
    sun four thought let keep eye never last door between city tree cross since hard start might story saw
    far sea draw left late run while press close night real life few stop open seem together next white
    children begin got walk example ease paper often always music those both mark book letter until mile
    river car feet care second group carry took rain eat room friend began idea fish mountain north once
    base hear horse cut sure watch color face wood main enough plain girl usual young ready above ever red
    list though feel talk bird soon body dog family direct pose leave song measure state product black
    short numeral class wind question happen complete ship area half rock order fire south problem piece
    told knew pass farm top whole king size heard best hour better true during hundred five remember step
    early hold west ground interest reach fast verb sing listen six table travel less morning ten simple
    several vowel toward war lay against pattern slow center love person money serve appear road map
    secret password key flag message hello world congratulations welcome decode encoded text data file
    ctf challenge solution answer crypto cipher the quick brown fox jumps lazy dog is are""".split()
)
_TOKEN = re.compile(r"[a-z]+")


def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def letter_cosine(letters: str) -> float:
    counts = [0] * 26
    for c in letters:
        counts[ord(c) - 97] += 1
    norm = math.sqrt(sum(c * c for c in counts))
    if not norm:
        return 0.0
    return sum(a * b for a, b in zip(counts, _EN_VEC, strict=True)) / (norm * _EN_NORM)


def english_parts(data: bytes) -> dict[str, float]:
    """Component scores (0..1) of English plausibility; all zero for non-text input."""
    zero = {"letters": 0.0, "words": 0.0, "bigrams": 0.0, "freq": 0.0}
    sample = data[:20000]
    if len(sample) < 4:
        return zero
    text = sample.decode("latin-1").lower()
    tokens = _TOKEN.findall(text)
    n_letters = sum(len(t) for t in tokens)
    if n_letters < 3:
        return zero
    share = sum(1 for c in text if "a" <= c <= "z" or c in " \n\r\t.,;:!?'\"-") / len(text)
    words = sum(len(t) for t in tokens if t in WORDS) / n_letters
    pairs = [(t[i : i + 2], t[i : i + 3]) for t in tokens for i in range(len(t) - 1)]
    bi = sum(1 for b, _ in pairs if b in BIGRAMS) / max(1, len(pairs))
    tri_total = sum(1 for _, t in pairs if len(t) == 3)
    tri = sum(1 for _, t in pairs if t in TRIGRAMS) / max(1, tri_total)
    ngram = _clamp(0.6 * bi / 0.40 + 0.4 * tri / 0.12)
    freq = _clamp((letter_cosine("".join(tokens)) - 0.80) / 0.17)
    return {"letters": share, "words": _clamp(words / 0.5), "bigrams": ngram, "freq": freq}


def english_score(data: bytes) -> float:
    p = english_parts(data)
    return _clamp(p["letters"] * (0.40 * p["words"] + 0.30 * p["bigrams"] + 0.30 * p["freq"]))
