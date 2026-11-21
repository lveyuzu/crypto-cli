"""Accuracy + speed benchmark for `cryptix auto` on synthetic multilayer challenges.

    PYTHONPATH=src python benchmarks/auto_corpus.py exhaustive 2     # every ordered 2-op chain
    PYTHONPATH=src python benchmarks/auto_corpus.py random 11 300    # seed 11, 300 random 1-5 layer chains

A chain counts as recovered when the search reports a *non-generic* flag match whose text is a
substring of the true plaintext. Lossy encoders (morse, a1z26 discard case), letter ciphers over
compressed bytes, and consecutive blind transforms are excluded: they are not realistic challenges.
"""

from __future__ import annotations

import collections
import itertools
import random
import statistics
import sys
import time

from cryptix.core.registry import Registry
from cryptix.search.engine import AutoDecoder, SearchConfig

REG = Registry()
REG.discover(entry_points=False, user_dirs=False)
OPS = [p.info.name for p in REG.decoders() if p.info.auto_safe and p.info.name not in {"morse", "a1z26"}]
BLIND, LETTER, BINARY = {"rot13", "reverse", "atbash", "rot47"}, {"rot13", "atbash", "rot47"}, {"zlib", "gzip", "bzip2", "lzma"}
PLAINS = [
    b"flag{layers_of_encoding}", b"CTF{n3st3d_3nc0d1ng_is_fun}", b"picoCTF{b4s3_s1xty_f0ur}",
    b"HTB{some_hackthebox_flag_123}", b"The flag is flag{inside_a_sentence} so keep reading.",
]  # fmt: skip


def encode(ops, data):
    for op in ops:
        if op == "z85":
            data += b" " * (-len(data) % 4)
        data = REG.get(op).encode(data).data
    return data


def realistic(ops):
    if any(a in BLIND and b in BLIND for a, b in zip(ops, ops[1:])):
        return False
    binary = False
    for o in ops:
        if o in LETTER and binary:
            return False
        binary = o in BINARY or (binary and o == "reverse")
    return True


def run(chains, plains):
    ok, times, fails = 0, [], collections.Counter()
    for ops in chains:
        for plain in plains:
            try:
                data = encode(ops, plain)
            except Exception:
                continue  # e.g. html over binary: cannot be encoded
            if data == plain or len(data) > 300_000:
                continue
            t = time.perf_counter()
            res = AutoDecoder(REG, SearchConfig(time_limit=10)).run(data)
            times.append(time.perf_counter() - t)
            if any(f.kind != "generic" and f.data in plain for n in res.flag_nodes for f in n.score.flags):
                ok += 1
            else:
                fails["|".join(ops)] += 1
    ts = sorted(times)
    print(f"recovered {ok}/{len(times)} ({100 * ok / max(1, len(times)):.1f}%)")
    print(f"time per search: median {statistics.median(ts) * 1000:.1f} ms, p95 {ts[int(len(ts) * .95)] * 1000:.1f} ms, max {ts[-1] * 1000:.1f} ms")
    for chain, n in fails.most_common(15):
        print(f"  not recovered: {chain} ({n}x)")


def main(argv):
    mode = argv[1] if len(argv) > 1 else "exhaustive"
    if mode == "exhaustive":
        depth = int(argv[2]) if len(argv) > 2 else 2
        run((c for c in itertools.product(OPS, repeat=depth) if realistic(c)), PLAINS[:3])
    else:
        rng = random.Random(int(argv[2]) if len(argv) > 2 else 1)
        n = int(argv[3]) if len(argv) > 3 else 200
        chains = [[rng.choice(OPS) for _ in range(rng.choice([1, 2, 2, 3, 3, 4, 5]))] for _ in range(n)]
        run((c for c in chains if realistic(c)), [rng.choice(PLAINS)])


if __name__ == "__main__":
    main(sys.argv)
