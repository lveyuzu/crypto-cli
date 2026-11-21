"""Bounded search over chains of decoders.

State = bytes. An edge = one auto-safe decoder whose ``detect()`` fired (or a *blind* transform
such as rot13 that is judged purely by whether the output improves). Strategies:

  best-first  expand the highest-priority node; at most ``beam_width`` children kept per node
  beam        level by level, keep the ``beam_width`` best nodes per depth
  bfs         level by level, keep everything (bounded by ``max_nodes``)

Protection against useless work:
  * dedup: a state (blake2b of its bytes) is never expanded twice, which also kills cycles;
  * a self-inverse operation (rot13, reverse ...) is never applied twice in a row;
  * blind transforms only run on printable text that is not already English, and are kept only
    if the output is clearly more English-like;
  * low-value branches sink to the back of the frontier by priority (they are not discarded:
    a reversed or compressed blob looks like junk until a blind byte transform reveals it);
  * hard limits: depth, nodes, wall time, per-output size, retained memory; Ctrl+C returns the
    results found so far.
Expensive plugins (cost > ``max_cost``) or plugins without ``auto_safe`` are never run implicitly.
"""

from __future__ import annotations

import hashlib
import heapq
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptix.core.data import is_texty
from cryptix.core.plugin import Cost, Decoder
from cryptix.core.registry import Registry, get_registry
from cryptix.errors import CryptixError, UsageError
from cryptix.search.flags import FlagMatcher
from cryptix.search.scoring import SAMPLE, CandidateScorer, Score

MiB = 1024 * 1024
STRATEGIES = ("best-first", "beam", "bfs")
BLIND_MAX_ENGLISH = 0.35  # blind transforms are only tried while the text is not yet English
BLIND_MIN_GAIN = 0.15  # ... and must raise the English score by at least this much,
BLIND_MIN_POTENTIAL_GAIN = 0.25  # ... or make the text newly recognisable as an encoding,
STILL_ENCODED = 0.5  # a flag hit on data with a detection >= this is not yet "settled"
SPECULATIVE_PENALTY = 0.3  # a non-improving blind step is kept as a low-priority "speculative" probe


@dataclass
class SearchConfig:
    max_depth: int = 8
    beam_width: int = 16
    max_nodes: int = 5000
    time_limit: float = 30.0
    max_output: int = 16 * MiB
    max_memory: int = 512 * MiB
    strategy: str = "best-first"
    min_confidence: float = 0.05
    min_score: float = 0.30
    max_cost: Cost = Cost.CHEAP
    stop_on_flag: bool = True
    only: frozenset[str] | None = None
    exclude: frozenset[str] = frozenset()
    max_detect_bytes: int = 32 * MiB
    #: After a *generic* (heuristic) flag match the search continues for this many more nodes,
    #: so a user-specified / known-prefix match found by a further transform can overtake it.
    generic_grace: int = 64
    #: Same, for a strong match on data that still looks like an encoding/container.
    settle_grace: int = 16

    def validate(self) -> None:
        if self.strategy not in STRATEGIES:
            raise UsageError(f"unknown strategy {self.strategy!r}; choose from {', '.join(STRATEGIES)}")
        for name in ("max_depth", "beam_width", "max_nodes"):
            if getattr(self, name) < 1:
                raise UsageError(f"{name} must be >= 1")
        if self.time_limit <= 0 or self.max_output < 1:
            raise UsageError("time limit and max output must be positive")


@dataclass(frozen=True)
class Step:
    op: str
    confidence: float
    mode: str  # "strict" | "permissive" | "blind"
    in_len: int
    out_len: int
    evidence: str


@dataclass(slots=True, eq=False)
class Node:
    id: int
    data: bytes
    steps: tuple[Step, ...]
    depth: int
    score: Score
    parent: Node | None
    cost: int
    potential: float
    texty: bool
    used_self_inverse: frozenset[str]
    speculative: bool = False
    detections: list[tuple[Decoder, float, str]] = field(default_factory=list)

    @property
    def chain(self) -> list[str]:
        return [s.op for s in self.steps]

    @property
    def chain_spec(self) -> str:
        return "|".join(self.chain)

    def path(self) -> list[Node]:
        out, n = [], self
        while n is not None:
            out.append(n)
            n = n.parent  # type: ignore[assignment]
        return out[::-1]

    def is_ancestor_of(self, other: Node) -> bool:
        n = other.parent
        while n is not None:
            if n is self:
                return True
            n = n.parent
        return False


@dataclass
class SearchStats:
    nodes_generated: int = 0
    nodes_expanded: int = 0
    decode_attempts: int = 0
    pruned: dict[str, int] = field(default_factory=dict)
    elapsed: float = 0.0
    stop_reason: str = "exhausted"
    retained_bytes: int = 0
    plugin_errors: int = 0

    def prune(self, why: str) -> None:
        self.pruned[why] = self.pruned.get(why, 0) + 1


@dataclass
class SearchResult:
    candidates: list[Node]  # ranked, non-dominated, best first
    flag_nodes: list[Node]
    stats: SearchStats
    root: Node

    @property
    def interrupted(self) -> bool:
        return self.stats.stop_reason == "interrupted"

    @property
    def flag_found(self) -> bool:
        return bool(self.flag_nodes)


Progress = Callable[[SearchStats, float], None]
DEFAULTS = SearchConfig()  # single source of truth for CLI defaults


class AutoDecoder:
    def __init__(
        self,
        registry: Registry | None = None,
        config: SearchConfig | None = None,
        matcher: FlagMatcher | None = None,
        progress: Progress | None = None,
    ) -> None:
        self.registry = registry or get_registry()
        self.cfg = config or SearchConfig()
        self.cfg.validate()
        self.matcher = matcher or FlagMatcher()
        self.scorer = CandidateScorer(self.matcher)
        self.progress = progress
        self.decoders = self._eligible()

    # ------------------------------------------------------------ plugin selection
    def _eligible(self) -> list[Decoder]:
        cfg = self.cfg
        if cfg.only is not None:
            for name in cfg.only:  # explicit names are validated (and may opt in non-auto-safe ops)
                self.registry.resolve_name(name)
        only = {self.registry.resolve_name(n) for n in cfg.only} if cfg.only is not None else None
        out = []
        for p in self.registry.decoders():
            name = p.info.name
            if name in {self.registry.resolve_name(n) for n in cfg.exclude}:
                continue
            if only is not None:
                if name not in only:
                    continue
            elif not p.info.auto_safe:
                continue
            if p.info.cost > cfg.max_cost or any(q.required for q in p.info.params):
                continue
            out.append(p)
        return out

    # ------------------------------------------------------------ main entry
    def run(self, data: bytes) -> SearchResult:
        self._t0 = time.monotonic()
        self._last_progress = 0.0
        self._next_id = 0
        self._seen: dict[bytes, Node] = {}
        self._all: list[Node] = []
        self._flag_nodes: list[Node] = []
        self._done = False
        self.stats = SearchStats()
        root = self._make_node(data, (), None, validity=0.0)
        self._all.append(root)
        self._seen[self._key(data)] = root
        self._grace_until: int | None = None
        if root.score.flags:
            self._flag_nodes.append(root)
            self._on_flag(root)
        try:
            if not self._done:
                {"best-first": self._best_first, "beam": self._beam, "bfs": self._bfs}[self.cfg.strategy](root)
        except KeyboardInterrupt:
            self.stats.stop_reason = "interrupted"
        self.stats.elapsed = time.monotonic() - self._t0
        return SearchResult(self._rank(), self._flag_nodes, self.stats, root)

    # ------------------------------------------------------------ strategies
    def _best_first(self, root: Node) -> None:
        heap: list[tuple[float, int, Node]] = []
        heapq.heappush(heap, (-self._prio(root), root.id, root))
        while heap and not self._stop():
            _, _, node = heapq.heappop(heap)
            if node.depth >= self.cfg.max_depth:
                continue
            kids = sorted(self._expand(node), key=self._prio, reverse=True)[: self.cfg.beam_width]
            for k in kids:
                heapq.heappush(heap, (-self._prio(k), k.id, k))

    def _beam(self, root: Node) -> None:
        frontier = [root]
        for _ in range(self.cfg.max_depth):
            kids: list[Node] = []
            for node in frontier:
                if self._stop():
                    return
                kids += self._expand(node)
            frontier = sorted(kids, key=self._prio, reverse=True)[: self.cfg.beam_width]
            if not frontier:
                return

    def _bfs(self, root: Node) -> None:
        frontier = [root]
        for _ in range(self.cfg.max_depth):
            kids: list[Node] = []
            for node in frontier:
                if self._stop():
                    return
                kids += self._expand(node)
            frontier = kids
            if not frontier:
                return

    # ------------------------------------------------------------ expansion
    def _prio(self, node: Node) -> float:
        return self.scorer.priority(node.score, node.potential) - (SPECULATIVE_PENALTY if node.speculative else 0.0)

    def _stop(self) -> bool:
        if self._done:
            return True
        cfg, st = self.cfg, self.stats
        self._tick()
        if time.monotonic() - self._t0 >= cfg.time_limit:
            st.stop_reason, self._done = "time limit", True
        elif st.nodes_generated >= cfg.max_nodes:
            st.stop_reason, self._done = "node limit", True
        elif st.retained_bytes >= cfg.max_memory:
            st.stop_reason, self._done = "memory limit", True
        elif self._grace_until is not None and st.nodes_generated >= self._grace_until:
            st.stop_reason, self._done = "flag found", True
        return self._done

    def _on_flag(self, node: Node) -> None:
        """Decide whether a flag hit ends the search.

        * strong match on data that no longer looks encoded -> stop now;
        * strong match on data that still looks encoded (e.g. an xz blob that stores the text
          verbatim) -> short grace period, so the fully decoded result can overtake it;
        * generic (heuristic) match -> longer grace period.
        """
        if not self.cfg.stop_on_flag:
            return
        strong = any(f.kind != "generic" for f in node.score.flags)
        if strong and node.potential < STILL_ENCODED:
            self._done = True
            self.stats.stop_reason = "flag found"
            return
        grace = self.cfg.settle_grace if strong else self.cfg.generic_grace
        deadline = self.stats.nodes_generated + grace
        if self._grace_until is None or deadline < self._grace_until:
            self._grace_until = deadline

    def _tick(self) -> None:
        if self.progress is None:
            return
        now = time.monotonic()
        if now - self._last_progress >= 0.1:
            self._last_progress = now
            self.stats.elapsed = now - self._t0
            self.progress(self.stats, max((n.score.total for n in self._all), default=0.0))

    def _expand(self, node: Node) -> list[Node]:
        self.stats.nodes_expanded += 1
        kids: list[Node] = []
        for plugin, conf, evidence in self._applicable(node):
            if self._stop():
                break
            kid = self._apply(node, plugin, conf, evidence)
            if kid is not None:
                kids.append(kid)
                if kid.score.flags:
                    self._on_flag(kid)
                    if self._done:
                        break
        return kids

    def _applicable(self, node: Node) -> list[tuple[Decoder, float, str]]:
        found: list[tuple[Decoder, float, str]] = []
        for p in self.decoders:
            info = p.info
            if info.blind:
                continue
            if info.input_type.value == "text" and not node.texty:
                continue
            if info.input_type.value == "text" and len(node.data) > self.cfg.max_detect_bytes:
                continue
            try:
                det = p.detect(node.data)
            except Exception:  # a faulty third-party detector must not abort the search
                self.stats.plugin_errors += 1
                continue
            if det is not None and det.confidence >= self.cfg.min_confidence:
                found.append((p, det.confidence, det.evidence))
        node.detections = list(found)
        found.sort(key=lambda t: -t[1])
        if not node.speculative and node.score.english < BLIND_MAX_ENGLISH:
            for p in self.decoders:
                if not p.info.blind or (p.info.self_inverse and node.steps and node.steps[-1].op == p.info.name):
                    continue  # an immediate repeat of a self-inverse op is a no-op; other loops are caught by dedup
                if node.texty or p.info.input_type.value == "bytes":  # letter ciphers need text; reverse works on bytes
                    found.append((p, 0.2, "blind transform (judged by output quality)"))
        return found

    def _apply(self, node: Node, plugin: Decoder, conf: float, evidence: str) -> Node | None:
        info, st = plugin.info, self.stats
        st.decode_attempts += 1
        params: dict[str, Any] = {"max_output": self.cfg.max_output} if info.accepts("max_output") else {}
        mode = "blind" if info.blind else "permissive"
        try:
            res = None
            if info.accepts("strict") and not info.blind:
                try:
                    res = plugin.decode(node.data, strict=True, **params)
                    mode = "strict"
                except CryptixError:
                    res = None
            if res is None:
                res = plugin.decode(node.data, **params)
        except CryptixError:
            st.prune("decode failed")
            return None
        except Exception:
            st.plugin_errors += 1
            st.prune("plugin error")
            return None
        out = res.data
        if not out:
            st.prune("empty output")
            return None
        if len(out) > self.cfg.max_output:
            st.prune("output too large")
            return None
        key = self._key(out)
        if key in self._seen:
            st.prune("duplicate state")
            return None
        validity = conf * (1.0 if mode == "strict" else 0.6)
        step = Step(info.name, conf, mode, len(node.data), len(out), evidence)
        kid = self._make_node(out, (*node.steps, step), node, validity)
        if info.blind and not kid.score.flags:
            improved = (
                kid.score.english >= node.score.english + BLIND_MIN_GAIN
                or kid.potential >= node.potential + BLIND_MIN_POTENTIAL_GAIN
                or (kid.score.signatures and not node.score.signatures)
            )
            if not improved:
                if node.speculative or not node.texty or node.depth + 1 >= self.cfg.max_depth:
                    st.prune("blind transform did not improve")
                    return None
                kid.speculative = True  # probe one more step; descendants decide whether it pays off
        self._seen[key] = kid
        self._all.append(kid)
        st.nodes_generated += 1
        st.retained_bytes += len(out)
        if kid.score.flags:
            self._flag_nodes.append(kid)
        # Low-scoring binary junk is NOT pruned: it may be a reversed/compressed blob that a
        # blind byte transform can still reveal. Its low priority keeps it at the back of the
        # frontier, and expanding it is cheap (only byte-level detectors and `reverse` apply).
        return kid

    # ------------------------------------------------------------ nodes / ranking
    @staticmethod
    def _key(data: bytes) -> bytes:
        return hashlib.blake2b(data, digest_size=16).digest()

    def _make_node(self, data: bytes, steps: tuple[Step, ...], parent: Node | None, validity: float) -> Node:
        texty = is_texty(data[:SAMPLE]) if data else False
        potential = self._potential(data, texty)
        cost = sum(int(self.registry.get(s.op).info.cost) for s in steps)
        score = self.scorer.score(data, depth=len(steps), cost=cost, validity=validity, potential=potential)
        used = frozenset(
            s.op for s in steps if self.registry.get(s.op).info.self_inverse
        )
        self._next_id += 1
        return Node(self._next_id, data, steps, len(steps), score, parent, cost, potential, texty, used)

    def _potential(self, data: bytes, texty: bool) -> float:
        """Best detection confidence among further decoders (how 'still encoded' is this?)."""
        best = 0.0
        for p in self.decoders:
            if p.info.blind or (p.info.input_type.value == "text" and (not texty or len(data) > self.cfg.max_detect_bytes)):
                continue
            try:
                det = p.detect(data)
            except Exception:
                continue
            if det is not None and det.confidence > best:
                best = det.confidence
        return best

    def _rank(self) -> list[Node]:
        eligible = [
            n for n in self._all
            if (n.depth >= 1 or n.score.flags)
            and (n.score.flags or (n.score.total >= self.cfg.min_score and not n.speculative))
        ]  # fmt: skip
        eligible.sort(key=lambda n: (-n.score.total, n.depth, n.id))
        kept: list[Node] = []
        for n in eligible[:300]:  # dominance check is quadratic: bound it
            if any(k.is_ancestor_of(n) or n.is_ancestor_of(k) for k in kept):
                continue  # same path as a better candidate
            kept.append(n)
        return kept


def explain_path(node: Node) -> list[str]:
    """Human-readable, step-by-step justification of how *node* was reached."""
    lines = []
    for i, s in enumerate(node.steps, 1):
        lines.append(f"{i}. {s.op} [{s.mode}, confidence {s.confidence:.2f}]  {s.in_len} -> {s.out_len} bytes  ({s.evidence})")
    return lines


def parse_size(text: str) -> int:
    """'16M' / '512k' / '1G' / '123' -> bytes."""
    t = text.strip().lower()
    mult = {"k": 1024, "m": MiB, "g": 1024 * MiB}.get(t[-1:], 1)
    try:
        return int(float(t[:-1] if t[-1:] in "kmg" else t) * mult)
    except ValueError as exc:
        raise UsageError(f"invalid size {text!r} (use e.g. 4096, 512k, 16M)") from exc


def names_set(items: Iterable[str] | None) -> frozenset[str] | None:
    if items is None:
        return None
    out: set[str] = set()
    for item in items:
        out.update(x.strip() for x in item.split(",") if x.strip())
    return frozenset(out)


Mapping  # re-exported typing helper (kept for annotations in callers)
