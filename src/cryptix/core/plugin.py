"""Plugin interfaces.

Every operation is a class that declares a :class:`PluginInfo` and implements one
or more role interfaces:

=========  =========================================================
Encoder    ``encode(data, **params) -> TransformResult``
Decoder    ``decode(data, **params) -> TransformResult`` and ``detect(data)``
Codec      Encoder + Decoder (reversible)
Cipher     Codec whose behaviour depends on a key parameter
Analyzer   ``analyze(data, **params) -> Report``
Solver     ``solve(data, **params) -> list[Candidate]``
Scorer     ``score(data) -> float``  (0..1, higher = more plausible plaintext)
Detector   ``scan(data) -> list[Finding]``
=========  =========================================================

Authors implement the underscore methods (``_decode`` etc.). The public methods
validate/coerce parameters, translate stdlib exceptions into Cryptix errors, and
wrap results in structured objects, so every plugin behaves consistently.

``PluginInfo.input_type``/``output_type`` describe the *primary* direction: decode
for Decoders/Codecs, encode for encoder-only plugins.
"""

from __future__ import annotations

import abc
import binascii
import lzma
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any, ClassVar

from cryptix.core.data import parse_bytes_arg
from cryptix.errors import CryptixError, DecodeError, EncodeError, ParameterError


class Category(StrEnum):
    BASE = "base"
    TEXT = "text"
    BYTES = "bytes"
    COMPRESSION = "compression"
    SERIALIZATION = "serialization"
    CLASSICAL = "classical"
    XOR = "xor"
    HASH = "hash"
    RSA = "rsa"
    ANALYSIS = "analysis"
    DETECTION = "detection"
    SCORING = "scoring"
    OTHER = "other"


class DataKind(StrEnum):
    BYTES = "bytes"
    TEXT = "text"
    INTEGER = "integer"
    STRUCTURED = "structured"


class Cost(IntEnum):
    """Rough computational cost class used to gate automatic search."""

    TRIVIAL = 1  # O(n), microseconds
    CHEAP = 2  # O(n) with a larger constant, or tiny search
    MODERATE = 3  # seconds on large inputs / modest brute force
    EXPENSIVE = 4  # never run implicitly


class ParamType(StrEnum):
    INT = "int"
    STR = "str"
    BOOL = "bool"
    BYTES = "bytes"


_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f"}


@dataclass(frozen=True)
class Param:
    name: str
    type: ParamType = ParamType.STR
    default: Any = None
    help: str = ""
    required: bool = False
    choices: tuple[Any, ...] = ()

    def coerce(self, value: Any) -> Any:
        """Convert a CLI string (or already-typed value) to this parameter's type."""
        try:
            if self.type is ParamType.INT:
                if isinstance(value, str):
                    try:
                        value = int(value, 0)
                    except ValueError:
                        value = int(value, 10)
                elif isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError("not an integer")
            elif self.type is ParamType.BOOL:
                if isinstance(value, str):
                    low = value.strip().lower()
                    if low in _TRUE:
                        value = True
                    elif low in _FALSE:
                        value = False
                    else:
                        raise ValueError("expected true/false")
                elif not isinstance(value, bool):
                    raise ValueError("expected a boolean")
            elif self.type is ParamType.BYTES:
                if isinstance(value, str):
                    value = parse_bytes_arg(value)
                elif not isinstance(value, bytes | bytearray):
                    raise ValueError("expected bytes")
                value = bytes(value)
            else:
                if not isinstance(value, str):
                    raise ValueError("expected a string")
        except ValueError as exc:
            raise ParameterError(f"parameter '{self.name}': invalid value {value!r} ({exc})") from exc
        if self.choices and value not in self.choices:
            options = ", ".join(str(c) for c in self.choices)
            raise ParameterError(f"parameter '{self.name}': {value!r} not in {{{options}}}")
        return value


@dataclass(frozen=True)
class Example:
    """A documented, test-verified example.

    ``encoded`` is the canonical encoder output; ``decoded`` the plaintext. Tests
    check ``decode(encoded) == decoded`` and, unless ``decode_only``, also
    ``encode(decoded) == encoded``.
    """

    encoded: bytes
    decoded: bytes
    params: Mapping[str, Any] = field(default_factory=dict)
    decode_only: bool = False
    note: str = ""


@dataclass(frozen=True)
class PluginInfo:
    name: str
    category: Category
    description: str
    input_type: DataKind = DataKind.BYTES
    output_type: DataKind = DataKind.BYTES
    reversible: bool = False
    params: tuple[Param, ...] = ()
    cost: Cost = Cost.TRIVIAL
    auto_safe: bool = False
    aliases: tuple[str, ...] = ()
    detection_notes: str = "No detection heuristic."
    examples: tuple[Example, ...] = ()
    #: No structural signature exists: applicability can only be judged from the output's
    #: quality. The auto-decoder tries blind transforms only on text that is not yet English
    #: and keeps the result only if it clearly improves.
    blind: bool = False
    #: Applying the operation twice returns the input. The auto-decoder never applies such an
    #: operation twice in a row (rot13 -> rot13 is a no-op; longer loops are caught by state dedup).
    self_inverse: bool = False

    def resolve_params(self, given: Mapping[str, Any] | None) -> dict[str, Any]:
        """Validate, coerce and default *given* against the declared parameters."""
        given = dict(given or {})
        declared = {p.name: p for p in self.params}
        unknown = sorted(set(given) - set(declared))
        if unknown:
            valid = ", ".join(declared) or "(none)"
            raise ParameterError(
                f"{self.name}: unknown parameter(s) {', '.join(unknown)}; valid: {valid}"
            )
        resolved: dict[str, Any] = {}
        for p in self.params:
            if p.name in given:
                resolved[p.name] = p.coerce(given[p.name])
            elif p.required:
                raise ParameterError(f"{self.name}: missing required parameter '{p.name}'")
            else:
                resolved[p.name] = p.default
        return resolved

    def accepts(self, name: str) -> bool:
        return any(p.name == name for p in self.params)


@dataclass(frozen=True)
class TransformResult:
    data: bytes
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Detection:
    """A decoder's opinion on whether *data* looks like its input format."""

    confidence: float  # 0..1
    evidence: str


@dataclass(frozen=True)
class Finding:
    label: str
    confidence: float
    evidence: str


@dataclass(frozen=True)
class Candidate:
    data: bytes
    score: float
    description: str
    exact: bool = True  # False = heuristic guess
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Report:
    title: str
    fields: Mapping[str, Any]


_STDLIB_ERRORS = (
    ValueError,
    binascii.Error,
    zlib.error,
    lzma.LZMAError,
    EOFError,
    OSError,
    OverflowError,
    UnicodeError,
)


def _guarded(
    info: PluginInfo, error_cls: type[CryptixError], fn: Callable[..., Any], *a: Any, **kw: Any
) -> TransformResult:
    try:
        out = fn(*a, **kw)
    except CryptixError:
        raise
    except _STDLIB_ERRORS as exc:
        raise error_cls(f"{info.name}: {exc}") from exc
    if isinstance(out, TransformResult):
        return out
    return TransformResult(bytes(out))


class Plugin(abc.ABC):
    info: ClassVar[PluginInfo]

    @classmethod
    def roles(cls) -> tuple[str, ...]:
        names = (
            ("encoder", Encoder),
            ("decoder", Decoder),
            ("cipher", Cipher),
            ("analyzer", Analyzer),
            ("solver", Solver),
            ("scorer", Scorer),
            ("detector", Detector),
        )
        return tuple(n for n, base in names if issubclass(cls, base))


class Encoder(Plugin):
    def encode(self, data: bytes, **params: Any) -> TransformResult:
        resolved = self.info.resolve_params(params)
        return _guarded(self.info, EncodeError, self._encode, data, **resolved)

    @abc.abstractmethod
    def _encode(self, data: bytes, **params: Any) -> bytes | TransformResult: ...


class Decoder(Plugin):
    def decode(self, data: bytes, **params: Any) -> TransformResult:
        resolved = self.info.resolve_params(params)
        return _guarded(self.info, DecodeError, self._decode, data, **resolved)

    @abc.abstractmethod
    def _decode(self, data: bytes, **params: Any) -> bytes | TransformResult: ...

    def detect(self, data: bytes) -> Detection | None:
        """Cheap structural check: could *data* be in this decoder's input format?

        Return None when it clearly is not. Must be fast and side-effect free; the
        automatic decoder calls it on every search node.
        """
        return None


class Codec(Encoder, Decoder):
    """Reversible operation."""


class Cipher(Codec):
    """A Codec whose output depends on a key-like parameter."""


class Analyzer(Plugin):
    def analyze(self, data: bytes, **params: Any) -> Report:
        return self._analyze(data, **self.info.resolve_params(params))

    @abc.abstractmethod
    def _analyze(self, data: bytes, **params: Any) -> Report: ...


class Solver(Plugin):
    def solve(self, data: bytes, **params: Any) -> list[Candidate]:
        return self._solve(data, **self.info.resolve_params(params))

    @abc.abstractmethod
    def _solve(self, data: bytes, **params: Any) -> list[Candidate]: ...


class Scorer(Plugin):
    @abc.abstractmethod
    def score(self, data: bytes) -> float: ...


class Detector(Plugin):
    @abc.abstractmethod
    def scan(self, data: bytes) -> list[Finding]: ...
