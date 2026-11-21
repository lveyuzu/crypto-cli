"""Chain specification parser: ``base64|hex|rotn(n=3)`` (also comma separated)."""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptix.errors import UsageError


@dataclass
class Step:
    name: str
    params: dict[str, str] = field(default_factory=dict)


def _split_top(spec: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    for ch in spec:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"" and depth:
            quote = ch
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise UsageError("unbalanced ')' in chain specification")
            buf.append(ch)
        elif ch in "|," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if depth or quote:
        raise UsageError("unbalanced parentheses or quotes in chain specification")
    parts.append("".join(buf))
    return [p.strip() for p in parts]


def _split_params(body: str) -> list[str]:
    out, buf, quote = [], [], ""
    for ch in body:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return [p.strip() for p in out if p.strip()]


def parse_chain(spec: str) -> list[Step]:
    steps: list[Step] = []
    for part in _split_top(spec):
        if not part:
            raise UsageError("empty step in chain specification")
        if "(" in part:
            if not part.endswith(")"):
                raise UsageError(f"malformed step {part!r}")
            name, _, body = part[:-1].partition("(")
            params: dict[str, str] = {}
            for item in _split_params(body):
                key, eq, value = item.partition("=")
                if not eq or not key.strip():
                    raise UsageError(f"parameter {item!r} must look like key=value")
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                params[key.strip()] = value
            steps.append(Step(name.strip(), params))
        else:
            steps.append(Step(part))
    return steps
