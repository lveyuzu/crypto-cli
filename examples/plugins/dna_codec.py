"""Example Cryptix plugin: DNA encoding (2 bits per base).

Install it by copying this file into ``~/.config/cryptix/plugins/`` (or any directory
listed in $CRYPTIX_PLUGIN_PATH). It is picked up automatically:

    cryptix list -s dna
    cryptix encode dna 'Hi'              ->  CAGACGGC
    cryptix decode dna CAGACGGC          ->  Hi
    cryptix decode dna -p mapping=TGCA GTCT...   # CTFs love permuting the table

To ship a plugin as a package instead, expose the class through an entry point:

    [project.entry-points."cryptix.plugins"]
    dna = "my_package.dna_codec:DnaCodec"
"""

from __future__ import annotations

import re

from cryptix.core.plugin import (
    Category, Codec, DataKind, Detection, Example, Param, ParamType, PluginInfo,
)  # fmt: skip
from cryptix.core.textutil import clean_ascii
from cryptix.errors import DecodeError, ParameterError


def _check_mapping(mapping: str) -> str:
    mapping = mapping.upper()
    if len(mapping) != 4 or len(set(mapping)) != 4:
        raise ParameterError("mapping must be 4 distinct characters, e.g. ACGT")
    return mapping


class DnaCodec(Codec):
    info = PluginInfo(
        name="dna",
        aliases=("dna-bases",),
        category=Category.TEXT,
        description="DNA encoding: each byte is four bases (2 bits each, most significant first). "
        "Default table A=00 C=01 G=10 T=11; permute it with the `mapping` parameter.",
        input_type=DataKind.TEXT,
        output_type=DataKind.BYTES,
        reversible=True,
        params=(
            Param("mapping", ParamType.STR, "ACGT", "Bases for 00,01,10,11 in order."),
            Param("strict", ParamType.BOOL, False, "Reject inner whitespace."),
        ),
        auto_safe=True,
        detection_notes="Only the four bases (and whitespace), length a multiple of 4.",
        examples=(Example(b"CAGACGGC", b"Hi"),),
    )

    def _encode(self, data: bytes, mapping: str, strict: bool) -> bytes:
        table = _check_mapping(mapping)
        return "".join(table[(b >> s) & 3] for b in data for s in (6, 4, 2, 0)).encode()

    def _decode(self, data: bytes, mapping: str, strict: bool) -> bytes:
        table = _check_mapping(mapping)
        text = clean_ascii(data, strict).upper()
        bad = re.search(f"[^{re.escape(table)}]", text)
        if bad:
            raise DecodeError(f"{bad.group()!r} is not one of the bases {table}")
        if len(text) % 4:
            raise DecodeError("number of bases must be a multiple of 4")
        index = {c: i for i, c in enumerate(table)}
        out = bytearray()
        for i in range(0, len(text), 4):
            v = 0
            for ch in text[i : i + 4]:
                v = (v << 2) | index[ch]
            out.append(v)
        return bytes(out)

    def detect(self, data: bytes) -> Detection | None:
        text = re.sub(rb"\s", b"", data).upper()
        if len(text) >= 8 and len(text) % 4 == 0 and re.fullmatch(rb"[ACGT]+", text):
            return Detection(0.4, "only A/C/G/T, length multiple of 4")
        return None
