"""File-signature table shared by detectors and compression plugins."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    name: str
    magic: bytes
    offset: int = 0
    kind: str = "file"  # "file", "archive", "compression", "executable", "text"


SIGNATURES: tuple[Signature, ...] = (
    Signature("PNG image", b"\x89PNG\r\n\x1a\n"),
    Signature("JPEG image", b"\xff\xd8\xff"),
    Signature("GIF image (87a)", b"GIF87a"),
    Signature("GIF image (89a)", b"GIF89a"),
    Signature("PDF document", b"%PDF-"),
    Signature("ZIP archive (also docx/xlsx/jar/apk)", b"PK\x03\x04", kind="archive"),
    Signature("ZIP archive (empty)", b"PK\x05\x06", kind="archive"),
    Signature("gzip", b"\x1f\x8b\x08", kind="compression"),
    Signature("bzip2", b"BZh", kind="compression"),
    Signature("xz", b"\xfd7zXZ\x00", kind="compression"),
    Signature("7-Zip archive", b"7z\xbc\xaf\x27\x1c", kind="archive"),
    Signature("RAR archive", b"Rar!\x1a\x07", kind="archive"),
    Signature("Zstandard", b"\x28\xb5\x2f\xfd", kind="compression"),
    Signature("ELF executable", b"\x7fELF", kind="executable"),
    Signature("PE/DOS executable", b"MZ", kind="executable"),
    Signature("Mach-O (64-bit LE)", b"\xcf\xfa\xed\xfe", kind="executable"),
    Signature("Java class / Mach-O fat", b"\xca\xfe\xba\xbe", kind="executable"),
    Signature("SQLite 3 database", b"SQLite format 3\x00"),
    Signature("tar archive", b"ustar", offset=257, kind="archive"),
    Signature("RIFF container (WAV/AVI/WebP)", b"RIFF"),
    Signature("OGG container", b"OggS"),
    Signature("FLAC audio", b"fLaC"),
    Signature("MP3 (ID3 tag)", b"ID3"),
    Signature("PEM/ASCII-armored block", b"-----BEGIN ", kind="text"),
    Signature("OpenSSH private key", b"openssh-key-v1\x00", offset=15),
    Signature("PCAP capture (LE)", b"\xd4\xc3\xb2\xa1"),
    Signature("PCAPNG capture", b"\x0a\x0d\x0d\x0a"),
    Signature("Windows Registry hive", b"regf"),
    Signature("BMP image", b"BM"),
    Signature("TIFF image (LE)", b"II*\x00"),
    Signature("TIFF image (BE)", b"MM\x00*"),
    Signature("Rich Text Format", b"{\\rtf"),
    Signature("PostScript", b"%!PS"),
)


def match_signatures(data: bytes) -> list[Signature]:
    """All signatures matching *data* (longest magic first, so weak 2-byte ones sort last)."""
    hits = [s for s in SIGNATURES if data[s.offset : s.offset + len(s.magic)] == s.magic]
    return sorted(hits, key=lambda s: -len(s.magic))


def is_zlib_header(data: bytes) -> bool:
    """RFC 1950: CM=8, CINFO<=7, header checksum multiple of 31, no preset dictionary."""
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return (cmf & 0x0F) == 8 and (cmf >> 4) <= 7 and (cmf * 256 + flg) % 31 == 0 and not flg & 0x20
