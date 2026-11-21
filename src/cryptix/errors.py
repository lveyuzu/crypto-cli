"""Exception hierarchy. Every error carries the process exit code it maps to.

Exit codes (stable, documented in README):
    0    success
    1    no result found (e.g. ``auto`` found nothing) / generic Cryptix error
    2    usage, parameter or input-format error
    3    data error: input could not be decoded/encoded by the operation
    4    unknown operation
    5    I/O error (unreadable file, unwritable output)
    130  interrupted (Ctrl+C)
"""

from __future__ import annotations


class CryptixError(Exception):
    exit_code = 1


class UsageError(CryptixError):
    exit_code = 2


class ParameterError(UsageError):
    """A plugin parameter is unknown, missing or has an invalid value."""


class InputError(UsageError):
    """The user-supplied input text could not be interpreted (bad hex, bad escape...)."""


class DecodeError(CryptixError):
    """The data is not valid for the requested decoding."""

    exit_code = 3


class EncodeError(CryptixError):
    """The data cannot be represented in the requested encoding."""

    exit_code = 3


class UnknownPluginError(CryptixError):
    exit_code = 4


class CryptixIOError(CryptixError):
    exit_code = 5
