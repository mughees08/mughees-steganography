"""Exception hierarchy for Mughees Steganography.

Every error carries a stable machine-readable ``code`` (used by the CLI exit
status, ``--json`` output and the REST API) and a numeric ``exit_code``.
All of them derive from ``ValueError`` so v1.x code that caught
``ValueError`` keeps working.
"""

from __future__ import annotations


class MGSError(ValueError):
    """Base class for all expected, user-facing errors."""

    code = "ERROR"
    exit_code = 1


class UsageError(MGSError):
    code = "USAGE"
    exit_code = 2


class WrongPasswordError(MGSError):
    code = "WRONG_PASSWORD"
    exit_code = 3


class IntegrityError(MGSError):
    """Data was corrupted, truncated or tampered with."""

    code = "INTEGRITY"
    exit_code = 4


class FormatError(MGSError):
    """Not a valid / supported Mughees container."""

    code = "FORMAT"
    exit_code = 5


class CapacityError(MGSError):
    """Image too small, or not enough free disk space."""

    code = "CAPACITY"
    exit_code = 6


class GuardrailError(MGSError):
    """Refused by a safety guardrail (e.g. concealing an executable)."""

    code = "GUARDRAIL"
    exit_code = 7


class Cancelled(MGSError):
    code = "CANCELLED"
    exit_code = 130
