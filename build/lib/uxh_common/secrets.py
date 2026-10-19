"""Secret field helpers: mask for API output, keep-on-masked merge for PUT,
and redaction before anything reaches logs or error messages."""
from collections.abc import Iterable

MASK = "***"


def mask(value: str | None) -> str:
    return MASK if value else ""


def is_masked(value: str | None) -> bool:
    return value == MASK


def merge_secret(incoming: str | None, stored: str) -> str:
    if not incoming or is_masked(incoming):
        return stored
    return incoming


def redact(text: str, secrets: Iterable[str | None]) -> str:
    # Longest first so a secret that contains another is replaced whole.
    for s in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(s, MASK)
    return text
