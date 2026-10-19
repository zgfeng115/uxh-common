"""AES-256-GCM field encryption, byte-compatible with the legacy encryption.py
in uxh-ops-system and xhs_autogen.

Token format: urlsafe_b64encode(nonce(12) + ciphertext_with_tag), no AAD.
Key: DATA_ENCRYPTION_KEY, urlsafe base64 of 32 bytes.

strict=False (compat) mirrors the legacy behaviour: without a usable key,
values pass through as plaintext. Only for migrating old projects.
strict=True raises KeyMissingError instead. New projects use strict.
"""
import base64
import binascii
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

ENV_VAR = "DATA_ENCRYPTION_KEY"
_NONCE_LEN = 12

_cached_key: bytes | None = None
_missing_warned = False


class CryptoError(Exception):
    pass


class KeyMissingError(CryptoError):
    pass


class DecryptError(CryptoError):
    pass


def _reset_key_cache() -> None:
    global _cached_key, _missing_warned
    _cached_key = None
    _missing_warned = False


def _unusable(reason: str, strict: bool) -> None:
    if strict:
        raise KeyMissingError(f"{ENV_VAR} {reason}")
    logger.warning("%s %s — sensitive fields pass through as plaintext", ENV_VAR, reason)


def _resolve_key(key: bytes | None, strict: bool) -> bytes | None:
    global _cached_key, _missing_warned
    if key is not None:
        if len(key) != 32:
            _unusable("must be 32 bytes", strict)
            return None
        return key
    if _cached_key is not None:
        return _cached_key

    raw = os.environ.get(ENV_VAR)
    if not raw:
        if strict:
            raise KeyMissingError(f"{ENV_VAR} is not set")
        if not _missing_warned:
            logger.warning("%s is not set — sensitive fields pass through as plaintext", ENV_VAR)
            _missing_warned = True
        return None
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except (binascii.Error, ValueError):
        _unusable("is not valid base64", strict)
        return None
    if len(decoded) != 32:
        _unusable("must decode to 32 bytes", strict)
        return None
    _cached_key = decoded
    return decoded


def encrypt(plaintext: str, *, strict: bool = False, key: bytes | None = None) -> str:
    if not plaintext:
        return ""
    k = _resolve_key(key, strict)
    if k is None:
        return plaintext
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(k).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt(token: str, *, strict: bool = False, key: bytes | None = None) -> str:
    if not token:
        return ""
    k = _resolve_key(key, strict)
    if k is None:
        return token
    try:
        combined = base64.urlsafe_b64decode(token.encode("ascii"))
        plaintext = AESGCM(k).decrypt(combined[:_NONCE_LEN], combined[_NONCE_LEN:], None)
        return plaintext.decode("utf-8")
    except (ValueError, InvalidTag):
        # binascii.Error, UnicodeError are ValueError subclasses; drop the chain so
        # the original exception (which may echo the token) never surfaces.
        raise DecryptError("decrypt failed") from None


def is_encrypted(value: str) -> bool:
    if not value:
        return False
    try:
        return len(base64.urlsafe_b64decode(value.encode("ascii"))) >= 28
    except Exception:
        return False


def generate_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
