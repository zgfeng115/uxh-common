import base64
import logging

import pytest

from uxh_common import crypto

KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
KEY = base64.urlsafe_b64decode(KEY_B64)

# Generated 2026-10-19 with the legacy encryption.py files and KEY_B64.
LEGACY = [
    ("uxh-common-compat", "xCmY9KYXXc1RkNkWbvgmSxafRGp6ufwwtJCaz0c3ugdKgCyR04k6Gl7F-Fmv"),  # uxh-ops
    ("中文密码!@#", "G0lXXHhHoapnpabL_vkjmjhvp20a5hhi9xBPp7EXo3EVFX_4Suc8rKejKg=="),  # uxh-ops
    ("uxh-common-compat", "Jn9RNNUfv3sZMfZLQClb3AIRepaMSELw6b_GJ46oI3gBzdfXrE0rpvJHdDVX"),  # xhs_autogen
    ("中文密码!@#", "bhJQW36inax8Ih0u87GDL2pZ1LD3Jnz3I6yEOFNWaJePDdppgFHGIp44OQ=="),  # xhs_autogen
]


@pytest.fixture(autouse=True)
def _clean_key(monkeypatch):
    monkeypatch.delenv("DATA_ENCRYPTION_KEY", raising=False)
    crypto._reset_key_cache()
    yield
    crypto._reset_key_cache()


def _key_warnings(caplog):
    return [r for r in caplog.records if r.name == "uxh_common.crypto" and r.levelno >= logging.WARNING]


@pytest.mark.parametrize("plain,token", LEGACY)
def test_decrypts_legacy_vectors(plain, token):
    assert crypto.decrypt(token, key=KEY) == plain
    assert crypto.decrypt(token, strict=True, key=KEY) == plain


def test_reads_key_from_env(monkeypatch):
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", KEY_B64)
    assert crypto.decrypt(LEGACY[0][1]) == LEGACY[0][0]
    assert crypto.decrypt(LEGACY[0][1], strict=True) == LEGACY[0][0]


@pytest.mark.parametrize("plain", ["中文", "x" * 10000])
def test_roundtrip_chinese_and_long(plain):
    token = crypto.encrypt(plain, key=KEY)
    assert token != plain
    assert crypto.is_encrypted(token)
    assert crypto.decrypt(token, key=KEY) == plain


def test_empty_string_passthrough():
    assert crypto.encrypt("", strict=True, key=KEY) == ""
    assert crypto.decrypt("", key=KEY) == ""


def test_strict_without_key_raises():
    with pytest.raises(crypto.KeyMissingError):
        crypto.encrypt("a", strict=True)
    with pytest.raises(crypto.KeyMissingError):
        crypto.decrypt(LEGACY[0][1], strict=True)


def test_strict_wrong_key_length_raises(monkeypatch):
    bad = base64.urlsafe_b64encode(b"x" * 16).decode()
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", bad)
    with pytest.raises(crypto.KeyMissingError) as ei:
        crypto.encrypt("a", strict=True)
    assert bad not in str(ei.value)
    with pytest.raises(crypto.KeyMissingError):
        crypto.encrypt("a", strict=True, key=b"short")


def test_compat_without_key_passthrough_warns_once(caplog):
    caplog.set_level(logging.WARNING)
    assert crypto.encrypt("abc") == "abc"
    assert crypto.decrypt("abc") == "abc"
    assert crypto.encrypt("def") == "def"
    assert len(_key_warnings(caplog)) == 1


def test_compat_wrong_key_length_passthrough(monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    bad = base64.urlsafe_b64encode(b"x" * 16).decode()
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", bad)
    assert crypto.encrypt("abc") == "abc"
    assert _key_warnings(caplog)
    assert bad not in caplog.text
    # bad key must not be cached: fixing the env takes effect
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", KEY_B64)
    token = crypto.encrypt("abc")
    assert token != "abc"
    assert crypto.decrypt(token, key=KEY) == "abc"


def test_tampered_token_raises_without_leak():
    tok = crypto.encrypt("secret-plain", key=KEY)
    raw = bytearray(base64.urlsafe_b64decode(tok))
    raw[-1] ^= 1
    bad = base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(crypto.DecryptError) as ei:
        crypto.decrypt(bad, key=KEY)
    assert str(ei.value) == "decrypt failed"
    assert bad not in str(ei.value) and "secret-plain" not in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


def test_legacy_plaintext_in_db_raises_decrypt_error():
    with pytest.raises(crypto.DecryptError) as ei:
        crypto.decrypt("plain-api-key-123", key=KEY)
    assert "plain-api-key-123" not in str(ei.value)


def test_is_encrypted_edges():
    assert crypto.is_encrypted("") is False
    assert crypto.is_encrypted("abc") is False
    assert crypto.is_encrypted("密码") is False
    assert crypto.is_encrypted(LEGACY[0][1]) is True


def test_generate_key():
    k = crypto.generate_key()
    raw = base64.urlsafe_b64decode(k)
    assert len(raw) == 32
    assert crypto.decrypt(crypto.encrypt("v", key=raw), key=raw) == "v"
