"""Feishu senders: custom-bot webhook (FeishuWebhook) and app bot (FeishuApp).

send_* never raises: network errors, non-2xx and business errors all return
SendResult(status="failed"). The webhook url, its hook token and the sign
secret never appear in SendResult.message or in logs — including httpx's own
request log, which is filtered.
"""
import base64
import hashlib
import hmac
import json
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import httpx

from uxh_common.secrets import redact

logger = logging.getLogger(__name__)


def gen_sign(timestamp: str, secret: str) -> str:
    string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
    return base64.b64encode(hmac.new(string_to_sign, b"", hashlib.sha256).digest()).decode("ascii")


@dataclass
class SendResult:
    status: Literal["sent", "suppressed", "failed"]
    code: int | None = None
    message: str = ""


class _RedactFilter(logging.Filter):
    """Copy-on-write: filter() reads an immutable tuple, so webhooks created in
    other threads never mutate what an in-flight log record iterates."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._secrets: tuple[str, ...] = ()

    def add(self, items: list[str]) -> None:
        with self._lock:
            merged = set(self._secrets).union(items)
            if len(merged) != len(self._secrets):
                self._secrets = tuple(sorted(merged, key=len, reverse=True))

    def discard(self, item: str) -> None:
        with self._lock:
            if item in self._secrets:
                self._secrets = tuple(s for s in self._secrets if s != item)

    def filter(self, record: logging.LogRecord) -> bool:
        secrets = self._secrets
        if secrets:
            record.msg = redact(record.getMessage(), secrets)
            record.args = None
        return True


_httpx_filter = _RedactFilter()
logging.getLogger("httpx").addFilter(_httpx_filter)


class FeishuWebhook:
    def __init__(self, url: str, *, secret: str | None = None,
                 gate: Callable[[], bool] | None = None, timeout: float = 10.0,
                 transport: httpx.BaseTransport | None = None):
        self._url = url
        self._secret = secret
        self._gate = gate
        self._timeout = timeout
        self._transport = transport
        token = url.rstrip("/").rsplit("/", 1)[-1]
        self._sensitive = [s for s in (url, token, secret) if s]
        _httpx_filter.add(self._sensitive)

    def send_text(self, text: str) -> SendResult:
        return self._send({"msg_type": "text", "content": {"text": text}})

    def send_card(self, card: dict) -> SendResult:
        return self._send({"msg_type": "interactive", "card": card})

    def _send(self, payload: dict) -> SendResult:
        try:
            if self._gate is not None and not self._gate():
                logger.info("feishu webhook status=suppressed")
                return SendResult("suppressed")
            if self._secret:
                ts = str(int(time.time()))
                payload = {**payload, "timestamp": ts, "sign": gen_sign(ts, self._secret)}
            result = self._post(payload)
        except Exception as exc:  # e.g. a gate that reads a DB which is down
            result = self._failed(None, f"{type(exc).__name__}: {exc}")
        log = logger.info if result.status == "sent" else logger.warning
        log("feishu webhook status=%s code=%s", result.status, result.code)
        return result

    def _post(self, payload: dict) -> SendResult:
        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                resp = client.post(self._url, json=payload)
            if not resp.is_success:
                return self._failed(None, f"HTTP {resp.status_code}")
            body = resp.json()
            if not isinstance(body, dict):
                return self._failed(None, "unexpected response body")
            code = body.get("code", body.get("StatusCode"))
            if code == 0:
                return SendResult("sent", 0, "")
            msg = str(body.get("msg") or body.get("StatusMessage") or "")
            return self._failed(code if isinstance(code, int) else None, msg)
        except ValueError:
            return self._failed(None, "response is not JSON")
        except httpx.HTTPError as exc:
            return self._failed(None, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # notification must never break the caller
            return self._failed(None, f"{type(exc).__name__}: {exc}")

    def _failed(self, code: int | None, message: str) -> SendResult:
        return SendResult("failed", code, redact(message, self._sensitive))


class FeishuError(Exception):
    """Raised by FeishuApp.list_chats; message already redacted, no __context__."""


_API = "https://open.feishu.cn/open-apis"
_TOKEN_INVALID = {99991661, 99991663}
_TOKEN_MARGIN = 300


class FeishuApp:
    """App bot (app_id + app_secret) sending to a chat by chat_id."""

    def __init__(self, app_id: str, app_secret: str, *,
                 gate: Callable[[], bool] | None = None, timeout: float = 10.0,
                 transport: httpx.BaseTransport | None = None):
        self._app_id = app_id
        self._secret = app_secret
        self._gate = gate
        self._timeout = timeout
        self._transport = transport
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_until = 0.0
        _httpx_filter.add([app_secret])

    def send_text(self, chat_id: str, text: str) -> SendResult:
        return self._send(chat_id, "text", {"text": text})

    def send_card(self, chat_id: str, card: dict) -> SendResult:
        return self._send(chat_id, "interactive", card)

    def list_chats(self) -> list[tuple[str, str]]:
        try:
            chats: list[tuple[str, str]] = []
            page_token = ""
            with self._client() as client:
                while True:
                    params = {"page_size": "100"}
                    if page_token:
                        params["page_token"] = page_token
                    body = self._authed(client, "GET", "/im/v1/chats", params=params)
                    if body.get("code") != 0:
                        raise _ApiError(body)
                    data = body.get("data") or {}
                    chats += [(c["chat_id"], c.get("name", "")) for c in data.get("items") or []]
                    page_token = data.get("page_token") or ""
                    if not data.get("has_more") or not page_token:
                        return chats
        except Exception as exc:
            message = self._redact(_describe(exc))
        raise FeishuError(message)

    def _send(self, chat_id: str, msg_type: str, content: dict) -> SendResult:
        try:
            if self._gate is not None and not self._gate():
                logger.info("feishu app status=suppressed")
                return SendResult("suppressed")
            payload = {"receive_id": chat_id, "msg_type": msg_type,
                       "content": json.dumps(content, ensure_ascii=False)}
            with self._client() as client:
                body = self._authed(client, "POST", "/im/v1/messages",
                                    params={"receive_id_type": "chat_id"}, json=payload)
            code = body.get("code")
            if code == 0:
                result = SendResult("sent", 0, "")
            else:
                result = self._failed(code if isinstance(code, int) else None, str(body.get("msg") or ""))
        except _ApiError as exc:
            result = self._failed(exc.code, exc.msg)
        except Exception as exc:  # notification must never break the caller
            result = self._failed(None, _describe(exc))
        log = logger.info if result.status == "sent" else logger.warning
        log("feishu app status=%s code=%s", result.status, result.code)
        return result

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self._timeout, transport=self._transport)

    def _authed(self, client: httpx.Client, method: str, path: str, **kw) -> dict:
        body = self._call(client, method, path, self._get_token(client), **kw)
        if body.get("code") in _TOKEN_INVALID:
            body = self._call(client, method, path, self._get_token(client, force=True), **kw)
        return body

    def _call(self, client: httpx.Client, method: str, path: str, token: str, **kw) -> dict:
        resp = client.request(method, _API + path, headers={"Authorization": f"Bearer {token}"}, **kw)
        return _json(resp)

    def _get_token(self, client: httpx.Client, *, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.monotonic() < self._token_until:
                return self._token
            body = _json(client.post(_API + "/auth/v3/tenant_access_token/internal",
                                     json={"app_id": self._app_id, "app_secret": self._secret}))
            if body.get("code") != 0 or not body.get("tenant_access_token"):
                raise _ApiError(body)
            if self._token:
                _httpx_filter.discard(self._token)
            self._token = body["tenant_access_token"]
            _httpx_filter.add([self._token])
            self._token_until = time.monotonic() + int(body.get("expire", 0)) - _TOKEN_MARGIN
            return self._token

    def _redact(self, message: str) -> str:
        return redact(message, [s for s in (self._secret, self._token) if s])

    def _failed(self, code: int | None, message: str) -> SendResult:
        return SendResult("failed", code, self._redact(message))


class _ApiError(Exception):
    def __init__(self, body: dict):
        code = body.get("code")
        self.code = code if isinstance(code, int) else None
        self.msg = str(body.get("msg") or "")
        super().__init__(f"feishu code={self.code} msg={self.msg}")


def _json(resp: httpx.Response) -> dict:
    if not resp.is_success:
        raise RuntimeError(f"HTTP {resp.status_code}")
    body = resp.json()
    if not isinstance(body, dict):
        raise RuntimeError("unexpected response body")
    return body


def _describe(exc: Exception) -> str:
    if isinstance(exc, _ApiError):
        return str(exc)
    if isinstance(exc, ValueError):
        return "response is not JSON"
    return f"{type(exc).__name__}: {exc}"
