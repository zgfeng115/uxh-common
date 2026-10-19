"""Feishu custom-bot webhook sender.

Never raises: network errors, non-2xx and business errors all return
SendResult(status="failed"). The webhook url, its hook token and the sign
secret never appear in SendResult.message or in logs — including httpx's own
request log, which is filtered.
"""
import base64
import hashlib
import hmac
import logging
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
    def __init__(self) -> None:
        super().__init__()
        self.secrets: set[str] = set()

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            record.msg = redact(record.getMessage(), self.secrets)
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
        _httpx_filter.secrets.update(self._sensitive)

    def send_text(self, text: str) -> SendResult:
        return self._send({"msg_type": "text", "content": {"text": text}})

    def send_card(self, card: dict) -> SendResult:
        return self._send({"msg_type": "interactive", "card": card})

    def _send(self, payload: dict) -> SendResult:
        if self._gate is not None and not self._gate():
            logger.info("feishu webhook status=suppressed")
            return SendResult("suppressed")
        if self._secret:
            ts = str(int(time.time()))
            payload = {**payload, "timestamp": ts, "sign": gen_sign(ts, self._secret)}
        result = self._post(payload)
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
