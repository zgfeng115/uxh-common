import json
import logging

import httpx
import pytest

from uxh_common.notify import feishu
from uxh_common.notify.feishu import FeishuApp, FeishuError, SendResult

APP_ID = "cli_test123"
SECRET = "sec-app"
TOKEN = "t-tenant-token-abc"
TOKEN2 = "t-tenant-token-def"
CHAT = "oc_chat1"


class Feishu:
    """Fake open.feishu.cn: hands out tokens, records messages, pages chats."""

    def __init__(self, *, msg_codes=(0,), tokens=(TOKEN, TOKEN2), expire=7200, chats=None, exc=None):
        self.requests: list[httpx.Request] = []
        self.msg_codes = list(msg_codes)
        self.tokens = list(tokens)
        self.expire = expire
        self.chats = chats or []
        self.exc = exc
        self.token_calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.exc:
            raise self.exc
        path = request.url.path
        if path.endswith("/tenant_access_token/internal"):
            self.token_calls += 1
            return httpx.Response(200, json={"code": 0, "tenant_access_token": self.tokens.pop(0), "expire": self.expire})
        if path.endswith("/im/v1/messages"):
            code = self.msg_codes.pop(0) if len(self.msg_codes) > 1 else self.msg_codes[0]
            return httpx.Response(200, json={"code": code, "msg": "ok" if code == 0 else "bad", "data": {}})
        if path.endswith("/im/v1/chats"):
            page = request.url.params.get("page_token") or "0"
            items, nxt = self.chats[int(page)]
            data = {"items": [{"chat_id": c, "name": n} for c, n in items], "has_more": nxt is not None}
            if nxt is not None:
                data["page_token"] = nxt
            return httpx.Response(200, json={"code": 0, "data": data})
        return httpx.Response(404)

    def messages(self):
        return [r for r in self.requests if r.url.path.endswith("/im/v1/messages")]


def make(fake, **kw):
    return FeishuApp(APP_ID, SECRET, transport=httpx.MockTransport(fake), **kw)


def test_send_text_payload_and_auth():
    fake = Feishu()
    assert make(fake).send_text(CHAT, "hi") == SendResult("sent", 0, "")
    token_req = fake.requests[0]
    assert json.loads(token_req.content) == {"app_id": APP_ID, "app_secret": SECRET}
    msg = fake.messages()[0]
    assert msg.url.params["receive_id_type"] == "chat_id"
    assert msg.headers["Authorization"] == f"Bearer {TOKEN}"
    body = json.loads(msg.content)
    assert body == {"receive_id": CHAT, "msg_type": "text", "content": json.dumps({"text": "hi"})}


def test_send_card_payload():
    fake = Feishu()
    card = {"config": {"update_multi": True}, "elements": []}
    assert make(fake).send_card(CHAT, card).status == "sent"
    body = json.loads(fake.messages()[0].content)
    assert body["msg_type"] == "interactive"
    assert json.loads(body["content"]) == card


def test_token_cached_across_sends():
    fake = Feishu()
    app = make(fake)
    app.send_text(CHAT, "a")
    app.send_text(CHAT, "b")
    assert fake.token_calls == 1


def test_token_refreshed_when_near_expiry():
    fake = Feishu(expire=200)  # under the 300s safety margin: never reused
    app = make(fake)
    app.send_text(CHAT, "a")
    app.send_text(CHAT, "b")
    assert fake.token_calls == 2
    assert fake.messages()[1].headers["Authorization"] == f"Bearer {TOKEN2}"


@pytest.mark.parametrize("code", [99991661, 99991663])
def test_invalid_token_refreshes_once_and_retries(code):
    fake = Feishu(msg_codes=(code, 0))
    assert make(fake).send_text(CHAT, "hi").status == "sent"
    assert fake.token_calls == 2
    assert fake.messages()[1].headers["Authorization"] == f"Bearer {TOKEN2}"


def test_invalid_token_retry_is_bounded():
    fake = Feishu(msg_codes=(99991663, 99991663), tokens=(TOKEN, TOKEN2))
    result = make(fake).send_text(CHAT, "hi")
    assert result.status == "failed"
    assert result.code == 99991663
    assert len(fake.messages()) == 2


def test_business_error_fails():
    fake = Feishu(msg_codes=(230002,))
    result = make(fake).send_text(CHAT, "hi")
    assert result.status == "failed"
    assert result.code == 230002


def test_auth_error_fails_without_raising():
    def handler(request):
        return httpx.Response(200, json={"code": 10003, "msg": f"invalid app_secret {SECRET}"})

    result = FeishuApp(APP_ID, SECRET, transport=httpx.MockTransport(handler)).send_text(CHAT, "hi")
    assert result.status == "failed"
    assert SECRET not in result.message


def test_network_error_fails_without_raising():
    fake = Feishu(exc=httpx.ConnectError("boom"))
    result = make(fake).send_text(CHAT, "hi")
    assert result.status == "failed"
    assert "ConnectError" in result.message


def test_gate_suppresses_without_network():
    fake = Feishu()
    assert make(fake, gate=lambda: False).send_text(CHAT, "hi").status == "suppressed"
    assert fake.requests == []


def test_gate_error_fails_without_raising():
    def gate():
        raise RuntimeError("db down")

    assert make(Feishu(), gate=gate).send_text(CHAT, "hi").status == "failed"


def test_secret_and_token_never_in_result_or_httpx_log(caplog):
    def handler(request):
        if request.url.path.endswith("/tenant_access_token/internal"):
            return httpx.Response(200, json={"code": 0, "tenant_access_token": TOKEN, "expire": 7200})
        return httpx.Response(200, json={"code": 1, "msg": f"echo {SECRET} {TOKEN}"})

    caplog.set_level(logging.DEBUG)
    logging.getLogger("httpx").info("request with %s and %s", SECRET, TOKEN)
    result = FeishuApp(APP_ID, SECRET, transport=httpx.MockTransport(handler)).send_text(CHAT, "hi")
    logging.getLogger("httpx").info("request with %s and %s", SECRET, TOKEN)
    assert result.status == "failed"
    assert SECRET not in result.message and TOKEN not in result.message
    assert SECRET not in caplog.text and TOKEN not in caplog.text


def test_list_chats_pages():
    fake = Feishu(chats=[([("oc_1", "运维群")], "1"), ([("oc_2", "销售群")], None)])
    assert make(fake).list_chats() == [("oc_1", "运维群"), ("oc_2", "销售群")]
    assert fake.token_calls == 1


def test_list_chats_raises_redacted_error():
    def handler(request):
        return httpx.Response(200, json={"code": 10003, "msg": f"bad {SECRET}"})

    with pytest.raises(FeishuError) as ei:
        FeishuApp(APP_ID, SECRET, transport=httpx.MockTransport(handler)).list_chats()
    assert SECRET not in str(ei.value)
    assert ei.value.__context__ is None or SECRET not in str(ei.value.__context__)


def test_module_exports():
    assert feishu.FeishuApp is FeishuApp
