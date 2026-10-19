import json
import logging

import httpx
import pytest

from uxh_common.notify.feishu import FeishuWebhook, SendResult, gen_sign

URL = "https://open.feishu.cn/open-apis/bot/v2/hook/tok-abc123"
SECRET = "sec-xyz"


class Recorder:
    def __init__(self, response=None, exc=None):
        self.requests = []
        self.response = response or httpx.Response(200, json={"code": 0, "msg": "success", "data": {}})
        self.exc = exc

    def __call__(self, request):
        self.requests.append(request)
        if self.exc:
            raise self.exc
        return self.response

    @property
    def body(self):
        return json.loads(self.requests[-1].content)


def make(rec, **kw):
    return FeishuWebhook(URL, transport=httpx.MockTransport(rec), **kw)


def test_gen_sign_vector():
    assert gen_sign("1599360473", "demo-secret") == "3/MaVZ8JLIy4TUG+7KSFJqvUkTKd+HWY8g+56DZWq8s="


def test_text_payload():
    rec = Recorder()
    result = make(rec).send_text("hi")
    assert rec.body == {"msg_type": "text", "content": {"text": "hi"}}
    assert result == SendResult("sent", 0, "")
    assert str(rec.requests[-1].url) == URL


def test_card_payload():
    rec = Recorder()
    card = {"config": {"update_multi": True}, "elements": []}
    assert make(rec).send_card(card).status == "sent"
    assert rec.body == {"msg_type": "interactive", "card": card}


def test_signed_payload():
    rec = Recorder()
    make(rec, secret=SECRET).send_text("hi")
    body = rec.body
    assert body["timestamp"].isdigit()
    assert body["sign"] == gen_sign(body["timestamp"], SECRET)


def test_gate_closed_no_request():
    rec = Recorder()
    result = make(rec, gate=lambda: False).send_text("hi")
    assert result.status == "suppressed"
    assert rec.requests == []


def test_gate_open_sends():
    rec = Recorder()
    assert make(rec, gate=lambda: True).send_text("hi").status == "sent"


@pytest.mark.parametrize("resp,code", [
    (httpx.Response(200, json={"code": 19021, "msg": "sign match fail or timestamp is not within one hour"}), 19021),
    (httpx.Response(500, text="err"), None),
    (httpx.Response(200, text="<html>"), None),
    (httpx.Response(200, json=["not", "a", "dict"]), None),
])
def test_failed_responses(resp, code):
    result = make(Recorder(response=resp)).send_text("hi")
    assert result.status == "failed"
    assert result.code == code


def test_legacy_statuscode_success():
    rec = Recorder(response=httpx.Response(200, json={"StatusCode": 0, "StatusMessage": "success"}))
    assert make(rec).send_text("hi").status == "sent"


@pytest.mark.parametrize("exc_type", [httpx.ReadTimeout, httpx.ConnectError])
def test_network_error_redacted(exc_type, caplog):
    caplog.set_level(logging.DEBUG)
    rec = Recorder(exc=exc_type(f"boom {URL} /open-apis/bot/v2/hook/tok-abc123 {SECRET}"))
    result = make(rec, secret=SECRET).send_text("hi")
    assert result.status == "failed"
    blob = result.message + caplog.text
    assert URL not in blob and "tok-abc123" not in blob and SECRET not in blob


def test_server_msg_redacted():
    rec = Recorder(response=httpx.Response(200, json={"code": 9499, "msg": f"bad hook tok-abc123 {SECRET}"}))
    result = make(rec, secret=SECRET).send_text("hi")
    assert result.status == "failed"
    assert "tok-abc123" not in result.message and SECRET not in result.message


def test_never_logs_payload(caplog):
    caplog.set_level(logging.DEBUG)
    rec = Recorder()
    make(rec, secret=SECRET).send_text("payload-text-xyz")
    assert "payload-text-xyz" not in caplog.text
    assert URL not in caplog.text and "tok-abc123" not in caplog.text and SECRET not in caplog.text
