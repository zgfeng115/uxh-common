# uxh-common v0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新建无状态公共包 `uxh-common`：AES-GCM 加解密（兼容现有密文）、密钥打码/脱敏、飞书 webhook 发送，打 tag v0.1.0 供 yundocker-deployer 引用。

**Architecture:** 三个互不依赖的模块：`crypto`、`secrets`，以及依赖 `secrets.redact` 的 `notify.feishu`。不碰数据库、不读配置文件，只有 `crypto` 读一个环境变量。工程布局照抄 `/Users/Shared/AIGC/AICoding/uxh-ai`（setuptools、`[tool.setuptools.packages.find]`、`tests/`）。

**Tech Stack:** Python ≥3.11、cryptography≥42（AESGCM）、httpx≥0.27（`httpx.Client` + `MockTransport`）、pytest。

**Spec:** `/Users/Shared/AIGC/AICoding/uxh-common/docs/spec.md`（PRD：`docs/prd.md`）

## Global Constraints

- `requires-python = ">=3.11"`；依赖 `cryptography>=42`, `httpx>=0.27`；dev 依赖 `pytest`。本地 venv 用 `/opt/homebrew/bin/python3.12`（deployer 镜像是 3.11，不用系统 3.14）。
- `uxh_common/__init__.py`：`__version__ = "0.1.0"`，pyproject `version = "0.1.0"`。
- 环境变量名 `DATA_ENCRYPTION_KEY`；解码后必须 32 字节。
- 密文格式 `urlsafe_b64encode(nonce(12) + ciphertext_with_tag)`，AAD=None。
- `MASK = "***"`。
- 任何异常文本、日志、`SendResult.message` 中不得出现：密钥、明文、密文、webhook url、签名 secret。
- 日志 logger 名：`uxh_common.crypto`、`uxh_common.notify.feishu`。
- 不改 uxh-ops-system、xhs_autogen 任何代码。
- 开发命令：`/opt/homebrew/bin/python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"`；测试 `.venv/bin/python -m pytest -q`。

## 已固化的测试向量（2026-10-19 用现有代码生成）

测试密钥：`AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`（即 `urlsafe_b64encode(bytes(range(32)))`）

| 来源 | 明文 | 密文 |
|---|---|---|
| uxh-ops `backend/db/encryption.py` | `uxh-common-compat` | `xCmY9KYXXc1RkNkWbvgmSxafRGp6ufwwtJCaz0c3ugdKgCyR04k6Gl7F-Fmv` |
| uxh-ops | `中文密码!@#` | `G0lXXHhHoapnpabL_vkjmjhvp20a5hhi9xBPp7EXo3EVFX_4Suc8rKejKg==` |
| xhs_autogen `shared/encryption.py` | `uxh-common-compat` | `Jn9RNNUfv3sZMfZLQClb3AIRepaMSELw6b_GJ46oI3gBzdfXrE0rpvJHdDVX` |
| xhs_autogen | `中文密码!@#` | `bhJQW36inax8Ih0u87GDL2pZ1LD3Jnz3I6yEOFNWaJePDdppgFHGIp44OQ==` |

飞书签名向量（飞书文档无现成示例，按文档算法固定 timestamp/secret 生成）：`gen_sign("1599360473", "demo-secret") == "3/MaVZ8JLIy4TUG+7KSFJqvUkTKd+HWY8g+56DZWq8s="`

## Review Focus

1. **httpx 异常文本带 url**：`ConnectError`/`ReadTimeout` 的 `str(exc)` 可能包含完整 URL 或仅 path，而 path 末段就是 hook token。expected：url 全文和 token 末段都要脱敏。测试在 Task 3。
2. **飞书 HTTP 200 但业务失败**：签名错时返回 `{"code":19021,"msg":"sign match fail..."}`，老格式是 `{"StatusCode":0,...}`，也可能返回非 JSON。expected：以 `code`（缺省取 `StatusCode`）判定成功；非 JSON 判 `failed`，不抛异常。测试在 Task 3。
3. **兼容模式密钥长度错误**：老代码只 log error 然后按明文透传。expected：兼容模式同样透传并 warning；严格模式抛 `KeyMissingError`；两种情况都不缓存坏密钥。测试在 Task 1。
4. **兼容模式下有密钥、但库里是历史明文**：老库里可能有加密前写入的明文。expected：`decrypt` 抛 `DecryptError`（与老代码一样会失败，只是异常类型统一），调用方先用 `is_encrypted` 判断；异常文本不含该明文。测试在 Task 1。
5. **redact 输入为 None 或密钥列表含 None**：调用方常传 `[url, secret]`，其中 secret 可能是 None。expected：跳过 None 和空串，不抛异常。测试在 Task 2。

---

### Task 1: 工程骨架 + `uxh_common.crypto`

**Files:**
- Create: `pyproject.toml`、`.gitignore`（`.venv/ __pycache__/ *.egg-info/ .pytest_cache/`）、`uxh_common/__init__.py`、`uxh_common/crypto.py`、`uxh_common/notify/__init__.py`（空）
- Test: `tests/test_crypto.py`

**Interfaces:**
- Produces（spec §2.2 原样）：`CryptoError(Exception)`、`KeyMissingError(CryptoError)`、`DecryptError(CryptoError)`；`encrypt(plaintext: str, *, strict: bool = False, key: bytes | None = None) -> str`；`decrypt(token: str, *, strict: bool = False, key: bytes | None = None) -> str`；`is_encrypted(value: str) -> bool`；`generate_key() -> str`；测试用私有函数 `_reset_key_cache() -> None`。

- [ ] **Step 1: 仓库初始化**：`git init`（目录目前只有 `docs/`），写 pyproject（照 uxh-ai 的格式，name `uxh-common`）、`.gitignore`，建 venv 并 `pip install -e ".[dev]"`。确认：`.venv/bin/python -c "import uxh_common; print(uxh_common.__version__)"` 输出 `0.1.0`。

- [ ] **Step 2: 写失败测试 `tests/test_crypto.py`**（autouse fixture：`monkeypatch.delenv("DATA_ENCRYPTION_KEY", raising=False)` + `crypto._reset_key_cache()`）

```python
KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
KEY = base64.urlsafe_b64decode(KEY_B64)
LEGACY = [  # 上方向量表的 4 行
    ("uxh-common-compat", "xCmY9KYXXc1RkNkWbvgmSxafRGp6ufwwtJCaz0c3ugdKgCyR04k6Gl7F-Fmv"), ...]

@pytest.mark.parametrize("plain,token", LEGACY)
def test_decrypts_legacy_vectors(plain, token):
    assert crypto.decrypt(token, key=KEY) == plain
    assert crypto.decrypt(token, strict=True, key=KEY) == plain

def test_reads_key_from_env(monkeypatch):           # setenv KEY_B64；decrypt(LEGACY[0][1]) == 原文
def test_roundtrip_chinese_and_long():               # "中文"、"x"*10000；密文 != 明文，且 is_encrypted(密文)
def test_empty_string_passthrough():                 # encrypt("", strict=True, key=KEY) == "" ；decrypt("", key=KEY) == ""
def test_strict_without_key_raises():                # encrypt("a", strict=True) / decrypt(tok, strict=True) -> KeyMissingError
def test_strict_wrong_key_length_raises(monkeypatch):# env = urlsafe_b64encode(b"x"*16) -> KeyMissingError
def test_compat_without_key_passthrough_warns_once(caplog):
    assert crypto.encrypt("abc") == "abc"; assert crypto.decrypt("abc") == "abc"
    assert sum("DATA_ENCRYPTION_KEY" in r.message for r in caplog.records) == 1
def test_compat_wrong_key_length_passthrough(monkeypatch, caplog):  # Review Focus #3：透传 + warning，之后 setenv 正确 key 并 _reset 后能正常加密（未缓存坏 key）
def test_tampered_token_raises_without_leak():
    tok = crypto.encrypt("secret-plain", key=KEY); raw = bytearray(base64.urlsafe_b64decode(tok)); raw[-1] ^= 1
    bad = base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(crypto.DecryptError) as ei: crypto.decrypt(bad, key=KEY)
    assert str(ei.value) == "decrypt failed" and bad not in str(ei.value) and "secret-plain" not in str(ei.value)
def test_legacy_plaintext_in_db_raises_decrypt_error():  # Review Focus #4：decrypt("plain-api-key-123", key=KEY) -> DecryptError，异常文本不含原值
def test_is_encrypted_edges():  # "" -> False；"abc" -> False；"密码" -> False；LEGACY[0][1] -> True
def test_generate_key():        # len(urlsafe_b64decode(generate_key())) == 32，且可作 key 往返
```

- [ ] **Step 3: 跑测试确认失败**：`.venv/bin/python -m pytest tests/test_crypto.py -q`，预期 ImportError / AttributeError。

- [ ] **Step 4: 实现 `uxh_common/crypto.py`**
  - 密钥解析 `_resolve_key(key, strict) -> bytes | None`：`key` 参数优先（长度不为 32 时同样按 strict 规则处理）。否则读 env，只缓存合法密钥。缺失时只 warning 一次（模块级标志，`_reset_key_cache` 一并清掉）；长度错或 base64 错时，strict 抛 `KeyMissingError`，compat 打 warning 后返回 None。异常和日志里都不带 env 值。
  - `encrypt`/`decrypt`：空串直接返回 `""`，在解析密钥之前判断，与老代码一致。拿不到密钥时原样返回（只有 compat 会走到这里）。`decrypt` 把 `binascii.Error`、`ValueError`、`cryptography.exceptions.InvalidTag`、`UnicodeDecodeError` 统一改抛 `DecryptError("decrypt failed")`，并 `from None` 切断异常链，避免原异常带出密文。
  - `is_encrypted` 逐字照搬老实现的语义：`urlsafe_b64decode(value.encode("ascii"))`，长度 ≥ 28 返回 True，异常返回 False。
  - `generate_key`：`urlsafe_b64encode(os.urandom(32)).decode()`。

- [ ] **Step 5: 跑测试确认通过**：`.venv/bin/python -m pytest tests/test_crypto.py -q`，全部 PASS。

- [ ] **Step 6: Commit**：`git add -A && git commit -m "feat(crypto): AES-256-GCM compatible with legacy encryption.py, strict mode"`

### Task 2: `uxh_common.secrets`

**Files:**
- Create: `uxh_common/secrets.py`
- Test: `tests/test_secrets.py`

**Interfaces:**
- Produces：`MASK: str = "***"`；`mask(value: str | None) -> str`；`is_masked(value: str | None) -> bool`；`merge_secret(incoming: str | None, stored: str) -> str`；`redact(text: str, secrets: list[str | None]) -> str`

- [ ] **Step 1: 写失败测试**

```python
def test_mask():          # mask("abc") == "***"；mask("") == ""；mask(None) == ""
def test_is_masked():     # "***" -> True；"" / None / "****" -> False
@pytest.mark.parametrize("incoming,expected", [(None, "old"), ("", "old"), ("***", "old"), ("new", "new")])
def test_merge_secret(incoming, expected): assert merge_secret(incoming, "old") == expected
def test_redact_multiple():   # redact("u=AAA p=BBB", ["AAA", "BBB"]) == "u=*** p=***"
def test_redact_nested():     # redact("tok=abcdef", ["abc", "abcdef"]) == "tok=***"（长的先替换）
def test_redact_empty_and_none():  # redact("x", []) == "x"；redact("x", [None, ""]) == "x"（Review Focus #5）
```

- [ ] **Step 2: 跑测试确认失败**：`.venv/bin/python -m pytest tests/test_secrets.py -q`，预期失败。
- [ ] **Step 3: 实现**：`redact` 先过滤掉假值，再按长度倒序逐个 `str.replace` 成 `MASK`。
- [ ] **Step 4: 跑测试确认通过**：`.venv/bin/python -m pytest -q`，全部 PASS。
- [ ] **Step 5: Commit**：`git commit -am "feat(secrets): mask, merge_secret, redact"`（新文件先 `git add`）

### Task 3: `uxh_common.notify.feishu`

**Files:**
- Create: `uxh_common/notify/feishu.py`
- Test: `tests/test_feishu.py`

**Interfaces:**
- Consumes：`uxh_common.secrets.redact`
- Produces：
  - `gen_sign(timestamp: str, secret: str) -> str`（模块级函数，便于固定向量测试）
  - `SendResult`（dataclass：`status: Literal["sent","suppressed","failed"]`、`code: int | None = None`、`message: str = ""`）
  - `FeishuWebhook(url: str, *, secret: str | None = None, gate: Callable[[], bool] | None = None, timeout: float = 10.0, transport: httpx.BaseTransport | None = None)`，方法有 `send_text(text: str) -> SendResult` 和 `send_card(card: dict) -> SendResult`。`transport` 是在 spec 签名之外新增的 keyword 参数，只给测试注入 `MockTransport` 用。

- [ ] **Step 1: 写失败测试**：用 `httpx.MockTransport(handler)` 捕获请求；`URL = "https://open.feishu.cn/open-apis/bot/v2/hook/tok-abc123"`，`SECRET = "sec-xyz"`。

```python
def test_gen_sign_vector(): assert gen_sign("1599360473", "demo-secret") == "3/MaVZ8JLIy4TUG+7KSFJqvUkTKd+HWY8g+56DZWq8s="
def test_text_payload():    # body == {"msg_type": "text", "content": {"text": "hi"}}；无 timestamp/sign；result == SendResult("sent", 0, "")
def test_card_payload():    # body["msg_type"] == "interactive" and body["card"] == card
def test_signed_payload():  # body["timestamp"] 是纯数字字符串，且 body["sign"] == gen_sign(body["timestamp"], SECRET)
def test_gate_closed_no_request():  # gate=lambda: False -> status "suppressed"，handler 调用次数 0
@pytest.mark.parametrize("resp", [
    httpx.Response(200, json={"code": 19021, "msg": "sign match fail or timestamp is not within one hour"}),
    httpx.Response(500, text="err"),
    httpx.Response(200, text="<html>"),            # 非 JSON（Review Focus #2）
])
def test_failed_responses(resp):   # status == "failed"，不抛异常；第一个 case 的 code == 19021
def test_legacy_statuscode_success():  # 200 {"StatusCode": 0, "StatusMessage": "success"} -> "sent"
@pytest.mark.parametrize("exc", [httpx.ReadTimeout, httpx.ConnectError])
def test_network_error_redacted(exc, caplog):
    # handler 抛出 exc(f"boom {URL} /open-apis/bot/v2/hook/tok-abc123")；Review Focus #1
    r = hook.send_text("hi"); assert r.status == "failed"
    blob = r.message + caplog.text
    assert URL not in blob and "tok-abc123" not in blob and SECRET not in blob
def test_never_logs_payload(caplog):  # 发送成功后用 caplog.set_level(DEBUG)，确认 caplog.text 中不含 "hi"、URL、SECRET
```

- [ ] **Step 2: 跑测试确认失败**：`.venv/bin/python -m pytest tests/test_feishu.py -q`，预期失败。
- [ ] **Step 3: 实现**
  - `gen_sign`：`base64.b64encode(hmac.new(f"{timestamp}\n{secret}".encode(), b"", hashlib.sha256).digest()).decode()`。
  - `_send(payload)`：先检查 gate。带 secret 时加入 `timestamp=str(int(time.time()))` 和 `sign`。用 `httpx.Client(timeout=..., transport=...)` POST json。
    - 2xx 时解析 JSON，`code = body.get("code", body.get("StatusCode"))`；`code == 0` 判 `sent`，否则判 `failed`，message 取 `body.get("msg")`。
    - 捕获 `httpx.HTTPError`、`ValueError`，以及最外层兜底的 `Exception`，一律返回 `failed`。
    - message 统一经 `redact(..., [url, secret, url.rstrip("/").rsplit("/", 1)[-1]])` 处理。
  - 日志只写 `status=%s code=%s`。

- [ ] **Step 4: 跑测试确认通过**：`.venv/bin/python -m pytest -q`，全部 PASS。
- [ ] **Step 5: Commit**：`git add -A && git commit -m "feat(notify): Feishu webhook with sign, gate, redacted failures"`

### Task 4: README + 发布 v0.1.0

**Files:**
- Create: `README.md`（风格同 uxh-ai README：安装一行，三个模块的用法片段取自 PRD §4，加一节「已固化的坑」：兼容模式只给老项目用；有密钥时 decrypt 历史明文会抛错，先用 is_encrypted 判断；飞书 HTTP 200 不代表成功；async 调用方用 `asyncio.to_thread`）

- [ ] **Step 1: 写 README**。
- [ ] **Step 2: 全量验证**：`.venv/bin/python -m pytest -q` 全绿；密钥日志自检 `grep -rnE 'logger\.|print\(' uxh_common | grep -iE 'password|secret|key|token|url'`，命中行只能是不带值的固定文案。
- [ ] **Step 3: 安装验证**：在 scratchpad 新建 venv，跑 `pip install /Users/Shared/AIGC/AICoding/uxh-common`，然后执行 PRD §4 的示例代码。webhook 指向 MockTransport，或者 gate=False，**不发真实群**。
- [ ] **Step 4: Commit**：`git add README.md && git commit -m "docs: README"`，然后 `git tag v0.1.0`。
- [ ] **Step 5: 推送（⚠️ 需用户明确授权后执行）**：`gh repo create zgfeng115/uxh-common --private --source . --push`，再 `git push origin v0.1.0`。验证：`pip install "uxh-common @ git+https://github.com/zgfeng115/uxh-common.git@v0.1.0"` 在本机能装上。

---

## 交接给 deployer 计划的事项（不在本计划执行）

2026-10-19 已对服务器 `/opt/yundocker-deployer` 做了只读比对：服务器上没有 git，代码副本放在本会话 scratchpad 的 `server-deployer/`。比对结果：

- 本地 6 个未提交改动里，`api/clients.py`、`client_manager.py`、`config.py`、`docker_client.py`、`Upgrade.tsx` 和服务器一致，说明已经部署。
- `backend/version_manager.py` 服务器版（05-18）比本地版（05-14）新：改按 `VersionNotify.id` 排序，去掉了 DeployLog 补充逻辑，旧条目交给 `scripts/prune-ccr-versions.sh` 清理（root crontab 每天 04:00 跑）。**以服务器版为基线**，并把 prune 脚本纳入仓库。
- 服务器的 `backend/Dockerfile` 改成 COPY 本地的 `docker-compose-linux-x86_64`（63MB），不再用 curl。不要把这个二进制提交进 git，到 deployer 计划里再决定做法。
- 服务器独有的 `Dockerfile`（根目录）和 `backend/upgrades.py`（04-30 旧副本）是残留文件，不纳入仓库。`docker-compose.override.yml` 是服务器配置，同样不纳入。
- 本地独有：`scripts/backfill-worker-api-key.sh`、`scripts/fix-client-permissions.sh`、`tasks/lessons.md`。
