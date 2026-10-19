# 技术规格：uxh-common v0.1.0

- PRD：`docs/prd.md`
- 仓库：`/Users/Shared/AIGC/AICoding/uxh-common`，推送到 GitHub 私有仓 `zgfeng115/uxh-common`，版本 tag `v0.1.0`
- 工程结构参照 `/Users/Shared/AIGC/AICoding/uxh-ai`，包括 pyproject、包布局和 tests 目录

## 1. 工程

```
uxh-common/
  pyproject.toml          # name="uxh-common"，requires-python=">=3.11"
                          # 依赖：cryptography>=42, httpx>=0.27；dev 依赖：pytest
  README.md               # 用法、模块清单、已固化的坑（风格同 uxh-ai）
  uxh_common/
    __init__.py           # __version__ = "0.1.0"
    crypto.py
    secrets.py
    notify/
      __init__.py
      feishu.py
  tests/
    test_crypto.py
    test_secrets.py
    test_feishu.py
```

开发命令：

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

## 2. `uxh_common.crypto`

### 2.1 与现有实现的兼容（硬约束）

现有两份实现完全相同，算法定义如下：

- 密钥：环境变量 `DATA_ENCRYPTION_KEY`，`base64.urlsafe_b64decode` 解码后必须是 **32 字节**。
- 加密：AES-256-GCM，随机 12 字节 nonce，不用附加数据（AAD 为 None）。
- 密文：`base64.urlsafe_b64encode(nonce(12) + ciphertext_with_tag)`，转成 ascii 字符串。
- 空串直接返回空串。
- `is_encrypted(v)`：能按 urlsafe base64 解码，并且解码后长度不小于 28，就判为已加密。

### 2.2 接口

```python
class CryptoError(Exception): ...
class KeyMissingError(CryptoError): ...
class DecryptError(CryptoError): ...      # 错误信息不含密文或明文，只写 "decrypt failed"

def encrypt(plaintext: str, *, strict: bool = False, key: bytes | None = None) -> str
def decrypt(token: str, *, strict: bool = False, key: bytes | None = None) -> str
def is_encrypted(value: str) -> bool
def generate_key() -> str                 # 返回可直接写进 DATA_ENCRYPTION_KEY 的 urlsafe base64 字符串
```

- `key` 参数主要给测试用，也方便调用方自己管理密钥。不传时读环境变量，读到后缓存在进程内。
- **兼容模式**（`strict=False`，默认）：行为和现有实现一致。没有密钥时加密、解密都原样返回，并且只在第一次打一条 warning。这个模式只给老项目迁移用。
- **严格模式**（`strict=True`）：没有密钥或密钥不合法时抛 `KeyMissingError`，不回退到明文。**新项目一律用这个模式。**
- 解密时 base64 不合法或 GCM 校验失败，都抛 `DecryptError`，日志里不打出入参。

### 2.3 兼容向量（实现前先生成，写进测试）

1. 固定一个测试密钥，例如 `base64.urlsafe_b64encode(bytes(range(32)))`。
2. 用**现有的** `uxh-ops-system/backend/db/encryption.py`，设置环境变量 `DATA_ENCRYPTION_KEY=<上面的值>`，对 `"uxh-common-compat"` 和 `"中文密码!@#"` 各加密一次，把输出的密文记下来。这些密文是向量，nonce 是随机的，所以只用来校验能否解密。
3. `test_crypto.py::test_decrypts_legacy_vectors`：`decrypt(向量, key=测试密钥)` 必须等于原文。
4. 再对 xhs_autogen 的 `shared/encryption.py` 做同样的事，生成一组向量。

### 2.4 测试
- 加密后再解密能还原，包括中文和长文本。
- 现有两份实现产出的兼容向量都能解开。
- 严格模式下没有密钥、或者密钥长度不是 32，都抛 `KeyMissingError`。
- 兼容模式下没有密钥时原样返回，warning 只打一次。
- 篡改一个字节后解密抛 `DecryptError`，并且异常文本里不含密文或明文。
- `is_encrypted` 的边界：空串、短串、非 base64 字符串。

## 3. `uxh_common.secrets`

```python
MASK = "***"

def mask(value: str | None) -> str          # 有值返回 "***"，无值或 None 返回 ""（同 uxh-ops _mask）
def is_masked(value: str | None) -> bool    # value == "***"
def merge_secret(incoming: str | None, stored: str) -> str
    # incoming 是 None、""、"***" 时返回 stored（PUT 时没改这个字段），否则返回 incoming
def redact(text: str, secrets: list[str]) -> str
    # 把 text 中出现的每个非空密钥替换为 "***"，从长到短替换，避免短串替换后长串匹配不上
```

测试：
- `mask` 和 `merge_secret` 的各种组合；
- `redact` 能处理多个密钥、包含关系的密钥、空密钥列表。

## 4. `uxh_common.notify.feishu`

```python
@dataclass
class SendResult:
    status: Literal["sent", "suppressed", "failed"]
    code: int | None = None        # 飞书返回的 code；0 表示成功
    message: str = ""              # 已脱敏，不含 url 和 secret

class FeishuWebhook:
    def __init__(self, url: str, *, secret: str | None = None,
                 gate: Callable[[], bool] | None = None, timeout: float = 10.0): ...
    def send_text(self, text: str) -> SendResult
    def send_card(self, card: dict) -> SendResult      # msg_type="interactive"
```

- **报文**：
  - 文本：`{"msg_type": "text", "content": {"text": text}}`；
  - 卡片：`{"msg_type": "interactive", "card": card}`。
- **签名**：给了 `secret` 时，报文里加上 `timestamp`（秒级字符串）和 `sign`。算法按飞书自定义机器人文档：
  - `string_to_sign = f"{timestamp}\n{secret}"`；
  - `sign = base64(hmac_sha256(key=string_to_sign, msg=b""))`。
  - 测试用飞书文档里的示例做固定向量；如果文档没有示例，就固定 timestamp 和 secret，写出预期值。
- **总闸**：`gate` 不为 None 且返回 False 时，不发请求，返回 `suppressed`。对应 uxh-ops 的 `NOTIFY_ENABLED`：本地开发库常带着生产配置，不加闸就会往真实群里发消息。
- **失败处理**：网络错误、HTTP 状态不是 2xx、返回体里 `code != 0`，都返回 `failed`，**不抛异常**，因为通知失败不应该拖垮调用方的主流程。`message` 要先经过 `redact`，去掉 url 和 secret。
- **日志**：用 `logging.getLogger("uxh_common.notify.feishu")`，只记 status 和 code，**永不记 url、secret 或报文全文**。
- **HTTP**：用 `httpx.Client(timeout=timeout)`，同步调用。异步调用方用 `asyncio.to_thread` 包一层，本期不提供 async 版。

测试用 `httpx.MockTransport` 打桩，覆盖：
- 文本和卡片的报文形状；
- 带签名时有 timestamp 和 sign 字段；
- 签名向量；
- 总闸关闭时返回 `suppressed`，并且没有发出请求；
- 返回 `code != 0`、HTTP 500、超时都返回 `failed`；
- 在 caplog 和 `SendResult.message` 里搜索 url 和 secret，确认没有出现。

## 5. 发布

1. 测试全部通过，README 写完。
2. `git tag v0.1.0`，推送到 `zgfeng115/uxh-common`（私有仓）。
3. 使用方的 `requirements.txt` 里写 `uxh-common @ git+https://github.com/zgfeng115/uxh-common.git@v0.1.0`。
   - 构建镜像时如果拉不到私有仓，有两个办法：参照 uxh-ai 的现有做法；或者在镜像构建时用 build secret 传入 token。规格不规定具体做法，以使用方仓库现有的方式为准。

## 6. 老项目迁移指引（本期只写，不做）

uxh-ops-system 和 xhs_autogen 迁移时：

1. `requirements.txt` 加入 uxh-common。
2. 保留原来的 `encryption.py` 文件，但把内容改成转调公共包：

   ```python
   from uxh_common.crypto import encrypt, decrypt, is_encrypted
   ```

   这样原有的 import 不用改。
3. **上线前在云端只读核对**：从生产库取 10 条已加密的字段，用新实现解密，确认全部成功，再换镜像。
4. 打码和飞书发送这两块，各项目按自己的节奏替换，不强求一次做完。
