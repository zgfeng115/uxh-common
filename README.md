# uxh-common

各项目共用的基础设施包：敏感字段加密、密钥打码/脱敏、飞书 webhook / 应用机器人发送。无状态，不碰数据库，
配置存储由各项目自己实现，只调用本包做加解密。

```bash
pip install "uxh-common @ git+https://github.com/zgfeng115/uxh-common.git@v0.2.0"
```

## 用法

```python
from uxh_common import crypto, secrets
from uxh_common.notify.feishu import FeishuApp, FeishuWebhook

token = crypto.encrypt("nas-password", strict=True)       # 存库
plain = crypto.decrypt(token, strict=True)                 # 用时解密
api_value = secrets.mask(stored)                           # 接口返回 "***"
to_store = secrets.merge_secret(incoming, stored)          # PUT 时打码或空值保留原值
safe = secrets.redact(error_text, [password, webhook])     # 写日志/错误前脱敏

hook = FeishuWebhook(url, secret=sign_secret, gate=lambda: settings.notify_enabled)
result = hook.send_text("【备份失败】txyun / uxh-ops：pg_dumpall 退出码 1")
if result.status == "failed":
    ...                                                    # 不抛异常，自行决定是否告警

app = FeishuApp(app_id, app_secret, gate=...)              # 应用机器人：按 chat_id 发群消息
app.send_text(chat_id, "...")                              # 同样不抛异常，返回 SendResult
chats = app.list_chats()                                   # 机器人所在的群；失败抛 FeishuError（已脱敏）
```

生成密钥：`python -c "from uxh_common.crypto import generate_key; print(generate_key())"`，写入
`DATA_ENCRYPTION_KEY`，并另存一份到安全位置——丢了库里的密文就解不开。

## 模块

| 模块 | 内容 |
|---|---|
| `crypto` | `encrypt` / `decrypt` / `is_encrypted` / `generate_key`；`KeyMissingError`、`DecryptError` |
| `secrets` | `MASK`、`mask`、`is_masked`、`merge_secret`、`redact` |
| `notify.feishu` | `FeishuWebhook.send_text` / `send_card`、`FeishuApp.send_text` / `send_card` / `list_chats`、`SendResult`、`FeishuError`、`gen_sign` |

## 已固化的坑

- **加密与老项目逐字节兼容**：AES-256-GCM，`urlsafe_b64(nonce12 + ciphertext+tag)`，与
  uxh-ops `backend/db/encryption.py`、xhs_autogen `shared/encryption.py` 的密文互通，测试里有固定向量。
- **兼容模式只给老项目迁移用**：`strict=False`（默认）没有密钥时按明文透传，和老代码一样。
  新项目一律 `strict=True`，没密钥或密钥不是 32 字节直接抛 `KeyMissingError`。启动时用
  `crypto.encrypt("probe", strict=True)` 自检即可做到「缺密钥就启动失败」。
- **有密钥时 decrypt 历史明文会抛 `DecryptError`**：库里可能还有加密前写入的明文，先用
  `is_encrypted` 判断。异常文本固定为 `decrypt failed`，不带密文或明文。
- **飞书 HTTP 200 不代表成功**：签名错、关键词不匹配都返回 200 + `code != 0`，本包按 `code`
  （老格式 `StatusCode`）判定。
- **webhook 地址就是凭证**：地址末段 token 能直接往群里发消息。`SendResult.message` 和日志都会去掉
  url、token、secret；httpx 自带的请求日志（INFO 级别会打完整 URL）也加了过滤。
- **总闸 `gate`**：本地开发库常带着生产配置，不加闸就会往真实群里发。返回 False 时不发请求，结果为 `suppressed`。
- **应用机器人的 token 自动管理**：`tenant_access_token` 按实例缓存，过期前 5 分钟刷新；返回 token 失效
  （99991661 / 99991663）时刷新一次重试。app_secret 和 token 同样不进结果和 httpx 日志。机器人要先被拉进目标群。
- **只有同步版**：异步调用方用 `await asyncio.to_thread(hook.send_text, text)`。

## 开发

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

老项目迁移步骤见 `docs/spec.md` 第 6 节（本期不做）。
