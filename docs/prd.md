# PRD：uxh-common —— 各项目共用的基础设施包

- 日期：2026-10-14
- 技术规格：`docs/spec.md`
- 参照：`/Users/Shared/AIGC/AICoding/uxh-ai`（LLM 调用策略层，也是用 pip 从 git 安装的共享包）

## 1. 背景

几个项目里有同一批基础代码，各自复制、各自维护：

| 能力 | 现状 |
|---|---|
| 敏感字段加密 | `uxh-ops-system/backend/db/encryption.py` 与 `xhs_autogen_byzgf/shared/encryption.py` 几乎完全一样，都是 AES-256-GCM，密钥取 `DATA_ENCRYPTION_KEY` |
| 密钥打码显示 | uxh-ops `api/settings.py::_mask`，只回 `***` |
| 飞书 webhook 发送 | uxh-ops `services/feishu_client.py`，外发总闸是 `notifier.outbound_enabled()`（读 `NOTIFY_ENABLED`） |

yundocker-deployer 马上要做「PG 定时备份」，需要加密存储 NAS 密码和飞书 webhook、打码显示、发送飞书通知。如果再复制一遍，就是第三份。复制的代码会慢慢走样，修了一处漏修另一处是迟早的事。

## 2. 目标

1. 抽出一个**无状态、不依赖数据库**的公共包 `uxh-common`，提供加密、密钥处理、飞书通知三类能力。
2. **和现有加密数据完全兼容**：老项目以后迁过来，库里已有的密文不需要重新加密。
3. yundocker-deployer 是第一个使用方。uxh-ops-system 和 xhs_autogen 暂时不动，以后单独迁移（做法同 ai-core-ts：先建公共包，老项目择期迁移）。

## 3. 范围

### 本期做
- `crypto`：加密、解密、判断是否已加密；分「兼容模式」和「严格模式」。
- `secrets`：打码、识别打码值、保存时「打码或空值就保留原值」、日志脱敏。
- `notify.feishu`：飞书自定义机器人 webhook，支持文本和卡片、签名校验、外发总闸、不泄露 webhook。

### 不做
- 配置存储。各项目的库和表不同，由各项目自己实现，只调用本包做加解密。
- LLM 相关，已在 uxh-ai。
- 企业微信、邮件等其他通道，以后需要再加。
- 本期不改 uxh-ops-system 和 xhs_autogen 的代码。

## 4. 使用方式

```bash
pip install "uxh-common @ git+https://github.com/zgfeng115/uxh-common.git@v0.1.0"
```

```python
from uxh_common import crypto, secrets
from uxh_common.notify.feishu import FeishuWebhook

token = crypto.encrypt("nas-password", strict=True)       # 存库
plain = crypto.decrypt(token, strict=True)                 # 用时解密
api_value = secrets.mask(stored)                           # 接口返回 "***"
to_store = secrets.merge_secret(incoming, stored)          # PUT 时打码或空值保留原值

hook = FeishuWebhook(url, secret=sign_secret, gate=lambda: True)
result = hook.send_text("【备份失败】txyun / uxh-ops：pg_dumpall 退出码 1")
```

## 5. 验收标准

1. 用现有两份 `encryption.py` 加密的密文，`uxh_common.crypto.decrypt` 都能解出原文。测试里固定使用规格中记录的兼容向量。
2. 严格模式下没有密钥、或者密钥长度不对时，直接抛错，不会悄悄退回明文。
3. 飞书签名结果和飞书官方算法一致，测试里有固定向量。
4. 任何异常信息和日志里，都不出现 webhook 地址、签名密钥、明文或密文。
5. 发布 v0.1.0 的 git tag。yundocker-deployer 用 `pip install` 能装上并正常使用。
