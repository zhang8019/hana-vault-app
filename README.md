# 凭证保险库 · Hana App

一个加密凭证保险库：以主密码派生密钥、AES-256-GCM 认证加密落盘，保存网站登录、SSH、API Key、OAuth 令牌与 TOTP 密钥；既能被 Agent 在对话里检索调用，也带一个整页图形管理界面。

**完全开源**，MIT 许可。

## 改造来源

本 App 是 **DSH 插件 `dsh-vault` 的 Hana 迁移与改造版**。

- 上游项目：`dsh-vault`（作者 Ox0400，MIT 许可）——加密内核的直接来源。
- 本 App 复用了上游的加密内核（`lib/vault-core.js`），在原样保留 AES-256-GCM + scrypt、库文件格式与条目结构的前提下，把它移植到 Hana 的 v2 App 运行时上，并重写了服务层、工具集与管理界面。
- 因此 **v1 时代的库文件可被本 App 直接读取**，迁移只需复制文件，无需重新加密。
- 上游 MIT 许可与第三方组件声明随包携带（见 `ui/assets/THIRD_PARTY_NOTICES.txt` 与 `LICENSE`）。

## 功能

- **密钥不进对话**：检索只返回摘要（标题 / 账号 / 主机 / 标签），永不返回口令、密钥、令牌。
- **落盘即加密**：磁盘上只有密文，GCM 校验标签能识别错误主密码与篡改。
- **可管理**：整页界面里检索、新增、编辑、删除、回收站、TOTP、生成口令、安全体检、近期审计、加密备份导出。
- **可选免密**：开启「本机自动解锁（记住这台设备）」后，本机下次启动自动解锁，不必再输主密码（凭据以本机绑定的密钥封装于本机）。
- **按 Agent 授权**：Agent 读写凭证需逐次确认，也可按 Agent / 凭证 / 动作 / 字段长期授权；面板顶部的「授权管理」集中展示当前生效的长期授权，可逐条或整个 Agent 一键撤销。
- **脚本可用**：带 `env` 标签的条目可渲染成 `KEY=VALUE` 交给脚本，明文不必进入模型上下文。

## 安全设计

| 环节 | 做法 |
|---|---|
| 密钥派生 | `scrypt(主密码, 每库随机盐)` → 256 位密钥，参数随密文持久化以便日后升级 |
| 加密 | AES-256-GCM，每条记录独立随机 nonce，杜绝 IV 复用 |
| 校验 | 固定明文的校验信封，错误主密码立即失败，绝不返回乱码 |
| 落盘 | 原子替换 + 跨进程文件锁；文件权限 0600、目录 0700 |
| 检索 | 列表摘要不含密钥字段；健康体检报告按白名单投影，不包含复用凭证的明文值 |
| 主密码 | **只存在于 App 进程内存**；不提供任何"保存主密码"的入口 |
| 本机自动解锁 | 可选、默认关闭。开启时用 `scrypt` 自行派生的密钥（非主密码）经 AES-256-GCM 封装后落在本机，并用库文件指纹（SHA-256）绑定；库文件被替换或修改即失效并清除。同一 Windows 账户下的其他程序理论上可读取该凭据——这是**基于"本机同一用户"信任模型的取舍**，仓库默认不开 |
| 自动锁定 | 闭包空闲超时自动锁定，离开页面尽力锁定；手动锁定会抑制自动解锁，空闲/关机不抑制 |
| 暴力破解 | 连续解锁失败递增延迟 |
| Agent 工具 | 每次调用绑定宿主注入的 sessionPath/callToken，并从宿主 session 查询 Agent；身份缺失时拒绝。读取/写入用卡片逐次确认，也可按 Agent、凭证、动作与字段长期授权；长期授权对"整库只读元数据"（列表/检索/统计/风险分析）单独放行，对导出、导入、删除、彻底删除等大范围动作仍仅限单次。所有长期授权可在面板「授权管理」查看与撤销 |
| 写入策略 | `readonly` 拒绝任何写入；Agent 工具不能把模式改为 `auto` 或切换目标库。面板直接操作由用户发起；彻底删除还需显式二次确认 |
| 审计 | 独立无密钥审计日志（unlock / lock / add / update / trash / restore / purge / import），从不记录口令 |

> 与同类实现的差别：有些插件把主密码本身存进配置文件以支持"重启自动解锁"，代价是主密码以明文落盘。本 App 从不保存主密码；若要免密，只把**本机绑定的派生密钥**封装落盘（见上表）。

## 数据位置

`<HANA_HOME>/app-data/hana-vault/vaults/<库名>.json`（默认库名为 `default`）。

若从 v1 插件迁移，把 `plugin-data/hana-vault/vaults/*.json` 复制到上述目录即可；库文件格式不变。

## 权限说明

| 能力词 | 用途 |
|---|---|
| `app/tools.expose-to-model` | 让模型可以调用本 App 的 21 个工具 |
| `app/sessions.read` | 查询宿主注入会话的 Agent 身份以执行按 Agent 授权；不读取对话历史 |
| `sdk.userInteraction.ask` | 使用宿主已有确认卡片请求单次或长期授权；不需要自定义 input panel 能力 |
| `app/ui.clipboard-write` | 界面上的「复制」按钮 |
| `app/resources.write` | 加密备份经宿主另存为文件 |

本 App **不请求任何出站网络能力**（无 `network` 声明），不会联网。

## 工具清单

`vault_status` `vault_unlock` `vault_lock` `vault_list` `vault_search` `vault_get` `vault_add` `vault_update` `vault_delete` `vault_restore` `vault_purge` `vault_totp` `vault_generate_password` `vault_health` `vault_watchtower` `vault_stats` `vault_strength` `vault_config` `vault_export` `vault_import` `vault_audit`

## 许可

MIT（见 `LICENSE`）。加密内核来自 `dsh-vault`（MIT，© Ox0400），其许可与声明一并保留。
