# 个人信息管理系统（Cloudflare 版）

单管理员的个人信息管理系统，由原 PHP + SQLite 版本移植到 **Cloudflare Workers + D1**（会话层预留 KV 适配）。两个并列模块：

- **账号提示**：管理「网站 / 账号 / 密码提示」。系统只保存手写的密码提示，绝不保存完整密码，界面里也没有任何要求输入完整密码的入口。每次改提示会自动保留上一次、上上次的历史。
- **私密信息**：保存身份证号、社保号、银行卡号等零散信息。备注用 AES-256-GCM 加密保存，密钥由主密码派生包装，服务器数据库里看不到明文。

## PHP 版（在 Releases 里）

本仓库是 Cloudflare Workers 版。原版的 **PHP + SQLite 实现**打包放在 [Releases](https://github.com/tyrains/infosys/releases) 里（`infosys-php-v1.1.0.zip`），功能与本版一致：要求 PHP 8.1+（启用 `pdo_sqlite`、`openssl`），**解压后在 PHP 环境下可直接运行**——放进任意 PHP 站点目录即可，或在解压目录执行 `php -S localhost:8000` 用浏览器打开。数据存本地 `data/` 下的 SQLite 文件，包内不含数据库，首次打开自动建库，默认密码同为 `123`。有自己的 PHP 主机、不想用 Cloudflare 的，选这个包。

## 首次登录

- **默认密码：`123`** —— 首次打开自动建库初始化。登录后顶部会出现醒目提示条，请尽快到「设置」页修改密码（新密码至少 6 位、不能是 `123`；改完会退出登录，用新密码重新登录）。默认密码下禁止新增/修改私密信息（可查看）。

> ⚠️ **主密码一旦忘记，私密信息无法找回**，没有找回途径，也不会生成恢复码。

## 架构

| 部分 | 实现 |
| --- | --- |
| 程序 | 单个 Worker（`src/worker.js`），服务端渲染页面，行为与原 PHP 版一致 |
| 数据 | D1 数据库 `infosys-db`：`settings` / `entries` / `hint_history` / `vault_items` 四张表（原两个 SQLite 文件合并为一个 D1 库） |
| 会话 | D1 的 `sessions` 表：登录态、CSRF token、闪现消息、私密信息数据密钥（DK）只存在会话里，退出即清除。会话层已预留 KV 适配——日后建好 KV 命名空间并在 `wrangler.toml` 打开 `SESSIONS` 绑定即自动切换（当前部署账号的 API 令牌无 KV 权限，故先用 D1） |
| 样式 | `src/style.css`（原版样式，两套主题：普通 / Claude） |

## 安全说明

- 主密码以 PBKDF2-SHA256（10 万次迭代，Workers 的 WebCrypto 上限）哈希存储；私密信息数据密钥 DK 由主密码经 PBKDF2-SHA256（10 万次）派生密钥包装，改密码只重新包装 DK，备注密文不动。
- 备注密文格式 `base64(nonce12 + tag16 + 密文)`，与原 PHP 版一致。
- 所有 SQL 走参数绑定；所有输出经 HTML 转义；所有 POST 带 CSRF token 校验。
- 会话 cookie：HttpOnly + Secure + SameSite=Strict；登录后页面响应带 `Cache-Control: no-store`；全站 `noindex,nofollow`。
- 登录失败逐次延迟 1 秒起、最多 5 秒。
- 备份导出为 JSON 明文（含密码提示与私密信息备注明文），请妥善保管、导入后删除；导入支持追加 / 覆盖两种模式，文件格式与原 PHP 版兼容。

与原 PHP 版的差异：DK 包装只使用 PBKDF2（Workers 的 WebCrypto 不支持 Argon2id；原 PHP 版在没有 sodium 时也是走 PBKDF2 回退，格式兼容）。本仓库部署的是空库，不含原本地版的任何条目数据。

## 本地开发 / 重新部署

需要 Node.js 与 wrangler（`npm i -g wrangler`），并登录有权限的 Cloudflare 账号。

```bash
# 1. 建 D1（已建过可跳过），把输出的 id 填回 wrangler.toml 的绑定里
wrangler d1 create infosys-db
# 可选：wrangler kv namespace create infosys-sessions，再打开 wrangler.toml 里的 SESSIONS 绑定

# 2. 部署
wrangler deploy

# 3. 打开部署得到的 workers.dev 地址（或你绑定的自定义域名），用默认密码 123 登录并立即改密
```

数据库无需手动初始化：Worker 首次请求会自动建表并写入默认设置（见 `schema.sql`，内容与代码内初始化一致）。

## 文件结构

```
src/worker.js    Worker 全部逻辑：路由、页面渲染、数据访问、加解密、会话
src/style.css    原版样式（两套主题变量）
schema.sql       D1 建表 SQL（与代码内自动初始化一致，备查/手动初始化用）
wrangler.toml    部署配置（Worker 名、D1 / KV 绑定）
README.md        本说明
```
