-- 个人信息管理系统 · D1 建表 SQL
-- 说明：Worker 首次运行时会自动执行同样的建表与默认设置初始化，
-- 本文件仅供手动初始化 / 排查时使用（wrangler d1 execute infosys-db --file schema.sql）。

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  site        TEXT NOT NULL,
  url         TEXT NOT NULL DEFAULT '',
  category    TEXT NOT NULL DEFAULT '',
  account     TEXT NOT NULL DEFAULT '',
  hint        TEXT NOT NULL DEFAULT '',
  hint_set_at TEXT NOT NULL DEFAULT '',
  note        TEXT NOT NULL DEFAULT '',
  updated_at  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hint_history (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL,
  hint     TEXT NOT NULL,
  set_at   TEXT NOT NULL,
  FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_history_entry ON hint_history(entry_id, id);

CREATE TABLE IF NOT EXISTS vault_items (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  note_enc   TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT ''
);

-- 会话表（绑定 KV 命名空间 SESSIONS 时不使用此表，会话自动改走 KV）
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- 默认设置（master_hash 由 Worker 首次运行时写入，值为密码 123 的 PBKDF2 哈希，不在此写死）
INSERT OR IGNORE INTO settings (key, value) VALUES ('theme', 'normal');
INSERT OR IGNORE INTO settings (key, value) VALUES ('is_default_pw', '1');
INSERT OR IGNORE INTO settings (key, value) VALUES ('page_size', '20');
INSERT OR IGNORE INTO settings (key, value) VALUES ('site_name', '个人信息管理系统');
