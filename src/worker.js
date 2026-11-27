// 个人信息管理系统 · Cloudflare Workers + D1 + KV 版
// 由原 PHP + SQLite 版本移植：账号提示（只存提示不存完整密码）+ 私密信息（AES-256-GCM 加密备注）
// 数据与会话存 D1（会话层已预留 KV 适配，绑定 SESSIONS 后自动切换）。
// 默认管理员密码 123，首次登录后请到设置页修改。
import cssText from './style.css';

const SESSION_COOKIE = 'INFOSYSSESS';
const SESSION_TTL = 7 * 24 * 3600; // 会话存活时间（秒），写入时滑动续期
const PBKDF2_ITER_PW = 100000;     // 主密码哈希迭代次数（Workers 的 WebCrypto PBKDF2 上限为 10 万次）
const PBKDF2_ITER_WRAP = 100000;   // DK 包装密钥派生迭代次数（同上）
const BACKUP_VERSION = 1;
const BACKUP_MAX_BYTES = 10485760; // 10 MB
const BACKUP_MAX_RECORDS = 10000;

/* ================= 工具 ================= */

function h(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function b64encode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(str) {
  try {
    const bin = atob(String(str));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 存库用完整时间（Asia/Shanghai），格式 Y-m-d H:i:s。 */
function nowStr() {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).formatToParts(new Date());
  const p = Object.fromEntries(parts.map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
}

function dateOnly(value) {
  if (!value) return '';
  return String(value).slice(0, 10);
}

function seqNo(n) {
  return String(n).padStart(3, '0');
}

function strLenUtf8(s) {
  return [...String(s)].length;
}

/** 只有 http/https 才输出为可点击链接。 */
function safeUrl(url) {
  const u = String(url ?? '').trim();
  return /^https?:\/\//i.test(u) ? u : '';
}

/* ================= 加密（WebCrypto） ================= */

async function pbkdf2(password, saltBytes, iterations, length = 32) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

/** 主密码哈希：pbkdf2$迭代$盐$哈希（自包含格式）。 */
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITER_PW);
  return `pbkdf2$${PBKDF2_ITER_PW}$${b64encode(salt)}$${b64encode(hash)}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored ?? '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iter = parseInt(parts[1], 10);
  const salt = b64decode(parts[2]);
  const expect = b64decode(parts[3]);
  if (!iter || !salt || !expect) return false;
  const actual = await pbkdf2(password, salt, iter, expect.length);
  return timingSafeEqual(actual, expect);
}

/** AES-256-GCM 加密（字节版），返回 base64(nonce12 + tag16 + 密文)，与原 PHP 版格式一致。 */
async function aeEncryptRaw(keyBytes, plainBytes) {
  if (keyBytes.length !== 32) throw new Error('密钥长度必须为 32 字节。');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const out = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plainBytes)
  );
  const ct = out.slice(0, out.length - 16);
  const tag = out.slice(out.length - 16);
  const packed = new Uint8Array(12 + 16 + ct.length);
  packed.set(nonce, 0);
  packed.set(tag, 12);
  packed.set(ct, 28);
  return b64encode(packed);
}

/** 解密（字节版），失败返回 null。 */
async function aeDecryptRaw(keyBytes, payload) {
  if (!keyBytes || keyBytes.length !== 32) return null;
  const raw = b64decode(payload);
  if (!raw || raw.length < 28) return null;
  const nonce = raw.slice(0, 12);
  const tag = raw.slice(12, 28);
  const ct = raw.slice(28);
  const joined = new Uint8Array(ct.length + 16);
  joined.set(ct, 0);
  joined.set(tag, ct.length);
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, joined);
    return new Uint8Array(plain);
  } catch {
    return null;
  }
}

/** 文本版加解密（备注用）。 */
async function aeEncrypt(keyBytes, plainText) {
  return aeEncryptRaw(keyBytes, new TextEncoder().encode(plainText));
}

async function aeDecrypt(keyBytes, payload) {
  const bytes = await aeDecryptRaw(keyBytes, payload);
  return bytes === null ? null : new TextDecoder().decode(bytes);
}

/* ---- DK 包装：主密码派生包装密钥，加密随机数据密钥 DK ---- */

async function wrapDk(db, dkBytes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapKey = await pbkdf2(password, salt, PBKDF2_ITER_WRAP);
  await setSetting(db, 'dk_salt', b64encode(salt));
  await setSetting(db, 'dk_wrapped', 'pbkdf2$' + (await aeEncryptRaw(wrapKey, dkBytes)));
}

/** 用主密码解开 DK，返回 32 字节 Uint8Array；密码错或数据损坏返回 null。 */
async function unwrapDk(db, password) {
  const saltB64 = await getSetting(db, 'dk_salt');
  const wrapped = await getSetting(db, 'dk_wrapped');
  if (!saltB64 || !wrapped) return null;
  const salt = b64decode(saltB64);
  if (!salt) return null;
  const idx = wrapped.indexOf('$');
  if (idx < 0) return null;
  const algo = wrapped.slice(0, idx);
  const payload = wrapped.slice(idx + 1);
  if (algo !== 'pbkdf2') return null; // 本版只生成 pbkdf2 包装（新库无旧数据）
  const wrapKey = await pbkdf2(password, salt, PBKDF2_ITER_WRAP);
  const dk = await aeDecryptRaw(wrapKey, payload);
  return dk !== null && dk.length === 32 ? dk : null;
}

/* ================= 数据库（D1） ================= */

let dbReady = false;

async function initDb(db) {
  if (dbReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
      account TEXT NOT NULL DEFAULT '', hint TEXT NOT NULL DEFAULT '',
      hint_set_at TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT '')`),
    db.prepare(`CREATE TABLE IF NOT EXISTS hint_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entry_id INTEGER NOT NULL, hint TEXT NOT NULL, set_at TEXT NOT NULL,
      FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_history_entry ON hint_history(entry_id, id)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS vault_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, note_enc TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')`),
    db.prepare(`CREATE TABLE IF NOT EXISTS note_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, note_enc TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL)`),
  ]);
  const existing = await getSetting(db, 'master_hash');
  if (existing === '') {
    const defaults = [
      ['master_hash', await hashPassword('123')],
      ['theme', 'normal'],
      ['is_default_pw', '1'],
      ['page_size', '20'],
      ['site_name', '个人信息管理系统'],
    ];
    for (const [k, v] of defaults) {
      await db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').bind(k, v).run();
    }
  }
  dbReady = true;
}

async function getSetting(db, key) {
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? String(row.value) : '';
}

async function setSetting(db, key, value) {
  await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind(key, value).run();
}

async function siteName(db) {
  const name = (await getSetting(db, 'site_name')).trim();
  return name !== '' ? name : '个人信息管理系统';
}

async function pageSize(db) {
  const n = parseInt(await getSetting(db, 'page_size'), 10);
  return n >= 5 && n <= 200 ? n : 20;
}

function normalizePage(raw) {
  const p = parseInt(raw, 10);
  return p > 0 ? p : 1;
}

function totalPages(total, size) {
  return Math.max(1, Math.ceil(total / Math.max(1, size)));
}

async function getTheme(db) {
  const t = await getSetting(db, 'theme');
  return t === 'claude' || t === 'normal' ? t : 'normal';
}

/* ---- 账号记录 ---- */

async function listCategories(db) {
  const { results } = await db
    .prepare("SELECT DISTINCT category FROM entries WHERE category <> '' ORDER BY category")
    .all();
  return results.map((r) => String(r.category));
}

function entryWhere(q, category) {
  const clauses = [];
  const params = [];
  if (q !== '') {
    const like = '%' + q + '%';
    clauses.push('(site LIKE ? OR url LIKE ? OR account LIKE ? OR note LIKE ? OR category LIKE ?)');
    params.push(like, like, like, like, like);
  }
  if (category !== '') {
    clauses.push('category = ?');
    params.push(category);
  }
  return { where: clauses.length ? ' WHERE ' + clauses.join(' AND ') : '', params };
}

async function countEntries(db, q, category) {
  const { where, params } = entryWhere(q, category);
  const row = await db.prepare('SELECT COUNT(*) AS c FROM entries' + where).bind(...params).first();
  return row ? Number(row.c) : 0;
}

async function totalEntries(db) {
  const row = await db.prepare('SELECT COUNT(*) AS c FROM entries').first();
  return row ? Number(row.c) : 0;
}

async function searchEntries(db, q, category, limit, offset) {
  const { where, params } = entryWhere(q, category);
  let sql =
    'SELECT e.*, (SELECT COUNT(*) FROM entries e2 WHERE e2.id <= e.id) AS seq FROM entries e' +
    where +
    ' ORDER BY e.id DESC';
  if (limit > 0) sql += ` LIMIT ${Math.trunc(limit)} OFFSET ${Math.trunc(offset)}`;
  const { results } = await db.prepare(sql).bind(...params).all();
  return results;
}

async function getEntry(db, id) {
  return db.prepare('SELECT * FROM entries WHERE id = ?').bind(id).first();
}

async function entrySeq(db, id) {
  const row = await db.prepare('SELECT COUNT(*) AS c FROM entries WHERE id <= ?').bind(id).first();
  return row ? Number(row.c) : 0;
}

async function historyOf(db, entryId, limit = 2) {
  const { results } = await db
    .prepare('SELECT hint, set_at FROM hint_history WHERE entry_id = ? ORDER BY id DESC LIMIT ?')
    .bind(entryId, limit)
    .all();
  return results;
}

async function pushHistory(db, entryId, oldHint, oldSetAt) {
  if (oldHint === '') return; // 旧提示为空时不产生一条空历史
  await db
    .prepare('INSERT INTO hint_history (entry_id, hint, set_at) VALUES (?, ?, ?)')
    .bind(entryId, oldHint, oldSetAt !== '' ? oldSetAt : nowStr())
    .run();
  // 只保留最近 2 条
  await db
    .prepare(
      `DELETE FROM hint_history WHERE entry_id = ? AND id NOT IN (
         SELECT id FROM hint_history WHERE entry_id = ? ORDER BY id DESC LIMIT 2)`
    )
    .bind(entryId, entryId)
    .run();
}

async function insertEntry(db, d) {
  const r = await db
    .prepare(
      `INSERT INTO entries (site, url, category, account, hint, hint_set_at, note, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(d.site, d.url, d.category, d.account, d.hint, d.hint_set_at, d.note, d.updated_at)
    .run();
  return Number(r.meta.last_row_id);
}

async function updateEntry(db, id, d) {
  await db
    .prepare(
      `UPDATE entries SET site = ?, url = ?, category = ?, account = ?,
         hint = ?, hint_set_at = ?, note = ?, updated_at = ? WHERE id = ?`
    )
    .bind(d.site, d.url, d.category, d.account, d.hint, d.hint_set_at, d.note, d.updated_at, id)
    .run();
}

async function deleteEntry(db, id) {
  await db.batch([
    db.prepare('DELETE FROM hint_history WHERE entry_id = ?').bind(id),
    db.prepare('DELETE FROM entries WHERE id = ?').bind(id),
  ]);
}

/* ---- 私密信息（备注始终是密文，此处只搬运字节） ---- */

async function countVaultItems(db, q) {
  if (q === '') {
    const row = await db.prepare('SELECT COUNT(*) AS c FROM vault_items').first();
    return row ? Number(row.c) : 0;
  }
  const row = await db
    .prepare('SELECT COUNT(*) AS c FROM vault_items WHERE name LIKE ?')
    .bind('%' + q + '%')
    .first();
  return row ? Number(row.c) : 0;
}

async function listVaultItems(db, q, limit, offset) {
  let sql =
    'SELECT v.*, (SELECT COUNT(*) FROM vault_items v2 WHERE v2.id <= v.id) AS seq FROM vault_items v';
  const params = [];
  if (q !== '') {
    sql += ' WHERE name LIKE ?';
    params.push('%' + q + '%');
  }
  sql += ' ORDER BY v.id DESC';
  if (limit > 0) sql += ` LIMIT ${Math.trunc(limit)} OFFSET ${Math.trunc(offset)}`;
  const { results } = await db.prepare(sql).bind(...params).all();
  return results;
}

async function getVaultItem(db, id) {
  return db.prepare('SELECT * FROM vault_items WHERE id = ?').bind(id).first();
}

async function vaultItemSeq(db, id) {
  const row = await db.prepare('SELECT COUNT(*) AS c FROM vault_items WHERE id <= ?').bind(id).first();
  return row ? Number(row.c) : 0;
}

async function insertVaultItem(db, name, noteEnc, now) {
  const r = await db
    .prepare('INSERT INTO vault_items (name, note_enc, created_at, updated_at) VALUES (?, ?, ?, ?)')
    .bind(name, noteEnc, now, now)
    .run();
  return Number(r.meta.last_row_id);
}

async function updateVaultItem(db, id, name, noteEnc, now) {
  await db
    .prepare('UPDATE vault_items SET name = ?, note_enc = ?, updated_at = ? WHERE id = ?')
    .bind(name, noteEnc, now, id)
    .run();
}

async function deleteVaultItem(db, id) {
  await db.prepare('DELETE FROM vault_items WHERE id = ?').bind(id).run();
}

/* ---- 随手记录（结构与私密信息完全一致，备注同样加密存储） ---- */

async function countNoteItems(db, q) {
  if (q === '') {
    const row = await db.prepare('SELECT COUNT(*) AS c FROM note_items').first();
    return row ? Number(row.c) : 0;
  }
  const row = await db
    .prepare('SELECT COUNT(*) AS c FROM note_items WHERE name LIKE ?')
    .bind('%' + q + '%')
    .first();
  return row ? Number(row.c) : 0;
}

async function listNoteItems(db, q, limit, offset) {
  let sql =
    'SELECT v.*, (SELECT COUNT(*) FROM note_items v2 WHERE v2.id <= v.id) AS seq FROM note_items v';
  const params = [];
  if (q !== '') {
    sql += ' WHERE name LIKE ?';
    params.push('%' + q + '%');
  }
  sql += ' ORDER BY v.id DESC';
  if (limit > 0) sql += ` LIMIT ${Math.trunc(limit)} OFFSET ${Math.trunc(offset)}`;
  const { results } = await db.prepare(sql).bind(...params).all();
  return results;
}

async function getNoteItem(db, id) {
  return db.prepare('SELECT * FROM note_items WHERE id = ?').bind(id).first();
}

async function noteItemSeq(db, id) {
  const row = await db.prepare('SELECT COUNT(*) AS c FROM note_items WHERE id <= ?').bind(id).first();
  return row ? Number(row.c) : 0;
}

async function insertNoteItem(db, name, noteEnc, now) {
  const r = await db
    .prepare('INSERT INTO note_items (name, note_enc, created_at, updated_at) VALUES (?, ?, ?, ?)')
    .bind(name, noteEnc, now, now)
    .run();
  return Number(r.meta.last_row_id);
}

async function updateNoteItem(db, id, name, noteEnc, now) {
  await db
    .prepare('UPDATE note_items SET name = ?, note_enc = ?, updated_at = ? WHERE id = ?')
    .bind(name, noteEnc, now, id)
    .run();
}

async function deleteNoteItem(db, id) {
  await db.prepare('DELETE FROM note_items WHERE id = ?').bind(id).run();
}

/* ================= 会话存储 =================
   默认存 D1 的 sessions 表（强一致，读写无延迟问题）。
   若日后绑定了 KV 命名空间 SESSIONS，会自动改走 KV，无需改代码。 */

class D1SessionStore {
  constructor(db) { this.db = db; }
  async get(id) {
    const row = await this.db
      .prepare('SELECT data, expires_at FROM sessions WHERE id = ?')
      .bind(id)
      .first();
    if (!row) return null;
    if (Number(row.expires_at) < Math.floor(Date.now() / 1000)) {
      await this.delete(id);
      return null;
    }
    return String(row.data);
  }
  async put(id, value) {
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
    await this.db
      .prepare('INSERT OR REPLACE INTO sessions (id, data, expires_at) VALUES (?, ?, ?)')
      .bind(id, value, exp)
      .run();
  }
  async delete(id) {
    await this.db.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
  }
}

class KvSessionStore {
  constructor(kv) { this.kv = kv; }
  async get(id) { return this.kv.get('sess:' + id); }
  async put(id, value) { await this.kv.put('sess:' + id, value, { expirationTtl: SESSION_TTL }); }
  async delete(id) { await this.kv.delete('sess:' + id); }
}

class Session {
  constructor(store) {
    this.store = store;
    this.id = null;
    this.data = {};
    this.isNew = false;
    this.destroyed = false;
    this.cookieDirty = false;
  }

  static parseCookie(request) {
    const header = request.headers.get('Cookie') || '';
    for (const part of header.split(';')) {
      const [k, ...rest] = part.trim().split('=');
      if (k === SESSION_COOKIE) return rest.join('=');
    }
    return null;
  }

  async load(request) {
    const id = Session.parseCookie(request);
    if (id && /^[a-f0-9]{64}$/.test(id)) {
      const raw = await this.store.get(id);
      if (raw) {
        try {
          this.data = JSON.parse(raw);
          this.id = id;
          return;
        } catch { /* 损坏则当新会话 */ }
      }
    }
    this.create();
  }

  create() {
    this.id = randomHex(32);
    this.data = {};
    this.isNew = true;
    this.cookieDirty = true;
  }

  async regenerate() {
    const oldId = this.id;
    this.id = randomHex(32);
    this.cookieDirty = true;
    if (oldId) await this.store.delete(oldId);
  }

  async destroy() {
    if (this.id) await this.store.delete(this.id);
    this.data = {};
    this.destroyed = true;
  }

  async save() {
    if (this.destroyed || !this.id) return;
    await this.store.put(this.id, JSON.stringify(this.data));
  }

  cookieHeader() {
    if (this.destroyed) {
      return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
    }
    if (!this.cookieDirty) return null;
    return `${SESSION_COOKIE}=${this.id}; Path=/; HttpOnly; Secure; SameSite=Strict`;
  }

  /* -- 字段小工具 -- */
  get loggedIn() { return !!this.data.logged_in; }
  csrfToken() {
    if (!this.data.csrf) this.data.csrf = randomHex(32);
    return this.data.csrf;
  }
  csrfValid(token) {
    return typeof token === 'string' && token !== '' && token === this.data.csrf;
  }
  flashSet(message, type = 'ok') { this.data.flash = { message, type }; }
  flashTake() {
    const f = this.data.flash || null;
    delete this.data.flash;
    return f;
  }
}

/* ---- 私密信息会话侧 ---- */

function vaultDkBytes(session) {
  const b64 = session.data.vault_dk || '';
  if (!b64) return null;
  const bytes = b64decode(b64);
  return bytes && bytes.length === 32 ? bytes : null;
}

function vaultHasDk(session) {
  return vaultDkBytes(session) !== null;
}

async function vaultEncrypt(session, plain) {
  const dk = vaultDkBytes(session);
  if (!dk) throw new Error('数据密钥无效，请退出后重新登录。');
  return aeEncrypt(dk, plain);
}

async function vaultDecrypt(session, payload) {
  const dk = vaultDkBytes(session);
  if (!dk) return null;
  return aeDecrypt(dk, payload);
}

/** 登录成功后调用：解开 DK 放进会话；首次使用则生成并包装。 */
async function vaultAfterLogin(db, session, password) {
  const wrapped = await getSetting(db, 'dk_wrapped');
  let dk = null;
  if (wrapped !== '') {
    dk = await unwrapDk(db, password);
  } else {
    dk = crypto.getRandomValues(new Uint8Array(32));
    await wrapDk(db, dk, password);
  }
  if (dk) session.data.vault_dk = b64encode(dk);
  else delete session.data.vault_dk;
}

/** 改主密码：旧密码解 DK，新密码+新盐重新包装，备注密文不动。 */
async function rewrapDk(db, oldPassword, newPassword) {
  if ((await getSetting(db, 'dk_wrapped')) === '') {
    await wrapDk(db, crypto.getRandomValues(new Uint8Array(32)), newPassword);
    return true;
  }
  const dk = await unwrapDk(db, oldPassword);
  if (!dk) return false;
  await wrapDk(db, dk, newPassword);
  return true;
}

async function vaultDefaultPassword(db) {
  if ((await getSetting(db, 'is_default_pw')) === '1') return true;
  return verifyPassword('123', await getSetting(db, 'master_hash'));
}

/* ================= 页面片段 ================= */

function starSvg() {
  return '<svg class="star" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M12 2v20M2 12h20M5 5l14 14M19 5L5 19"></path></svg>';
}

function searchSvg() {
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="M20 20l-4-4"></path></svg>';
}

function htmlHead(theme, title) {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="${h(theme)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title>${h(title)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&amp;family=Noto+Serif+SC:wght@500;600&amp;family=IBM+Plex+Mono:wght@500&amp;display=swap" rel="stylesheet">
  <link rel="stylesheet" href="assets/style.css">
</head>
<body>
`;
}

function csrfInput(session) {
  return `<input type="hidden" name="csrf" value="${h(session.csrfToken())}">`;
}

function defaultPwNotice(extra = '') {
  return `<div class="notice">
      <strong>你还在使用默认密码，请尽快修改</strong>
      ${extra}
      <a class="btn btn-sm btn-primary" href="settings.php">去修改</a>
    </div>`;
}

function themeForm(session, action, theme) {
  return `<form method="post" action="${action}" class="segmented">
          ${csrfInput(session)}
          <input type="hidden" name="action" value="theme">
          <button type="submit" name="theme" value="normal" class="btn ${theme === 'normal' ? 'on' : ''}" aria-pressed="${theme === 'normal'}">普通</button>
          <button type="submit" name="theme" value="claude" class="btn ${theme === 'claude' ? 'on' : ''}" aria-pressed="${theme === 'claude'}">Claude</button>
        </form>`;
}

function logoutForm(session) {
  return `<form method="post" action="index.php">
          ${csrfInput(session)}
          <input type="hidden" name="action" value="logout">
          <button type="submit" class="btn">退出登录</button>
        </form>`;
}

function flashHtml(flash, cls = 'flash') {
  if (!flash) return '';
  return `<div class="${cls} ${h(flash.type)}">${h(flash.message)}</div>`;
}

/** 分页导航 HTML（与原 pager() 输出一致）。 */
function pagerHtml(page, pages, matched, baseParams, basePath) {
  if (pages <= 1) return '';
  const mk = (n) => {
    const params = new URLSearchParams(baseParams);
    params.set('p', String(n));
    return `${basePath}?${params.toString()}`;
  };
  const prev = Math.max(1, page - 1);
  const next = Math.min(pages, page + 1);
  let s = '<nav class="pager" aria-label="分页导航">';
  s += `<span class="pager-info">共 ${matched} 条 · 第 ${page}/${pages} 页</span>`;
  s += '<div class="pager-links">';
  s += `<a class="pager-btn${page <= 1 ? ' disabled' : ''}" href="${h(mk(1))}" aria-label="首页">首页</a>`;
  s += `<a class="pager-btn${page <= 1 ? ' disabled' : ''}" href="${h(mk(prev))}" aria-label="上一页">上一页</a>`;
  const from = Math.max(1, page - 2);
  const to = Math.min(pages, page + 2);
  if (from > 1) {
    s += `<a class="pager-btn" href="${h(mk(1))}">1</a>`;
    if (from > 2) s += '<span class="pager-gap">…</span>';
  }
  for (let n = from; n <= to; n++) {
    s += `<a class="pager-btn${n === page ? ' current' : ''}" href="${h(mk(n))}"${n === page ? ' aria-current="page"' : ''}>${n}</a>`;
  }
  if (to < pages) {
    if (to < pages - 1) s += '<span class="pager-gap">…</span>';
    s += `<a class="pager-btn" href="${h(mk(pages))}">${pages}</a>`;
  }
  s += `<a class="pager-btn${page >= pages ? ' disabled' : ''}" href="${h(mk(next))}" aria-label="下一页">下一页</a>`;
  s += `<a class="pager-btn${page >= pages ? ' disabled' : ''}" href="${h(mk(pages))}" aria-label="末页">末页</a>`;
  s += '</div></nav>';
  return s;
}

const MODAL_SCRIPT = (autoOpen) => `<script>
(function () {
  var modal = document.getElementById('addModal');
  function open() {
    modal.hidden = false;
    document.body.classList.add('modal-open');
    var first = modal.querySelector('[autofocus]') || modal.querySelector('input');
    if (first) { first.focus(); }
  }
  function close() {
    modal.hidden = true;
    document.body.classList.remove('modal-open');
  }
  document.querySelectorAll('[data-open-add]').forEach(function (el) {
    el.addEventListener('click', open);
  });
  document.querySelectorAll('[data-close-add]').forEach(function (el) {
    el.addEventListener('click', close);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !modal.hidden) { close(); }
  });
  // 整行可点：点条目行任意位置打开该条详情（点行内的链接、按钮、表单时不触发）
  document.querySelectorAll('tr[data-open]').forEach(function (tr) {
    tr.addEventListener('click', function (e) {
      if (e.target.closest('a, button, form, input, textarea, select, label')) { return; }
      window.location.href = tr.getAttribute('data-open');
    });
  });
  // 窄屏编辑时把编辑区滚到眼前
  if (window.location.search.indexOf('edit=') !== -1 && window.matchMedia('(max-width: 900px)').matches) {
    var ed = document.querySelector('.layout.editing .editor');
    if (ed) { ed.scrollIntoView(); }
  }
  ${autoOpen ? 'open();' : ''}
})();
</script>`;

/* ================= 响应小工具 ================= */

const NO_STORE = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  Pragma: 'no-cache',
  Expires: '0',
};

async function respond(session, response) {
  await session.save();
  const headers = new Headers(response.headers);
  const cookie = session.cookieHeader();
  if (cookie) headers.append('Set-Cookie', cookie);
  return new Response(response.body, { status: response.status, headers });
}

function htmlResponse(session, body, status = 200) {
  return respond(
    session,
    new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...NO_STORE } })
  );
}

function redirectResponse(session, location) {
  return respond(session, new Response(null, { status: 302, headers: { Location: location, ...NO_STORE } }));
}

/** 所有 POST 必须带有效 CSRF token。校验失败返回 true（已拦截）。 */
function csrfBlocked(session, form) {
  return !session.csrfValid(form.get('csrf'));
}

function csrfFailResponse(session) {
  return htmlResponse(session, '表单校验失败：CSRF token 无效，请刷新页面后重试。', 403);
}

/* ================= 账号提示页（index.php） ================= */

async function handleIndex(env, session, request, url) {
  const db = env.DB;

  if (request.method === 'POST') {
    const form = await request.formData();
    if (csrfBlocked(session, form)) return csrfFailResponse(session);
    const action = String(form.get('action') || '');

    if (action === 'login') {
      const triedPw = String(form.get('pw') || '');
      const hash = await getSetting(db, 'master_hash');
      if (hash !== '' && (await verifyPassword(triedPw, hash))) {
        await session.regenerate();
        session.data = { logged_in: true, login_fails: 0, csrf: randomHex(32) };
        await vaultAfterLogin(db, session, triedPw);
        session.flashSet('登录成功。');
        return redirectResponse(session, 'index.php');
      }
      const fails = (Number(session.data.login_fails) || 0) + 1;
      session.data.login_fails = fails;
      await session.save();
      await sleep(Math.min(fails, 5) * 1000);
      return renderLogin(env, session, '密码不正确，请重试。连续输错会逐次延长等待时间（最多 5 秒）。');
    }

    if (session.loggedIn) {
      if (action === 'logout') {
        await session.destroy();
        return redirectResponse(session, 'index.php');
      }

      if (action === 'theme') {
        const wanted = String(form.get('theme') || '');
        if (wanted === 'normal' || wanted === 'claude') await setSetting(db, 'theme', wanted);
        return redirectResponse(session, 'index.php');
      }

      if (action === 'save') {
        const id = parseInt(form.get('id') || '0', 10) || 0;
        const values = {
          site: String(form.get('site') || '').trim(),
          url: String(form.get('url') || '').trim(),
          category: String(form.get('category') || '').trim(),
          account: String(form.get('account') || '').trim(),
          hint: String(form.get('hint') || '').trim(),
          note: String(form.get('note') || ''),
        };
        const errors = {};
        if (values.site === '') {
          errors.site = '网站名称不能为空：请填上网站或服务的名称再保存。';
        }
        // 网址没写协议时自动补全 https://；只有明显非网址的乱码才提示
        if (values.url !== '') {
          const u = values.url;
          if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) {
            if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?(\/.*)?$/i.test(u)) {
              values.url = 'https://' + u;
            } else {
              errors.url = '网址看起来不太对：可以只填域名（如 baidu.com），会自动补 https://；记不全就留空。';
            }
          }
        }
        if (Object.keys(errors).length > 0) {
          session.data.form_state = { id, values, errors };
          return redirectResponse(session, 'index.php' + (id > 0 ? '?edit=' + id : '?add=1'));
        }

        const now = nowStr();
        if (id > 0) {
          const old = await getEntry(db, id);
          if (!old) {
            session.flashSet('要修改的记录不存在，可能已被删除。', 'err');
            return redirectResponse(session, 'index.php');
          }
          const hintChanged = values.hint !== String(old.hint);
          if (hintChanged) await pushHistory(db, id, String(old.hint), String(old.hint_set_at));
          await updateEntry(db, id, {
            ...values,
            hint_set_at: hintChanged ? now : String(old.hint_set_at),
            updated_at: now,
          });
          session.flashSet(hintChanged ? '已保存，提示变更已记入历史。' : '已保存。');
          return redirectResponse(session, 'index.php?edit=' + id);
        }
        const newId = await insertEntry(db, {
          ...values,
          hint_set_at: values.hint !== '' ? now : '',
          updated_at: now,
        });
        session.flashSet('已添加记录。');
        return redirectResponse(session, 'index.php?edit=' + newId);
      }

      if (action === 'delete') {
        const delId = parseInt(form.get('id') || '0', 10) || 0;
        if (delId > 0) await deleteEntry(db, delId);
        session.flashSet('已删除记录。');
        return redirectResponse(session, 'index.php');
      }
    }
    return redirectResponse(session, 'index.php');
  }

  /* GET */
  if (!session.loggedIn) return renderLogin(env, session, '');

  const theme = await getTheme(db);
  const name = await siteName(db);
  const flash = session.flashTake();
  const q = (url.searchParams.get('q') || '').trim();
  const cat = url.searchParams.get('cat') || '';
  const catList = await listCategories(db);
  const size = await pageSize(db);
  let page = normalizePage(url.searchParams.get('p') || '1');
  const matched = await countEntries(db, q, cat);
  const pages = totalPages(matched, size);
  if (page > pages) page = pages;
  const rows = await searchEntries(db, q, cat, size, (page - 1) * size);

  const editId = parseInt(url.searchParams.get('edit') || '0', 10) || 0;
  const isAdd = url.searchParams.has('add');
  const editing = editId > 0 ? await getEntry(db, editId) : null;

  const state = session.data.form_state || null;
  delete session.data.form_state;

  const blank = { site: '', url: '', category: '', account: '', hint: '', note: '' };
  let editValues = editing
    ? {
        site: String(editing.site), url: String(editing.url), category: String(editing.category),
        account: String(editing.account), hint: String(editing.hint), note: String(editing.note),
      }
    : blank;
  let addValues = blank;
  let editErrors = {};
  let addErrors = {};
  if (state && typeof state === 'object') {
    const stateId = Number(state.id) || 0;
    if (stateId > 0 && stateId === editId) {
      editValues = state.values;
      editErrors = state.errors || {};
    } else if (stateId === 0 && isAdd) {
      addValues = state.values;
      addErrors = state.errors || {};
    }
  }

  const history = editing ? await historyOf(db, editId) : [];
  const prev = history[0] || null;
  const prev2 = history[1] || null;
  const isDefault = (await getSetting(db, 'is_default_pw')) === '1';

  let body = htmlHead(theme, name);
  body += '<div class="wrap">\n';
  if (isDefault) body += defaultPwNotice();
  body += `<div class="topbar">
    <div class="brand"><h1>${starSvg()}${h(name)}</h1></div>
    <div class="top-right">
      <div class="top-actions">
        ${themeForm(session, 'index.php', theme)}
        <a class="btn" href="settings.php">设置</a>
        ${logoutForm(session)}
      </div>
      ${flash ? flashHtml(flash, 'flash top-flash') : ''}
    </div>
  </div>

  <nav class="tabs" aria-label="模块导航">
    <a href="index.php" class="on" aria-current="page">账号提示</a>
    <a href="vault.php">私密信息</a>
    <a href="notes.php">随手记录</a>
  </nav>

  <div class="toolbar">
    <form method="get" action="index.php" class="filter-form" id="filterForm">
      <label for="q" class="sr-only">搜索</label>
      <div class="search-box">
        ${searchSvg()}
        <input id="q" name="q" value="${h(q)}" placeholder="搜索网站、网址、账号、备注、分类" autocomplete="off">
      </div>
      <label for="cat" class="sr-only">按分类筛选</label>
      <select id="cat" name="cat" class="ctl">
        <option value="">全部分类</option>
        ${catList.map((c) => `<option value="${h(c)}"${cat === c ? ' selected' : ''}>${h(c)}</option>`).join('')}
      </select>
      <button type="submit" class="btn">筛选</button>
      ${q !== '' || cat !== '' ? '<a class="btn" href="index.php">清除</a>' : ''}
    </form>
    <button type="button" class="btn btn-primary" data-open-add>添加记录</button>
  </div>

  <div class="layout${editing ? ' editing' : ''}">
    <div class="list-card">`;

  if (rows.length === 0) {
    body += '<div class="empty">还没有记录，点「添加记录」存入第一个网站。</div>';
  } else {
    body += `<table class="entries">
          <thead>
            <tr><th>序号</th><th>网站</th><th>账号</th><th>密码提示</th><th>分类</th><th>修改于</th></tr>
          </thead>
          <tbody>`;
    for (const row of rows) {
      const rid = Number(row.id);
      const link = safeUrl(String(row.url));
      body += `<tr data-open="index.php?edit=${rid}" class="${editing && rid === editId ? 'active' : ''}">
                <td class="seq-cell" title="序号 ${seqNo(Number(row.seq))}">${seqNo(Number(row.seq))}</td>
                <td>${link !== ''
                  ? `<a class="site-link" href="${h(link)}" target="_blank" rel="noopener noreferrer">${h(row.site)}</a>`
                  : `<span class="site-link">${h(row.site)}</span>`}</td>
                <td>${h(row.account)}</td>
                <td>${String(row.hint) !== ''
                  ? `<span class="hint-tag">${h(row.hint)}</span>`
                  : '<span class="cell-sub">未设置</span>'}</td>
                <td>${h(row.category)}</td>
                <td class="meta-cell">
                  ${h(dateOnly(String(row.updated_at)))}
                  <a class="edit-link" href="index.php?edit=${rid}">编辑</a>
                  <form method="post" action="index.php" class="row-form"
                        onsubmit="return confirm('确定删除这条记录吗？删除后无法恢复。');">
                    ${csrfInput(session)}
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="${rid}">
                    <button type="submit" class="row-del">删除</button>
                  </form>
                </td>
              </tr>`;
    }
    body += '</tbody></table>';
  }
  const pagerParams = {};
  if (q !== '') pagerParams.q = q;
  if (cat !== '') pagerParams.cat = cat;
  body += pagerHtml(page, pages, matched, pagerParams, 'index.php');
  body += '</div>'; // list-card

  if (!editing) {
    body += `<div class="editor editor-empty">
        <div class="empty-mark" aria-hidden="true">&#9998;</div>
        <h2>等待编辑</h2>
        <p>在左侧选择一条记录进行修改，<br>或点击上方「添加记录」新建一条。</p>
      </div>`;
  } else {
    const editSeq = await entrySeq(db, editId);
    body += `<div class="editor">
      <a class="back-to-list" href="index.php">&larr; 返回列表</a>
      <div class="editor-head">
        <span class="seq-badge">序号 ${seqNo(editSeq)}</span>
        <span class="who">${h(editing.site)}</span>
      </div>

      <form method="post" action="index.php" id="saveForm">
        ${csrfInput(session)}
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="id" value="${editId}">

        <div class="hint-box">
          <label for="hint">
            当前密码提示(${String(editing.hint_set_at) !== '' ? '设置于 ' + h(dateOnly(String(editing.hint_set_at))) : '未设置'})
          </label>
          <input class="hint-input" type="text" id="hint" name="hint"
                 value="${h(editValues.hint ?? '')}"
                 autocomplete="off" spellcheck="false" placeholder="手写提示，例如 l。。。9">
          <div class="tip">保存新提示后，当前提示会自动变成「上一次」，往前顺延。</div>`;
    if (prev) {
      body += `<div class="hist-row">
              <span class="when">上一次(${h(dateOnly(String(prev.set_at)))})</span>
              <span class="val">${h(prev.hint)}</span>
            </div>`;
    }
    if (prev2) {
      body += `<div class="hist-row">
              <span class="when">上上次(${h(dateOnly(String(prev2.set_at)))})</span>
              <span class="val">${h(prev2.hint)}</span>
            </div>`;
    }
    body += `</div>

        <div class="field">
          <label for="site">网站名称</label>
          <input type="text" id="site" name="site" value="${h(editValues.site ?? '')}" required>
          ${editErrors.site ? `<span class="err">${h(editErrors.site)}</span>` : ''}
        </div>

        <div class="field">
          <label for="url">网址</label>
          <input type="text" id="url" name="url" value="${h(editValues.url ?? '')}" placeholder="https://example.com" inputmode="url">
          ${editErrors.url ? `<span class="err">${h(editErrors.url)}</span>` : ''}
        </div>

        <div class="field">
          <label for="account">账号</label>
          <input type="text" id="account" name="account" value="${h(editValues.account ?? '')}" autocomplete="off">
        </div>

        <div class="field">
          <label for="category">分类</label>
          <input type="text" id="category" name="category" list="categoryList" value="${h(editValues.category ?? '')}">
          <datalist id="categoryList">
            ${catList.map((c) => `<option value="${h(c)}"></option>`).join('')}
          </datalist>
        </div>

        <div class="field">
          <label for="note">备注</label>
          <textarea id="note" name="note" rows="16">${h(editValues.note ?? '')}</textarea>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary">保存</button>
          <a class="btn" href="index.php">取消</a>
          <button type="submit" class="btn btn-danger" form="deleteForm">删除</button>
        </div>
      </form>
    </div>

    <form id="deleteForm" method="post" action="index.php"
          onsubmit="return confirm('确定删除这条记录吗？删除后无法恢复。');">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="id" value="${editId}">
    </form>`;
  }

  body += `</div></div>

<div class="modal" id="addModal" role="dialog" aria-modal="true" aria-labelledby="addModalTitle" hidden>
  <div class="modal-backdrop" data-close-add></div>
  <div class="modal-dialog">
    <div class="modal-head">
      <h2 id="addModalTitle">添加记录</h2>
      <button type="button" class="modal-close" data-close-add aria-label="关闭">&times;</button>
    </div>
    <form method="post" action="index.php" id="addForm">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="0">

      <div class="hint-box">
        <label for="add_hint">当前密码提示（未设置）</label>
        <input class="hint-input" type="text" id="add_hint" name="hint"
               value="${h(addValues.hint ?? '')}"
               autocomplete="off" spellcheck="false" placeholder="手写提示，例如 l。。。9">
        <div class="tip">只存提示，不存完整密码。保存后可在编辑面板继续修改。</div>
      </div>

      <div class="field">
        <label for="add_site">网站名称</label>
        <input type="text" id="add_site" name="site" value="${h(addValues.site ?? '')}" required autofocus>
        ${addErrors.site ? `<span class="err">${h(addErrors.site)}</span>` : ''}
      </div>

      <div class="field">
        <label for="add_url">网址</label>
        <input type="text" id="add_url" name="url" value="${h(addValues.url ?? '')}" placeholder="https://example.com，可只填域名" inputmode="url">
        ${addErrors.url ? `<span class="err">${h(addErrors.url)}</span>` : ''}
      </div>

      <div class="field">
        <label for="add_account">账号</label>
        <input type="text" id="add_account" name="account" value="${h(addValues.account ?? '')}" autocomplete="off">
      </div>

      <div class="field">
        <label for="add_category">分类</label>
        <input type="text" id="add_category" name="category" list="addCategoryList" value="${h(addValues.category ?? '')}">
        <datalist id="addCategoryList">
          ${catList.map((c) => `<option value="${h(c)}"></option>`).join('')}
        </datalist>
      </div>

      <div class="field">
        <label for="add_note">备注</label>
        <textarea id="add_note" name="note" rows="10">${h(addValues.note ?? '')}</textarea>
      </div>

      <div class="actions">
        <button type="submit" class="btn btn-primary">保存</button>
        <button type="button" class="btn" data-close-add>取消</button>
      </div>
    </form>
  </div>
</div>

${MODAL_SCRIPT(isAdd)}
</body></html>`;
  return htmlResponse(session, body);
}

async function renderLogin(env, session, loginError) {
  const db = env.DB;
  const theme = await getTheme(db);
  const name = await siteName(db);
  const flash = session.flashTake();
  let body = htmlHead(theme, '登录 · ' + name);
  body += `<div class="auth-wrap">
      <div class="auth-card">
        <h1>${starSvg()}${h(name)}</h1>
        ${flash ? flashHtml(flash) : ''}
        ${loginError !== '' ? `<div class="flash err">${h(loginError)}</div>` : ''}
        <form method="post" action="index.php">
          ${csrfInput(session)}
          <input type="hidden" name="action" value="login">
          <div class="field">
            <label for="pw">密码</label>
            <input type="password" id="pw" name="pw" autocomplete="current-password" autofocus required>
          </div>
          <button type="submit" class="btn btn-primary">登录</button>
        </form>
      </div>
    </div>
    </body></html>`;
  return htmlResponse(session, body);
}

/* ================= 私密信息页（vault.php） ================= */

async function handleVault(env, session, request, url) {
  const db = env.DB;
  if (!session.loggedIn) return redirectResponse(session, 'index.php');

  if (request.method === 'POST') {
    const form = await request.formData();
    if (csrfBlocked(session, form)) return csrfFailResponse(session);
    const action = String(form.get('action') || '');

    if (action === 'theme') {
      const wanted = String(form.get('theme') || '');
      if (wanted === 'normal' || wanted === 'claude') await setSetting(db, 'theme', wanted);
      return redirectResponse(session, 'vault.php');
    }

    if (action === 'delete') {
      const rid = parseInt(form.get('id') || '0', 10) || 0;
      if (rid > 0) await deleteVaultItem(db, rid);
      session.flashSet('已删除私密信息。');
      return redirectResponse(session, 'vault.php');
    }

    if (action === 'save') {
      const id = parseInt(form.get('id') || '0', 10) || 0;
      const back = id > 0 ? 'vault.php?edit=' + id : 'vault.php?add=1';
      const name = String(form.get('name') || '').trim();
      const note = String(form.get('note') || '');
      const errs = [];

      if (await vaultDefaultPassword(db)) errs.push('请先修改默认密码,再保存私密信息。');
      if (!vaultHasDk(session)) errs.push('数据密钥未加载，请退出后重新登录。');
      if (name === '') errs.push('名称不能为空：请填写称呼，例如「身份证」。');

      if (errs.length > 0) {
        session.data.vault_form_state = { id, name, note, errors: errs };
        return redirectResponse(session, back);
      }

      const now = nowStr();
      if (id > 0) {
        const old = await getVaultItem(db, id);
        if (!old) {
          session.flashSet('这条私密信息不存在，可能已被删除。', 'err');
          return redirectResponse(session, 'vault.php');
        }
        const enc = await vaultEncrypt(session, note);
        await updateVaultItem(db, id, name, enc, now);
        session.flashSet('已保存。');
        return redirectResponse(session, 'vault.php?edit=' + id);
      }
      const enc = await vaultEncrypt(session, note);
      const newId = await insertVaultItem(db, name, enc, now);
      session.flashSet('已添加私密信息。');
      return redirectResponse(session, 'vault.php?edit=' + newId);
    }
    return redirectResponse(session, 'vault.php');
  }

  /* GET */
  const theme = await getTheme(db);
  const site = await siteName(db);
  const flash = session.flashTake();
  const dkReady = vaultHasDk(session);
  const q = (url.searchParams.get('q') || '').trim();
  const size = await pageSize(db);
  let page = normalizePage(url.searchParams.get('p') || '1');
  const matched = await countVaultItems(db, q);
  const pages = totalPages(matched, size);
  if (page > pages) page = pages;
  const items = await listVaultItems(db, q, size, (page - 1) * size);

  const editId = parseInt(url.searchParams.get('edit') || '0', 10) || 0;
  const isAdd = url.searchParams.has('add');
  let editing = editId > 0 ? await getVaultItem(db, editId) : null;
  if (editId > 0 && !editing) return redirectResponse(session, 'vault.php');

  const state = session.data.vault_form_state || null;
  delete session.data.vault_form_state;

  let editName = '';
  let editPlain = '';
  let editErrors = [];
  if (editing) {
    editName = String(editing.name);
    const dec = await vaultDecrypt(session, String(editing.note_enc));
    editPlain = dec === null ? '' : dec;
  }
  let addName = '';
  let addPlain = '';
  let addErrors = [];
  if (state && typeof state === 'object') {
    const stateId = Number(state.id) || 0;
    const errs = Array.isArray(state.errors) ? state.errors : [];
    if (stateId > 0 && stateId === editId) {
      editName = String(state.name ?? '');
      editPlain = String(state.note ?? '');
      editErrors = errs;
    } else if (stateId === 0 && isAdd) {
      addName = String(state.name ?? '');
      addPlain = String(state.note ?? '');
      addErrors = errs;
    }
  }

  const isDefault = (await getSetting(db, 'is_default_pw')) === '1';
  const errList = (errs) =>
    errs.length
      ? `<span class="err">${errs.map((e) => `<span>${h(e)}</span>`).join('')}</span>`
      : '';

  let body = htmlHead(theme, '私密信息 · ' + site);
  body += '<div class="wrap">\n';
  if (isDefault) body += defaultPwNotice('<span>默认密码下不能保存私密信息</span>');
  body += `<div class="topbar">
    <div class="brand"><h1>${starSvg()}${h(site)}</h1></div>
    <div class="top-right">
      <div class="top-actions">
        ${themeForm(session, 'vault.php', theme)}
        <a class="btn" href="settings.php">设置</a>
        ${logoutForm(session)}
      </div>
      ${flash ? flashHtml(flash, 'flash top-flash') : ''}
      ${!dkReady ? '<div class="flash top-flash err">数据密钥未加载，请退出后重新登录。</div>' : ''}
    </div>
  </div>

  <nav class="tabs" aria-label="模块导航">
    <a href="index.php">账号提示</a>
    <a href="vault.php" class="on" aria-current="page">私密信息</a>
    <a href="notes.php">随手记录</a>
  </nav>

  <div class="toolbar">
    <form method="get" action="vault.php" class="filter-form" id="filterForm">
      <label for="q" class="sr-only">搜索名称</label>
      <div class="search-box">
        ${searchSvg()}
        <input id="q" name="q" value="${h(q)}" placeholder="搜索名称" autocomplete="off">
      </div>
      <button type="submit" class="btn">搜索</button>
      ${q !== '' ? '<a class="btn" href="vault.php">清除</a>' : ''}
    </form>
    <button type="button" class="btn btn-primary" data-open-add>添加</button>
  </div>

  <div class="layout${editing ? ' editing' : ''}">
    <div class="list-card">`;

  if (items.length === 0) {
    body += '<div class="empty">还没有私密信息,点「添加」存入第一条。</div>';
  } else {
    body += `<table class="entries vault-table">
          <thead>
            <tr><th>序号</th><th>名称</th><th>修改于</th></tr>
          </thead>
          <tbody>`;
    for (const item of items) {
      const rid = Number(item.id);
      body += `<tr data-open="vault.php?edit=${rid}" class="${editing && rid === editId ? 'active' : ''}">
                <td class="seq-cell" title="序号 ${seqNo(Number(item.seq))}">${seqNo(Number(item.seq))}</td>
                <td><a class="site-link" href="vault.php?edit=${rid}">${h(item.name)}</a></td>
                <td class="meta-cell">
                  ${h(dateOnly(String(item.updated_at)))}
                  <a class="edit-link" href="vault.php?edit=${rid}">编辑</a>
                  <form method="post" action="vault.php" class="row-form"
                        onsubmit="return confirm('确定删除这条私密信息吗？删除后无法恢复。');">
                    ${csrfInput(session)}
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="${rid}">
                    <button type="submit" class="row-del">删除</button>
                  </form>
                </td>
              </tr>`;
    }
    body += '</tbody></table>';
  }
  const pagerParams = {};
  if (q !== '') pagerParams.q = q;
  body += pagerHtml(page, pages, matched, pagerParams, 'vault.php');
  body += '</div>'; // list-card

  if (!editing) {
    body += `<div class="editor editor-empty">
        <div class="empty-mark" aria-hidden="true">&#9998;</div>
        <h2>等待编辑</h2>
        <p>在左侧选择一条私密信息进行修改，<br>或点击上方「添加」新建一条。</p>
      </div>`;
  } else {
    const vseq = await vaultItemSeq(db, editId);
    body += `<div class="editor">
      <a class="back-to-list" href="vault.php">&larr; 返回列表</a>
      <div class="editor-head">
        <span class="seq-badge">序号 ${seqNo(vseq)}</span>
        <span class="who">${h(editing.name)}</span>
      </div>

      <form method="post" action="vault.php" id="saveForm">
        ${csrfInput(session)}
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="id" value="${editId}">

        <div class="field">
          <label for="vname">名称</label>
          <input type="text" id="vname" name="name" value="${h(editName)}" autocomplete="off" required>
          <div class="desc">名称只写称呼,例如「身份证」「社保」「工商银行卡」,号码写在备注里。</div>
          ${errList(editErrors)}
        </div>

        <div class="field">
          <label for="vnote">备注</label>
          <textarea id="vnote" name="note" rows="16" autocomplete="off">${h(editPlain)}</textarea>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary">保存</button>
          <a class="btn" href="vault.php">取消</a>
          <button type="submit" class="btn btn-danger" form="deleteFormV">删除</button>
        </div>
      </form>
    </div>

    <form id="deleteFormV" method="post" action="vault.php"
          onsubmit="return confirm('确定删除这条私密信息吗？删除后无法恢复。');">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="id" value="${editId}">
    </form>`;
  }

  body += `</div></div>

<div class="modal" id="addModal" role="dialog" aria-modal="true" aria-labelledby="addModalTitle" hidden>
  <div class="modal-backdrop" data-close-add></div>
  <div class="modal-dialog">
    <div class="modal-head">
      <h2 id="addModalTitle">添加私密信息</h2>
      <button type="button" class="modal-close" data-close-add aria-label="关闭">&times;</button>
    </div>
    <form method="post" action="vault.php" id="addForm">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="0">

      <div class="field">
        <label for="add_vname">名称</label>
        <input type="text" id="add_vname" name="name" value="${h(addName)}" autocomplete="off" required autofocus>
        <div class="desc">名称只写称呼,例如「身份证」「社保」「工商银行卡」,号码写在备注里。</div>
        ${errList(addErrors)}
      </div>

      <div class="field">
        <label for="add_vnote">备注</label>
        <textarea id="add_vnote" name="note" rows="10" autocomplete="off">${h(addPlain)}</textarea>
      </div>

      <div class="actions">
        <button type="submit" class="btn btn-primary">保存</button>
        <button type="button" class="btn" data-close-add>取消</button>
      </div>
    </form>
  </div>
</div>

${MODAL_SCRIPT(isAdd)}
</body></html>`;
  return htmlResponse(session, body);
}

/* ================= 随手记录页（notes.php） ================= */

async function handleNotes(env, session, request, url) {
  const db = env.DB;
  if (!session.loggedIn) return redirectResponse(session, 'index.php');

  if (request.method === 'POST') {
    const form = await request.formData();
    if (csrfBlocked(session, form)) return csrfFailResponse(session);
    const action = String(form.get('action') || '');

    if (action === 'theme') {
      const wanted = String(form.get('theme') || '');
      if (wanted === 'normal' || wanted === 'claude') await setSetting(db, 'theme', wanted);
      return redirectResponse(session, 'notes.php');
    }

    if (action === 'delete') {
      const rid = parseInt(form.get('id') || '0', 10) || 0;
      if (rid > 0) await deleteNoteItem(db, rid);
      session.flashSet('已删除随手记录。');
      return redirectResponse(session, 'notes.php');
    }

    if (action === 'save') {
      const id = parseInt(form.get('id') || '0', 10) || 0;
      const back = id > 0 ? 'notes.php?edit=' + id : 'notes.php?add=1';
      const name = String(form.get('name') || '').trim();
      const note = String(form.get('note') || '');
      const errs = [];

      if (await vaultDefaultPassword(db)) errs.push('请先修改默认密码，再保存随手记录。');
      if (!vaultHasDk(session)) errs.push('数据密钥未加载，请退出后重新登录。');
      if (name === '') errs.push('名称不能为空：请填写一个标题。');

      if (errs.length > 0) {
        session.data.note_form_state = { id, name, note, errors: errs };
        return redirectResponse(session, back);
      }

      const now = nowStr();
      if (id > 0) {
        const old = await getNoteItem(db, id);
        if (!old) {
          session.flashSet('这条随手记录不存在，可能已被删除。', 'err');
          return redirectResponse(session, 'notes.php');
        }
        const enc = await vaultEncrypt(session, note);
        await updateNoteItem(db, id, name, enc, now);
        session.flashSet('已保存。');
        return redirectResponse(session, 'notes.php?edit=' + id);
      }
      const enc = await vaultEncrypt(session, note);
      const newId = await insertNoteItem(db, name, enc, now);
      session.flashSet('已添加随手记录。');
      return redirectResponse(session, 'notes.php?edit=' + newId);
    }
    return redirectResponse(session, 'notes.php');
  }

  /* GET */
  const theme = await getTheme(db);
  const site = await siteName(db);
  const flash = session.flashTake();
  const dkReady = vaultHasDk(session);
  const q = (url.searchParams.get('q') || '').trim();
  const size = await pageSize(db);
  let page = normalizePage(url.searchParams.get('p') || '1');
  const matched = await countNoteItems(db, q);
  const pages = totalPages(matched, size);
  if (page > pages) page = pages;
  const items = await listNoteItems(db, q, size, (page - 1) * size);

  const editId = parseInt(url.searchParams.get('edit') || '0', 10) || 0;
  const isAdd = url.searchParams.has('add');
  let editing = editId > 0 ? await getNoteItem(db, editId) : null;
  if (editId > 0 && !editing) return redirectResponse(session, 'notes.php');

  const state = session.data.note_form_state || null;
  delete session.data.note_form_state;

  let editName = '';
  let editPlain = '';
  let editErrors = [];
  if (editing) {
    editName = String(editing.name);
    const dec = await vaultDecrypt(session, String(editing.note_enc));
    editPlain = dec === null ? '' : dec;
  }
  let addName = '';
  let addPlain = '';
  let addErrors = [];
  if (state && typeof state === 'object') {
    const stateId = Number(state.id) || 0;
    const errs = Array.isArray(state.errors) ? state.errors : [];
    if (stateId > 0 && stateId === editId) {
      editName = String(state.name ?? '');
      editPlain = String(state.note ?? '');
      editErrors = errs;
    } else if (stateId === 0 && isAdd) {
      addName = String(state.name ?? '');
      addPlain = String(state.note ?? '');
      addErrors = errs;
    }
  }

  const isDefault = (await getSetting(db, 'is_default_pw')) === '1';
  const errList = (errs) =>
    errs.length
      ? `<span class="err">${errs.map((e) => `<span>${h(e)}</span>`).join('')}</span>`
      : '';

  let body = htmlHead(theme, '随手记录 · ' + site);
  body += '<div class="wrap">\n';
  if (isDefault) body += defaultPwNotice('<span>默认密码下不能保存随手记录</span>');
  body += `<div class="topbar">
    <div class="brand"><h1>${starSvg()}${h(site)}</h1></div>
    <div class="top-right">
      <div class="top-actions">
        ${themeForm(session, 'notes.php', theme)}
        <a class="btn" href="settings.php">设置</a>
        ${logoutForm(session)}
      </div>
      ${flash ? flashHtml(flash, 'flash top-flash') : ''}
      ${!dkReady ? '<div class="flash top-flash err">数据密钥未加载，请退出后重新登录。</div>' : ''}
    </div>
  </div>

  <nav class="tabs" aria-label="模块导航">
    <a href="index.php">账号提示</a>
    <a href="vault.php">私密信息</a>
    <a href="notes.php" class="on" aria-current="page">随手记录</a>
  </nav>

  <div class="toolbar">
    <form method="get" action="notes.php" class="filter-form" id="filterForm">
      <label for="q" class="sr-only">搜索名称</label>
      <div class="search-box">
        ${searchSvg()}
        <input id="q" name="q" value="${h(q)}" placeholder="搜索名称" autocomplete="off">
      </div>
      <button type="submit" class="btn">搜索</button>
      ${q !== '' ? '<a class="btn" href="notes.php">清除</a>' : ''}
    </form>
    <button type="button" class="btn btn-primary" data-open-add>添加</button>
  </div>

  <div class="layout${editing ? ' editing' : ''}">
    <div class="list-card">`;

  if (items.length === 0) {
    body += '<div class="empty">还没有随手记录，点「添加」记下第一条。</div>';
  } else {
    body += `<table class="entries vault-table">
          <thead>
            <tr><th>序号</th><th>名称</th><th>修改于</th></tr>
          </thead>
          <tbody>`;
    for (const item of items) {
      const rid = Number(item.id);
      body += `<tr data-open="notes.php?edit=${rid}" class="${editing && rid === editId ? 'active' : ''}">
                <td class="seq-cell" title="序号 ${seqNo(Number(item.seq))}">${seqNo(Number(item.seq))}</td>
                <td><a class="site-link" href="notes.php?edit=${rid}">${h(item.name)}</a></td>
                <td class="meta-cell">
                  ${h(dateOnly(String(item.updated_at)))}
                  <a class="edit-link" href="notes.php?edit=${rid}">编辑</a>
                  <form method="post" action="notes.php" class="row-form"
                        onsubmit="return confirm('确定删除这条随手记录吗？删除后无法恢复。');">
                    ${csrfInput(session)}
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="${rid}">
                    <button type="submit" class="row-del">删除</button>
                  </form>
                </td>
              </tr>`;
    }
    body += '</tbody></table>';
  }
  const pagerParams = {};
  if (q !== '') pagerParams.q = q;
  body += pagerHtml(page, pages, matched, pagerParams, 'notes.php');
  body += '</div>'; // list-card

  if (!editing) {
    body += `<div class="editor editor-empty">
        <div class="empty-mark" aria-hidden="true">&#9998;</div>
        <h2>等待编辑</h2>
        <p>在左侧选择一条随手记录进行修改，<br>或点击上方「添加」新建一条。</p>
      </div>`;
  } else {
    const nseq = await noteItemSeq(db, editId);
    body += `<div class="editor">
      <a class="back-to-list" href="notes.php">&larr; 返回列表</a>
      <div class="editor-head">
        <span class="seq-badge">序号 ${seqNo(nseq)}</span>
        <span class="who">${h(editing.name)}</span>
      </div>

      <form method="post" action="notes.php" id="saveForm">
        ${csrfInput(session)}
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="id" value="${editId}">

        <div class="field">
          <label for="nname">名称</label>
          <input type="text" id="nname" name="name" value="${h(editName)}" autocomplete="off" required>
          <div class="desc">名称写个标题，网上看到的东西随手粘贴到备注里。</div>
          ${errList(editErrors)}
        </div>

        <div class="field">
          <label for="nnote">备注</label>
          <textarea id="nnote" name="note" rows="16" autocomplete="off">${h(editPlain)}</textarea>
        </div>

        <div class="actions">
          <button type="submit" class="btn btn-primary">保存</button>
          <a class="btn" href="notes.php">取消</a>
          <button type="submit" class="btn btn-danger" form="deleteFormN">删除</button>
        </div>
      </form>
    </div>

    <form id="deleteFormN" method="post" action="notes.php"
          onsubmit="return confirm('确定删除这条随手记录吗？删除后无法恢复。');">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="id" value="${editId}">
    </form>`;
  }

  body += `</div></div>

<div class="modal" id="addModal" role="dialog" aria-modal="true" aria-labelledby="addModalTitle" hidden>
  <div class="modal-backdrop" data-close-add></div>
  <div class="modal-dialog">
    <div class="modal-head">
      <h2 id="addModalTitle">添加随手记录</h2>
      <button type="button" class="modal-close" data-close-add aria-label="关闭">&times;</button>
    </div>
    <form method="post" action="notes.php" id="addForm">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="save">
      <input type="hidden" name="id" value="0">

      <div class="field">
        <label for="add_nname">名称</label>
        <input type="text" id="add_nname" name="name" value="${h(addName)}" autocomplete="off" required autofocus>
        <div class="desc">名称写个标题，网上看到的东西随手粘贴到备注里。</div>
        ${errList(addErrors)}
      </div>

      <div class="field">
        <label for="add_nnote">备注</label>
        <textarea id="add_nnote" name="note" rows="10" autocomplete="off">${h(addPlain)}</textarea>
      </div>

      <div class="actions">
        <button type="submit" class="btn btn-primary">保存</button>
        <button type="button" class="btn" data-close-add>取消</button>
      </div>
    </form>
  </div>
</div>

${MODAL_SCRIPT(isAdd)}
</body></html>`;
  return htmlResponse(session, body);
}

/* ================= 设置页（settings.php） ================= */

async function handleSettings(env, session, request) {
  const db = env.DB;
  if (!session.loggedIn) return redirectResponse(session, 'index.php');

  if (request.method === 'POST') {
    const form = await request.formData();
    if (csrfBlocked(session, form)) return csrfFailResponse(session);
    const action = String(form.get('action') || '');

    if (action === 'theme') {
      const wanted = String(form.get('theme') || '');
      if (wanted === 'normal' || wanted === 'claude') {
        await setSetting(db, 'theme', wanted);
        session.flashSet('主题已切换。');
      }
      return redirectResponse(session, 'settings.php');
    }

    if (action === 'page_size') {
      const raw = String(form.get('page_size') || '').trim();
      const n = parseInt(raw, 10);
      if (raw === '' || Number.isNaN(n) || n < 5 || n > 200) {
        session.flashSet('每页条数只能是 5 到 200 之间的整数，请重新填写。', 'err');
      } else {
        await setSetting(db, 'page_size', String(n));
        session.flashSet('每页显示条数已设为 ' + n + ' 条。');
      }
      return redirectResponse(session, 'settings.php');
    }

    if (action === 'site_name') {
      const name = String(form.get('site_name') || '').trim();
      if (name === '' || strLenUtf8(name) > 40) {
        session.flashSet('网站名称不能为空，且不超过 40 个字。', 'err');
      } else {
        await setSetting(db, 'site_name', name);
        session.flashSet('网站名称已修改。');
      }
      return redirectResponse(session, 'settings.php');
    }

    if (action === 'change_pw') {
      const current = String(form.get('current') || '');
      const fresh = String(form.get('new') || '');
      const confirm = String(form.get('confirm') || '');
      const errs = [];

      if (!(await verifyPassword(current, await getSetting(db, 'master_hash')))) {
        errs.push('当前密码不正确：请核对后重新输入。');
      }
      if (strLenUtf8(fresh) < 6) errs.push('新密码太短：至少需要 6 位，请换一个更长的。');
      if (fresh === '123') errs.push('新密码不能是 123：请换一个别的密码。');
      if (fresh !== confirm) errs.push('两次输入的新密码不一致：请重新确认。');

      if (errs.length === 0 && !(await rewrapDk(db, current, fresh))) {
        errs.push('私密信息密钥解开失败，已取消修改密码。请退出后重新登录再试。');
      }

      if (errs.length > 0) {
        session.data.settings_errors = errs;
        return redirectResponse(session, 'settings.php');
      }

      await setSetting(db, 'master_hash', await hashPassword(fresh));
      await setSetting(db, 'is_default_pw', '0');

      // 改密后强制重新登录：销毁旧会话，新会话只带一条闪现消息
      await session.destroy();
      session.destroyed = false;
      session.create();
      session.flashSet('密码已修改，请用新密码重新登录。');
      return redirectResponse(session, 'index.php');
    }
    return redirectResponse(session, 'settings.php');
  }

  /* GET */
  const theme = await getTheme(db);
  const site = await siteName(db);
  const flash = session.flashTake();
  const errors = Array.isArray(session.data.settings_errors) ? session.data.settings_errors : [];
  delete session.data.settings_errors;
  const isDefault = (await getSetting(db, 'is_default_pw')) === '1';
  const size = await pageSize(db);

  let body = htmlHead(theme, '设置 · ' + site);
  body += '<div class="wrap">\n';
  if (isDefault) {
    body += `<div class="notice">
      <strong>你还在使用默认密码，请尽快修改</strong>
      <span>当前仍是初始密码 123</span>
    </div>`;
  }
  body += `<div class="topbar">
    <div class="brand">
      <h1>${starSvg()}设置</h1>
      <div class="brand-sub">${h(site)} · 单管理员</div>
    </div>
    <div class="top-right">
      <div class="top-actions">
        <a class="btn" href="index.php">返回主页</a>
        ${logoutForm(session)}
      </div>
      ${flash ? flashHtml(flash, 'flash top-flash') : ''}
    </div>
  </div>

  <div class="settings-card">

    <h2>网站名称</h2>
    <p class="lead">页面顶部和浏览器标签显示的名字，可改成你自己的叫法。</p>
    <form method="post" action="settings.php" class="row">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="site_name">
      <label class="sr-only" for="site_name">网站名称</label>
      <input type="text" id="site_name" name="site_name" value="${h(site)}" maxlength="40" class="site-name-input" required>
      <button type="submit" class="btn btn-primary">保存</button>
    </form>

    <hr class="divider">

    <h2>修改密码</h2>
    <p class="lead">主密码一旦忘记，私密信息将无法找回。</p>
    ${errors.length ? `<div class="flash err"><div>${errors.map((e) => `<div>${h(e)}</div>`).join('')}</div></div>` : ''}
    <form method="post" action="settings.php" id="pwForm">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="change_pw">
      <div class="field">
        <label for="current">当前密码</label>
        <input type="password" id="current" name="current" autocomplete="current-password" required>
      </div>
      <div class="field">
        <label for="new">新密码</label>
        <input type="password" id="new" name="new" autocomplete="new-password" required>
      </div>
      <div class="field">
        <label for="confirm">确认新密码</label>
        <input type="password" id="confirm" name="confirm" autocomplete="new-password" required>
      </div>
      <div class="actions">
        <button type="submit" class="btn btn-primary">保存新密码</button>
      </div>
    </form>

    <hr class="divider">

    <h2>主题</h2>
    <p class="lead">选择后立即生效，并保存到设置中。</p>
    <form method="post" action="settings.php" class="row">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="theme">
      <div class="segmented">
        <button type="submit" name="theme" value="normal" class="btn ${theme === 'normal' ? 'on' : ''}" aria-pressed="${theme === 'normal'}">普通</button>
        <button type="submit" name="theme" value="claude" class="btn ${theme === 'claude' ? 'on' : ''}" aria-pressed="${theme === 'claude'}">Claude</button>
      </div>
    </form>

    <hr class="divider">

    <h2>分页</h2>
    <p class="lead">列表每页显示的条数，账号提示和私密信息两个列表共用。可填 5 到 200。</p>
    <form method="post" action="settings.php" class="row">
      ${csrfInput(session)}
      <input type="hidden" name="action" value="page_size">
      <label class="sr-only" for="page_size">每页显示条数</label>
      <input type="number" id="page_size" name="page_size" min="5" max="200" step="1"
             value="${size}" class="page-size-input" required>
      <button type="submit" class="btn btn-primary">保存</button>
    </form>

    <hr class="divider">

    <h2>数据备份与迁移</h2>
    <p class="lead">把全部记录导出成一个文件保存，之后可在另一台电脑或重新安装后导入恢复。账号提示与私密信息都包含在内。</p>

    <div class="backup-block">
      <div class="backup-row">
        <div class="backup-info">
          <strong>导出备份</strong>
          <span>下载一个 JSON 文件，包含当前全部记录。</span>
        </div>
        <a class="btn btn-primary" href="backup.php?action=export">下载备份文件</a>
      </div>

      <div class="backup-divider"></div>

      <div class="backup-row backup-row-top">
        <div class="backup-info">
          <strong>导入备份</strong>
          <span>选择之前导出的 JSON 文件恢复记录。</span>
        </div>
        <form method="post" action="backup.php" enctype="multipart/form-data" class="import-form" id="importForm">
          ${csrfInput(session)}
          <input type="hidden" name="action" value="import">
          <div class="field">
            <label for="backup_file">备份文件（.json，最大 10 MB）</label>
            <input type="file" id="backup_file" name="backup_file" accept=".json,application/json" required>
          </div>
          <div class="field">
            <label>导入方式</label>
            <div class="segmented">
              <label class="btn"><input type="radio" name="mode" value="append" checked> 追加</label>
              <label class="btn"><input type="radio" name="mode" value="replace"> 覆盖</label>
            </div>
            <div class="desc">追加＝保留现有记录，把备份里的加进来；覆盖＝先清空现有记录，再导入（不可撤销）。</div>
          </div>
          <div class="actions">
            <button type="submit" class="btn btn-primary" id="importSubmit">开始导入</button>
          </div>
        </form>
      </div>

      <div class="backup-warn">
        <strong>安全提醒</strong>
        <p>导出的备份文件里，密码提示和私密信息备注都是<strong>明文</strong>。请存放在安全的地方，导入后及时删除，不要通过微信、邮件随意发送。</p>
        <p>私密信息换环境导入时，会用新环境的密码重新加密；导出时若当前密钥无法解开某条备注，该条会被跳过，不会被写进文件。</p>
      </div>
    </div>

  </div>
</div>

<script>
(function () {
  var form = document.getElementById('importForm');
  if (!form) { return; }
  var radios = form.querySelectorAll('input[name="mode"]');
  function sync() {
    radios.forEach(function (r) {
      var label = r.closest('label');
      if (label) { label.classList.toggle('on', r.checked); }
    });
  }
  radios.forEach(function (r) { r.addEventListener('change', sync); });
  sync();

  var submit = document.getElementById('importSubmit');
  if (submit) {
    submit.addEventListener('click', function (e) {
      var mode = form.querySelector('input[name="mode"]:checked');
      var isReplace = mode && mode.value === 'replace';
      var msg = isReplace
        ? '确定导入吗？「覆盖」模式会先清空当前所有记录，请先做好备份。'
        : '确定导入吗？将把备份中的记录追加到现有数据中。';
      if (!window.confirm(msg)) { e.preventDefault(); }
    });
  }
})();
</script>
</body></html>`;
  return htmlResponse(session, body);
}

/* ================= 备份（backup.php） ================= */

function impStr(row, key, maxLen) {
  let v = row ? row[key] : '';
  if (typeof v !== 'string' && typeof v !== 'number') return '';
  v = String(v);
  const chars = [...v];
  return chars.length > maxLen ? chars.slice(0, maxLen).join('') : v;
}

async function handleBackup(env, session, request, url) {
  const db = env.DB;
  if (!session.loggedIn) return redirectResponse(session, 'index.php');

  const fail = (message) => {
    session.flashSet(message, 'err');
    return redirectResponse(session, 'settings.php');
  };

  let action = url.searchParams.get('action') || '';
  let form = null;
  if (request.method === 'POST') {
    form = await request.formData();
    if (csrfBlocked(session, form)) return csrfFailResponse(session);
    action = String(form.get('action') || action);
  }

  /* ---- 导出 ---- */
  if (action === 'export' && request.method === 'GET') {
    const { results: entryRows } = await db
      .prepare('SELECT * FROM entries ORDER BY id ASC')
      .all();
    const entries = [];
    for (const row of entryRows) {
      const { results: hist } = await db
        .prepare('SELECT hint, set_at FROM hint_history WHERE entry_id = ? ORDER BY id ASC')
        .bind(Number(row.id))
        .all();
      entries.push({
        site: String(row.site), url: String(row.url), category: String(row.category),
        account: String(row.account), hint: String(row.hint), hint_set_at: String(row.hint_set_at),
        note: String(row.note), updated_at: String(row.updated_at),
        history: hist.map((x) => ({ hint: String(x.hint), set_at: String(x.set_at) })),
      });
    }

    let vaultSkipped = 0;
    const vault = [];
    const { results: vaultRows } = await db
      .prepare('SELECT name, note_enc, created_at, updated_at FROM vault_items ORDER BY id ASC')
      .all();
    if (vaultHasDk(session)) {
      for (const row of vaultRows) {
        const plain = await vaultDecrypt(session, String(row.note_enc));
        if (plain === null) {
          vaultSkipped++;
          continue;
        }
        vault.push({
          name: String(row.name), note: plain,
          created_at: String(row.created_at), updated_at: String(row.updated_at),
        });
      }
    } else {
      vaultSkipped = vaultRows.length;
    }
    void vaultSkipped;

    const data = {
      app: await siteName(db),
      version: BACKUP_VERSION,
      exported_at: nowStr(),
      entries,
      vault_items: vault,
      _note: '本文件含明文密码提示与备注，请勿泄露；导入后请妥善删除。',
    };
    const json = JSON.stringify(data, null, 2);
    const stamp = nowStr().replace(' ', '_').replaceAll(':', '');
    const filename = `backup_${stamp.slice(0, 10)}_${stamp.slice(11)}.json`;
    return respond(
      session,
      new Response(json, {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'X-Content-Type-Options': 'nosniff',
          ...NO_STORE,
        },
      })
    );
  }

  /* ---- 导入 ---- */
  if (request.method === 'POST' && action === 'import') {
    const mode = String(form.get('mode') || 'append');
    if (mode !== 'append' && mode !== 'replace') {
      return fail('导入方式无效，请选择「追加」或「覆盖」。');
    }
    const file = form.get('backup_file');
    if (!file || typeof file === 'string') return fail('请选择要导入的备份文件。');
    if (file.size > BACKUP_MAX_BYTES) return fail('备份文件超过 10 MB 上限，请拆分后再导入。');
    const raw = await file.text();
    if (raw.length > BACKUP_MAX_BYTES) return fail('读取备份文件失败，请重试。');

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return fail('备份文件格式错误：不是有效的 JSON，请确认选对了文件。');
    }
    if (!data || typeof data !== 'object') {
      return fail('备份文件格式错误：不是有效的 JSON，请确认选对了文件。');
    }
    if (Number(data.version || 0) !== BACKUP_VERSION) {
      return fail('备份文件版本不兼容，请使用本系统导出的备份文件。');
    }
    if (!Array.isArray(data.entries) || !Array.isArray(data.vault_items)) {
      return fail('备份文件结构不完整：缺少记录数据。');
    }
    if (data.entries.length > BACKUP_MAX_RECORDS || data.vault_items.length > BACKUP_MAX_RECORDS) {
      return fail('备份文件记录数超过 ' + BACKUP_MAX_RECORDS + ' 条上限。');
    }

    const canVault = vaultHasDk(session) && !(await vaultDefaultPassword(db));
    if (mode === 'replace' && data.vault_items.length > 0 && !canVault) {
      return fail('「覆盖」模式下导入私密信息需先修改默认密码，以免清空现有数据后无法加密保存。');
    }

    let entryCount = 0;
    let vaultCount = 0;
    let vaultSkip = 0;
    try {
      if (mode === 'replace') {
        await db.batch([
          db.prepare('DELETE FROM hint_history'),
          db.prepare('DELETE FROM entries'),
          db.prepare('DELETE FROM vault_items'),
        ]);
      }
      const now = nowStr();
      for (const e of data.entries) {
        if (!e || typeof e !== 'object') continue;
        const site = impStr(e, 'site', 200);
        if (site === '') continue;
        const newId = await insertEntry(db, {
          site,
          url: impStr(e, 'url', 1000),
          category: impStr(e, 'category', 200),
          account: impStr(e, 'account', 300),
          hint: impStr(e, 'hint', 500),
          hint_set_at: impStr(e, 'hint_set_at', 40),
          note: impStr(e, 'note', 50000),
          updated_at: impStr(e, 'updated_at', 40) || now,
        });
        const history = Array.isArray(e.history) ? e.history : [];
        for (const hh of history) {
          if (!hh || typeof hh !== 'object') continue;
          await pushHistory(db, newId, impStr(hh, 'hint', 500), impStr(hh, 'set_at', 40));
        }
        entryCount++;
      }
      for (const v of data.vault_items) {
        if (!v || typeof v !== 'object') continue;
        const name = impStr(v, 'name', 200);
        if (name === '') continue;
        if (!canVault) {
          vaultSkip++;
          continue;
        }
        const enc = await vaultEncrypt(session, impStr(v, 'note', 100000));
        await insertVaultItem(db, name, enc, nowStr());
        vaultCount++;
      }
    } catch {
      return fail('导入失败，原有记录未受影响。');
    }

    let msg = '导入完成：账号 ' + entryCount + ' 条';
    if (vaultCount > 0) msg += '，私密信息 ' + vaultCount + ' 条';
    if (vaultSkip > 0) msg += '；跳过私密信息 ' + vaultSkip + ' 条（需修改默认密码后再导入）';
    if (entryCount === 0 && vaultCount === 0 && vaultSkip === 0) {
      msg = '导入完成，但备份文件中没有可导入的记录。';
    }
    msg += '。';
    session.flashSet(msg);
    return redirectResponse(session, 'settings.php');
  }

  return redirectResponse(session, 'settings.php');
}

/* ================= 路由 ================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/assets/style.css') {
      return new Response(cssText, {
        headers: { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': 'public, max-age=3600' },
      });
    }
    if (path === '/favicon.ico') return new Response(null, { status: 204 });

    const known = ['/', '/index.php', '/vault.php', '/notes.php', '/settings.php', '/backup.php'];
    if (!known.includes(path)) return new Response('Not Found', { status: 404 });

    await initDb(env.DB);
    const store = env.SESSIONS ? new KvSessionStore(env.SESSIONS) : new D1SessionStore(env.DB);
    const session = new Session(store);
    await session.load(request);

    if (path === '/' && request.method === 'GET') return redirectResponse(session, 'index.php');
    if (path === '/index.php' || path === '/') return handleIndex(env, session, request, url);
    if (path === '/vault.php') return handleVault(env, session, request, url);
    if (path === '/notes.php') return handleNotes(env, session, request, url);
    if (path === '/settings.php') return handleSettings(env, session, request);
    return handleBackup(env, session, request, url);
  },
};
