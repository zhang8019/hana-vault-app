var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// hana/atomic-write.js
var atomic_write_exports = {};
__export(atomic_write_exports, {
  default: () => atomic_write_default,
  withFileLock: () => withFileLock,
  writeFileAtomic: () => writeFileAtomic
});
import { mkdir, open, rename, rm, unlink, writeFile } from "node:fs/promises";
import { dirname, join as join2 } from "node:path";
import { randomBytes as randomBytes2 } from "node:crypto";
async function writeFileAtomic(path, data, options = {}) {
  const mode = options.mode;
  const dirMode = options.dirMode;
  await mkdir(dirname(path), { recursive: true, ...dirMode !== void 0 ? { mode: dirMode } : {} });
  const tmp = join2(dirname(path), `.${randomBytes2(6).toString("hex")}.tmp`);
  try {
    await writeFile(tmp, data, mode !== void 0 ? { mode } : void 0);
    const handle = await open(tmp, "r+");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tmp, path);
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => {
    });
    throw error;
  }
}
async function withFileLock(path, fn) {
  const lockPath = `${path}${LOCK_SUFFIX}`;
  const startedAt = Date.now();
  let handle;
  for (; ; ) {
    try {
      handle = await open(lockPath, "wx");
      break;
    } catch (error) {
      if (error && error.code === "EEXIST") {
        try {
          const stat = await import("node:fs/promises").then((fs) => fs.stat(lockPath));
          if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
            await unlink(lockPath).catch(() => {
            });
            continue;
          }
        } catch {
          continue;
        }
        if (Date.now() - startedAt > LOCK_TIMEOUT_MS) {
          throw new Error(`dsh-vault: timed out waiting for vault lock (${lockPath})`);
        }
        await sleep(LOCK_RETRY_MS);
        continue;
      }
      throw error;
    }
  }
  try {
    return await fn();
  } finally {
    await handle.close().catch(() => {
    });
    await rm(lockPath, { force: true }).catch(() => {
    });
  }
}
var LOCK_SUFFIX, LOCK_RETRY_MS, LOCK_TIMEOUT_MS, LOCK_STALE_MS, sleep, atomic_write_default;
var init_atomic_write = __esm({
  "hana/atomic-write.js"() {
    LOCK_SUFFIX = ".lock";
    LOCK_RETRY_MS = 50;
    LOCK_TIMEOUT_MS = 1e4;
    LOCK_STALE_MS = 3e4;
    sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    atomic_write_default = { writeFileAtomic, withFileLock };
  }
});

// src/crypto.ts
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";
var scrypt = promisify(scryptCallback);
var KEY_LENGTH = 32;
var IV_LENGTH = 12;
var SCRYPT_N = 2 ** 15;
var SCRYPT_R = 8;
var SCRYPT_P = 1;
var SCRYPT_MAXMEM = 1024 * 1024 * 1024;
var VAULT_FORMAT_VERSION = 1;
async function deriveKey(masterPassword, params) {
  const salt = Buffer.from(params.saltHex, "hex");
  return scrypt(masterPassword, salt, KEY_LENGTH, {
    N: params.n,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM
  });
}
function newKdfParams() {
  return {
    algo: "scrypt",
    n: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    saltHex: randomBytes(16).toString("hex")
  };
}
function encrypt(plaintext, key) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ivHex: iv.toString("hex"), tagHex: tag.toString("hex"), dataHex: data.toString("hex") };
}
function decrypt(blob, key) {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(blob.ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(blob.tagHex, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(blob.dataHex, "hex")),
    decipher.final()
  ]);
}
function safeEqual(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

// src/store.ts
import { chmod, mkdir as mkdir2, readFile, rm as rm2 } from "node:fs/promises";
import { basename, dirname as dirname2, join as join3 } from "node:path";
import { randomUUID } from "node:crypto";

// hana/home-paths.js
import { homedir } from "node:os";
import { join } from "node:path";
var HANA_HOME_ENV = "HANA_HOME";
var HANA_HOME_DIR_NAME = ".hanako";
function defaultHanaHome() {
  return join(homedir(), HANA_HOME_DIR_NAME);
}
function resolveHanaHome(configured, env = process.env) {
  const fromEnv = env[HANA_HOME_ENV];
  const selected = configured ?? (fromEnv !== void 0 && fromEnv.trim().length > 0 ? fromEnv : defaultHanaHome());
  return selected;
}
function hanaHomePath(...segments) {
  return join(resolveHanaHome(), ...segments);
}
function dshHomePath(...segments) {
  return hanaHomePath(...segments);
}

// src/store.ts
var VERIFY_PLAINTEXT = "dsh-vault:password-ok";
var EXPORT_FORMAT_VERSION = 2;
function defaultVaultPath(vaultName = "default") {
  return join3(dshHomePath("vault"), `${vaultName}.json`);
}
async function openVault(options) {
  const path = options.path ?? defaultVaultPath(options.name);
  const store = new VaultStore(path, options.masterPassword ?? "");
  if (options.keyMaterial !== void 0) await store.loadWithKey(options.keyMaterial);
  else { if (options.masterPassword.length === 0) throw new Error("vault master password must not be empty"); await store.load(); }
  return store;
}
var VaultStore = class _VaultStore {
  entries = /* @__PURE__ */ new Map();
  path;
  masterPassword;
  keyMaterial = false;
  /** KDF parameters fixed for this vault's life; set on first load/create. */
  kdf;
  /** Cached derived key; derived once after load and reused for every persist. */
  key;
  /** Serializes in-process persist calls so concurrent mutations never
   * contend for the cross-process file lock and every write sees the latest
   * in-memory state. */
  persistChain = Promise.resolve();
  /** Auto-lock: after this many ms of inactivity the vault re-locks (key
   * wiped). `0`/undefined disables auto-lock. */
  lockTimeoutMs;
  /** Epoch millis of the last operation; used for the auto-lock timer. */
  lastActivity = Date.now();
  /** Whether the vault is currently locked (key wiped, requires re-unlock). */
  locked = false;
  /** Weak-password heuristic: too short or in a tiny common list. */
  static MIN_PASSWORD_LENGTH = 12;
  /** How many previous passwords to keep per entry (1Password-style). */
  static MAX_PASSWORD_HISTORY = 10;
  /** In-process audit trail: oldest first, capped at AUDIT_CAP. Persisted to
   * an encrypted sidecar file (`<vault>-audit.json`) so activity survives
   * restarts. Events carry only action + entry title + timestamp — the caller
   * must never pass a secret value (see `audit()`). */
  history = [];
  /** Audit entries retained in memory and in the encrypted log file. */
  static AUDIT_CAP = 600;
  /** Debounce before writing non-mutation events (reads/searches/TOTP/switch)
   * to disk; mutations flush synchronously inside persist(). */
  static AUDIT_FLUSH_MS = 400;
  auditFlushTimer;
  /** Serializes sidecar writes so a debounced flush and a persist-triggered
   * flush never interleave partial files. */
  auditWriteChain = Promise.resolve();
  constructor(path, masterPassword) {
    this.path = path;
    this.masterPassword = masterPassword;
  }
  /** Enable auto-lock with the given idle timeout (ms). */
  setAutoLock(timeoutMs) {
    this.lockTimeoutMs = timeoutMs;
    this.lastActivity = Date.now();
  }
  /** Whether the vault is currently locked. */
  get isLocked() {
    return this.locked;
  }
  /** Touch the activity timestamp; call before every read/write. */
  touch() {
    this.lastActivity = Date.now();
  }
  /** Whether the auto-lock idle window has elapsed. */
  get expired() {
    if (this.lockTimeoutMs === void 0 || this.lockTimeoutMs <= 0) return false;
    return Date.now() - this.lastActivity > this.lockTimeoutMs;
  }
  /** Lock the vault: wipe the derived key and require re-unlock. */
  async lock() {
    if (!this.locked) await this.flushAuditLog().catch(() => {
    });
    if (!this.keyMaterial) { this.key?.fill(0); this.key = void 0; }
    this.locked = true;
    this.lastActivity = Date.now();
  }
  /** Reopen with the same key for device-authorized instances; password instances retain old behavior. */
  async unlock() {
    if (this.kdf === void 0) { await this.load(); return; }
    if (this.keyMaterial && this.key) {
      const { file, created } = await this.readDocument();
      if (created || !safeEqual(decrypt(file.verify, this.key), Buffer.from(VERIFY_PLAINTEXT, "utf8"))) throw new Error("device unlock failed");
    } else this.key = await deriveKey(this.masterPassword, this.kdf);
    this.locked = false; this.lastActivity = Date.now();
  }
  async loadWithKey(key) {
    const { file, created } = await this.readDocument();
    if (created || !Buffer.isBuffer(key) || key.length !== KEY_LENGTH) throw new Error("device unlock unavailable");
    this.kdf = file.kdf;
    try {
      if (!safeEqual(decrypt(file.verify, key), Buffer.from(VERIFY_PLAINTEXT, "utf8"))) throw new Error("invalid");
      for (const blob of file.entries) { const entry = JSON.parse(decrypt(blob, key).toString("utf8")); normalizeTimestamps(entry); this.entries.set(entry.id, entry); }
      this.history.push(...await this.readAuditLog());
    } catch { this.entries.clear(); throw new Error("device unlock failed"); }
    this.key = Buffer.from(key); this.keyMaterial = true; this.locked = false; this.lastActivity = Date.now();
  }
  /**
   * Load the vault document from disk (creating an empty one on first use)
   * and derive the vault key from the document's fixed KDF parameters.
   */
  async load() {
    await mkdir2(dirname2(this.path), { recursive: true, mode: 448 });
    await rm2(`${this.path}.lock`, { force: true }).catch(() => {
    });
    await chmod(dirname2(this.path), 448).catch(() => {
    });
    const { file, created } = await this.readDocument();
    this.kdf = file.kdf;
    this.key = await deriveKey(this.masterPassword, file.kdf);
    if (created) {
      await this.persist();
      this.locked = false;
      this.lastActivity = Date.now();
      return;
    }
    try {
      const verify = decrypt(file.verify, this.key);
      if (!safeEqual(verify, Buffer.from(VERIFY_PLAINTEXT, "utf8"))) {
        throw new Error("vault master password is incorrect");
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes("incorrect")) throw err;
      throw new Error("vault master password is incorrect");
    }
    for (const blob of file.entries) {
      const plaintext = decrypt(blob, this.key);
      const entry = JSON.parse(plaintext.toString("utf8"));
      normalizeTimestamps(entry);
      this.entries.set(entry.id, entry);
    }
    const persistedAudit = await this.readAuditLog();
    if (persistedAudit.length > 0) {
      this.history.push(...persistedAudit);
      if (this.history.length > _VaultStore.AUDIT_CAP) {
        this.history.splice(0, this.history.length - _VaultStore.AUDIT_CAP);
      }
    }
    this.locked = false;
    this.lastActivity = Date.now();
  }
  /** The vault file path (useful for messages and debugging). */
  get filePath() {
    return this.path;
  }
  /** All active (non-trashed) entries, in insertion order. */
  list() {
    return [...this.entries.values()].filter((entry) => entry.deletedAt === void 0);
  }
  /** All trashed entries (soft-deleted, awaiting purge or restore). */
  listTrash() {
    return [...this.entries.values()].filter((entry) => entry.deletedAt !== void 0);
  }
  /** Read one active entry by id. */
  get(id) {
    const entry = this.entries.get(id);
    return entry !== void 0 && entry.deletedAt === void 0 ? entry : void 0;
  }
  /** Read one entry by id, including trashed entries. */
  getIncludingTrash(id) {
    return this.entries.get(id);
  }
  /** Search entries across text fields; returns summaries without secrets.
   * Multiple whitespace-separated terms match when ANY term hits (OR).
   * Results are relevance-ranked: title prefix matches first, then title
   * contains, then any-field matches. */
  search(query, limit = 20) {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length > 0) this.audit("search", void 0, query.trim());
    const ranked = [];
    for (const entry of this.list()) {
      const rank = terms.length === 0 ? 0 : relevanceRank(entry, terms);
      if (rank >= 0) ranked.push({ entry, rank });
    }
    ranked.sort((a, b) => a.rank - b.rank || Number(Boolean(b.entry.favorite)) - Number(Boolean(a.entry.favorite)));
    return ranked.slice(0, limit).map((r) => toSummary(r.entry));
  }
  /** Search using a regular expression (case-insensitive); no secrets in results. */
  searchRegex(pattern, limit = 20) {
    let re;
    try {
      re = new RegExp(pattern, "i");
    } catch {
      return [];
    }
    const results = [];
    for (const entry of this.list()) {
      if (results.length >= limit) break;
      if (regexMatches(entry, re)) results.push(toSummary(entry));
    }
    return results;
  }
  /** Add a new entry; returns the stored entry with its assigned id. Empty
   * strings and empty arrays from the client form are dropped (a blank form
   * field means "not provided", not "store an empty value"). */
  async add(patch) {
    const now = Date.now();
    validatePatchTypes(patch);
    const entry = {
      id: randomUUID(),
      title: patch.title,
      ...pickDefined(patch, { skipEmpty: true }),
      createdAt: now,
      updatedAt: now
    };
    if (patch.rotationDays === 0) {
      delete entry.rotationDays;
    }
    normalizeTimestamps(entry);
    this.entries.set(entry.id, entry);
    this.recordHistory("add", entry.id, entry.title);
    await this.persist();
    return entry;
  }
  /** Pin or unpin an entry (favorite); returns the updated entry or undefined. */
  async setFavorite(id, favorite) {
    const entry = this.entries.get(id);
    if (!entry || entry.deletedAt !== void 0) return void 0;
    if (favorite) entry.favorite = true;
    else delete entry.favorite;
    entry.updatedAt = Date.now();
    await this.persist();
    return entry;
  }
  /** Record one event in the audit trail (oldest first) and schedule a
   * debounced sidecar flush for events that do not ride on a mutation's
   * persist() (mutation events flush synchronously inside persist()). */
  recordHistory(action, id, title) {
    this.history.push({
      action,
      ...id !== void 0 ? { id } : {},
      ...title !== void 0 ? { title } : {},
      at: Date.now()
    });
    if (this.history.length > _VaultStore.AUDIT_CAP) this.history.shift();
    this.scheduleAuditFlush();
  }
  scheduleAuditFlush() {
    if (this.auditFlushTimer !== void 0) return;
    this.auditFlushTimer = setTimeout(() => {
      this.auditFlushTimer = void 0;
      void this.flushAuditLog().catch(() => {
      });
    }, _VaultStore.AUDIT_FLUSH_MS);
    this.auditFlushTimer.unref?.();
  }
  /** Encrypt the current audit trail into the sidecar file. Serialized so a
   * debounced flush and a persist-triggered flush cannot interleave. Each
   * flush writes the newest full trail, so a queued older flush is harmless. */
  flushAuditLog() {
    const run = async () => {
      const key = this.key;
      if (key === void 0 || this.locked || this.history.length === 0) return;
      const retained = this.history.slice(-_VaultStore.AUDIT_CAP);
      const file = {
        kdf: this.kdf,
        events: encrypt(Buffer.from(JSON.stringify(retained), "utf8"), key)
      };
      await mkdir2(dirname2(this.path), { recursive: true, mode: 448 });
      const { writeFileAtomic: writeFileAtomic2 } = await atomicWrite();
      await writeFileAtomic2(this.auditPath, JSON.stringify(file), {
        mode: 384,
        dirMode: 448
      });
    };
    const next = this.auditWriteChain.then(run, run);
    this.auditWriteChain = next.catch(() => {
    });
    return next;
  }
  /** Sidecar file holding the encrypted audit trail (owner-only). */
  get auditPath() {
    return this.path.replace(/\.json$/i, "-audit.json");
  }
  /** Read and decrypt the audit sidecar; tolerates absence and corruption
   * (a damaged audit log must never block vault access — it is rewritten on
   * the next flush). */
  async readAuditLog() {
    let raw;
    try {
      raw = await readFile(this.auditPath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw error;
    }
    try {
      const key = this.key;
      if (key === void 0) return [];
      const file = JSON.parse(raw);
      if (!file || !file.events || typeof file.events !== "object") return [];
      const plaintext = decrypt(file.events, key);
      const parsed = JSON.parse(plaintext.toString("utf8"));
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((e) => typeof e === "object" && e !== null && typeof e.action === "string");
    } catch (error) {
      console.warn("dsh-vault: audit log unreadable \u2014 starting a fresh log", error?.message ?? "");
      return [];
    }
  }
  /** Public audit hook for host-layer read operations (vault_get, UI get,
   * TOTP generation, searches, vault switches). SECURITY: callers must only
   * pass the entry's *title* (user-chosen metadata) — never a username,
   * password, key, token, OTP secret or any other secret value. */
  audit(action, id, title) {
    if (title !== void 0 && title.length > 80) title = title.slice(0, 80);
    this.recordHistory(action, id, title);
  }
  /** Recent mutation history (audit trail), newest first. No secrets. */
  getHistory() {
    return [...this.history].reverse();
  }
  /** Insert an entry directly (used by bulk import); caller owns timestamps. */
  insertDirect(entry) {
    this.entries.set(entry.id, entry);
  }
  /** Update an existing entry's fields; returns the updated entry or undefined.
   * Every defined field in `patch` replaces the stored value; an empty string
   * clears (removes) that field. `id`/`createdAt` can never change. */
  async update(id, patch) {
    const current = this.entries.get(id);
    if (!current) return void 0;
    if ("title" in patch && (patch.title ?? "").trim().length === 0) {
      throw new Error("vault: title must not be empty");
    }
    validatePatchTypes(patch);
    const updated = {
      ...current,
      ...pickDefined(patch, { allowTitle: true }),
      updatedAt: Date.now()
    };
    const record = updated;
    for (const key of Object.keys(patch)) {
      if (patch[key] === "") {
        delete record[key];
      }
    }
    this.entries.set(id, updated);
    const record2 = updated;
    if ("rotationDays" in patch && (patch.rotationDays ?? 0) === 0) {
      delete record2.rotationDays;
    }
    if ("expiresAt" in patch && (patch.expiresAt ?? 0) === 0) {
      delete record2.expiresAt;
    }
    if ("password" in patch && typeof patch.password === "string" && patch.password.length > 0 && current.password !== void 0 && current.password !== patch.password) {
      const newest = (current.passwordHistory ?? []).reduce((m, h) => Math.max(m, h.at), 0);
      const at = Math.max(Date.now(), newest + 1);
      const history = [...current.passwordHistory ?? [], { password: current.password, at }].sort((a, b) => b.at - a.at).slice(0, _VaultStore.MAX_PASSWORD_HISTORY);
      updated.passwordHistory = history;
    }
    if ("envKey" in patch && patch.envKey === "") {
      delete updated.envKeys;
    }
    normalizeTimestamps(updated);
    this.recordHistory("update", id, updated.title);
    await this.persist();
    return updated;
  }
  /** Soft-delete an entry (move to trash); returns true when it existed.
   * The entry stays encrypted on disk until purged or restored. */
  async delete(id) {
    const entry = this.entries.get(id);
    if (!entry || entry.deletedAt !== void 0) return false;
    entry.deletedAt = Date.now();
    this.recordHistory("delete", id, entry.title);
    await this.persist();
    return true;
  }
  /** Restore a trashed entry; returns true when it existed in trash. */
  async restore(id) {
    const entry = this.entries.get(id);
    if (!entry || entry.deletedAt === void 0) return false;
    delete entry.deletedAt;
    this.recordHistory("restore", id, entry.title);
    await this.persist();
    return true;
  }
  /** Undo the most recent delete: restore the trashed entry deleted last.
   * Returns the restored summary (or undefined when the trash is empty). */
  async restoreRecent() {
    const trashed = this.listTrash().sort((a, b) => (b.deletedAt ?? 0) - (a.deletedAt ?? 0) || b.id.localeCompare(a.id));
    const latest = trashed[0];
    if (!latest) return void 0;
    delete latest.deletedAt;
    this.recordHistory("restore", latest.id, latest.title);
    await this.persist();
    return toSummary(latest);
  }
  /** Permanently remove a trashed (or active) entry; returns true when it existed. */
  async purge(id) {
    const existed = this.entries.delete(id);
    if (existed) {
      this.recordHistory("purge", id);
      await this.persist();
    }
    return existed;
  }
  /** Number of entries. */
  get size() {
    return this.entries.size;
  }
  /** Whether the vault is unlocked (loaded) with a usable key. */
  get unlocked() {
    return this.key !== void 0;
  }
  /**
   * Rotation & expiry report: entries whose `rotationDays` elapsed since
   * their last update, or whose `expiresAt` is near/past. Returns only
   * summaries plus the computed due state (no secrets).
   */
  rotationReport(now = Date.now(), soonWindowDays = 7) {
    const report = [];
    for (const entry of this.list()) {
      const base = entry.updatedAt ?? entry.createdAt;
      const rotationDays = entry.rotationDays !== void 0 && entry.rotationDays > 0 ? entry.rotationDays : void 0;
      const rotationAt = rotationDays !== void 0 ? base + rotationDays * 864e5 : void 0;
      const expiresAt = entry.expiresAt;
      let due;
      let daysLeft;
      if (rotationAt !== void 0 && now >= rotationAt) {
        due = "due";
        daysLeft = 0;
      } else if (expiresAt !== void 0 && now >= expiresAt) {
        due = "expired";
        daysLeft = 0;
      } else if (expiresAt !== void 0) {
        daysLeft = Math.ceil((expiresAt - now) / 864e5);
        if (daysLeft <= soonWindowDays) {
          due = "soon";
        }
      } else if (rotationAt !== void 0) {
        daysLeft = Math.ceil((rotationAt - now) / 864e5);
        if (daysLeft <= soonWindowDays) {
          due = "soon";
        }
      } else {
        continue;
      }
      if (due === void 0) continue;
      report.push({ ...toSummary(entry), due, daysLeft });
    }
    const severity = { expired: 0, due: 1, soon: 2 };
    return report.sort((a, b) => severity[a.due] - severity[b.due] || a.daysLeft - b.daysLeft);
  }
  /** Advanced multi-criteria search: title/username/kind/tag text + created-after. */
  advancedSearch(criteria) {
    const limit = criteria.limit ?? 20;
    const t = criteria.title?.toLowerCase();
    const u = criteria.username?.toLowerCase();
    const results = [];
    for (const entry of this.list()) {
      if (results.length >= limit) break;
      if (t !== void 0 && !entry.title.toLowerCase().includes(t)) continue;
      if (u !== void 0 && !(entry.username ?? entry.email ?? "").toLowerCase().includes(u)) continue;
      if (criteria.kind !== void 0 && (entry.kind ?? "login") !== criteria.kind) continue;
      if (criteria.tag !== void 0 && !(entry.tags ?? []).includes(criteria.tag)) continue;
      if (criteria.createdAfter !== void 0 && entry.createdAt < criteria.createdAfter) continue;
      if (criteria.createdBefore !== void 0 && entry.createdAt > criteria.createdBefore) continue;
      if (criteria.favoriteOnly === true && entry.favorite !== true) continue;
      results.push(toSummary(entry));
    }
    return results;
  }
  /** Vault overview statistics (1Password-style): counts by kind, TOTP,
   * high-sensitivity, expired entries. No secrets. */
  stats() {
    const byKind = {};
    const byTag = {};
    let withTotp = 0;
    let withPrivateKey = 0;
    let highSensitivity = 0;
    let expired = 0;
    let recent7d = 0;
    const now = Date.now();
    const weekAgo = now - 7 * 864e5;
    const byTitle = /* @__PURE__ */ new Map();
    for (const entry of this.list()) {
      byTitle.set(entry.title.toLowerCase(), (byTitle.get(entry.title.toLowerCase()) ?? 0) + 1);
    }
    let duplicates = 0;
    for (const count of byTitle.values()) if (count > 1) duplicates++;
    for (const entry of this.list()) {
      const kind = entry.kind ?? "login";
      byKind[kind] = (byKind[kind] ?? 0) + 1;
      for (const tag of entry.tags ?? []) byTag[tag] = (byTag[tag] ?? 0) + 1;
      if (entry.otpSecret !== void 0) withTotp++;
      if (entry.privateKey !== void 0) withPrivateKey++;
      if (entry.sensitivity === "high") highSensitivity++;
      if (entry.expiresAt !== void 0 && entry.expiresAt < now) expired++;
      if (entry.createdAt >= weekAgo) recent7d++;
    }
    return { total: this.list().length, byKind, byTag, withTotp, withPrivateKey, highSensitivity, expired, recent7d, trashCount: this.listTrash().length, duplicates, favoriteCount: this.list().filter((e) => e.favorite === true).length };
  }
  /** Merge `fromId` into `toId`: non-empty fields of `from` fill gaps in `to`,
   * then `from` is purged. Returns the merged entry or undefined. */
  async merge(fromId, toId, options = {}) {
    const from = this.entries.get(fromId);
    const to = this.entries.get(toId);
    if (!from || !to || from.deletedAt !== void 0 || to.deletedAt !== void 0) return void 0;
    const merged = { ...to };
    for (const [key, value] of Object.entries(from)) {
      const typed = merged;
      const existing = typed[key];
      if ((existing === void 0 || existing === "") && value !== void 0 && value !== "") {
        ;
        typed[key] = value;
      }
    }
    merged.updatedAt = Date.now();
    this.entries.set(toId, merged);
    if (options.keepSource !== true) {
      this.entries.delete(fromId);
    }
    this.recordHistory("merge", toId, to.title);
    await this.persist();
    return merged;
  }
  /** Touch an entry's updatedAt (mark as recently used); no other change. */
  async markUsed(id) {
    const entry = this.entries.get(id);
    if (!entry || entry.deletedAt !== void 0) return void 0;
    entry.updatedAt = Date.now();
    await this.persist();
    return entry;
  }
  /** The password history of an entry (newest first), or [] when none. */
  passwordHistoryOf(id) {
    const entry = this.entries.get(id);
    if (!entry) return [];
    return [...entry.passwordHistory ?? []].sort((a, b) => b.at - a.at);
  }
  /** Roll the entry's password back to a stored history entry (by `at` epoch
   * millis). The current password is pushed onto the history first (so the
   * rollback itself is reversible). Returns the updated entry. */
  async rollbackPassword(id, at) {
    const entry = this.entries.get(id);
    if (!entry) return void 0;
    const history = [...entry.passwordHistory ?? []].sort((a, b) => b.at - a.at);
    const target = history.find((h) => h.at === at);
    if (target === void 0) return void 0;
    const currentPassword = entry.password;
    const next = [...history.filter((h) => h.at !== at), ...currentPassword !== void 0 ? [{ password: currentPassword, at: Date.now() }] : []].sort((a, b) => b.at - a.at).slice(0, _VaultStore.MAX_PASSWORD_HISTORY);
    const updated = { ...entry, password: target.password, passwordHistory: next, updatedAt: Date.now() };
    this.entries.set(id, updated);
    this.recordHistory("rollback", id, updated.title);
    await this.persist();
    return updated;
  }
  /** Activity within the last `windowMs`: entries created, updated, or
   * soft-deleted in that window, with their action. No secrets. */
  changes(windowMs = 24 * 60 * 60 * 1e3, now = Date.now()) {
    const since = now - windowMs;
    const out = [];
    for (const entry of this.entries.values()) {
      if (entry.deletedAt !== void 0) {
        if (entry.deletedAt >= since) out.push({ ...toSummary(entry), action: "deleted", at: entry.deletedAt });
      } else if (entry.createdAt >= since && entry.updatedAt - entry.createdAt < 6e4) {
        out.push({ ...toSummary(entry), action: "created", at: entry.createdAt });
      } else if (entry.updatedAt >= since) {
        out.push({ ...toSummary(entry), action: "updated", at: entry.updatedAt });
      }
    }
    return out.sort((a, b) => b.at - a.at);
  }
  /** Most recently created/updated entries (Bitwarden-style "recent"),
   * returned as summaries without secrets. */
  recent(limit = 10) {
    return [...this.list()].sort((a, b) => b.updatedAt - a.updatedAt).slice(0, limit).map(toSummary);
  }
  /**
   * Health scan: weak passwords (too short), and passwords/API keys reused
   * across entries. Returns non-secret findings keyed by entry id.
   */
  health() {
    const weak = [];
    const strength = { weak: 0, fair: 0, strong: 0 };
    const no2fa = [];
    const httpSites = [];
    const passwordCounts = /* @__PURE__ */ new Map();
    const keyCounts = /* @__PURE__ */ new Map();
    const now = Date.now();
    for (const entry of this.list()) {
      const summary = toSummary(entry);
      const kind = entry.kind ?? "login";
      if (entry.password !== void 0 && (kind === "login" || kind === "ssh") && entry.otpSecret === void 0) {
        no2fa.push(summary);
      }
      if (typeof entry.url === "string" && /^http:\/\//i.test(entry.url)) {
        httpSites.push(summary);
      }
      if (entry.password !== void 0) {
        const len = entry.password.length;
        if (len < _VaultStore.MIN_PASSWORD_LENGTH) {
          weak.push(summary);
          strength.weak++;
        } else if (len < 20) strength.fair++;
        else strength.strong++;
        const list = passwordCounts.get(entry.password) ?? [];
        list.push(summary);
        passwordCounts.set(entry.password, list);
      }
      for (const key of [entry.apiKey, entry.accessToken, entry.refreshToken, entry.secret]) {
        if (key === void 0) continue;
        const list = keyCounts.get(key) ?? [];
        list.push(summary);
        keyCounts.set(key, list);
      }
      void now;
    }
    const reused = [
      ...[...passwordCounts.entries()].filter(([, v]) => v.length > 1),
      ...[...keyCounts.entries()].filter(([, v]) => v.length > 1)
    ].map(([value, entries]) => ({ value, entries }));
    let score = 100;
    score -= Math.min(weak.length * 10, 40);
    score -= Math.min(reused.length * 15, 30);
    score -= Math.min(no2fa.length * 5, 20);
    score -= Math.min(httpSites.length * 5, 10);
    score -= Math.min([...this.list()].filter((e) => e.expiresAt !== void 0 && e.expiresAt < now).length * 5, 15);
    score = Math.max(0, score);
    const verdict = score >= 80 ? "good" : score >= 50 ? "fair" : "poor";
    return { weak, reused, strength, no2fa, httpSites, score, verdict };
  }
  /**
   * Export the whole vault (including trash) as a single encrypted blob under
   * a separate export password: a portable, machine-independent document that
   * can be re-imported elsewhere. Returns the armored JSON string.
   */
  async exportEncrypted(exportPassword, now = Date.now(), onlyIds) {
    if (exportPassword.length === 0) throw new Error("vault: export password must not be empty");
    const exportKdf = newKdfParams();
    const exportKey = await deriveKey(exportPassword, exportKdf);
    const entries = onlyIds === void 0 ? [...this.entries.values()] : [...this.entries.values()].filter((e) => onlyIds.has(e.id));
    const payload = {
      format: EXPORT_FORMAT_VERSION,
      vaultName: basename(this.path).replace(/\.json$/, ""),
      exportedAt: now,
      kdf: exportKdf,
      entries: entries.map((entry) => ({
        id: entry.id,
        ...encrypt(Buffer.from(JSON.stringify(entry), "utf8"), exportKey)
      }))
    };
    exportKey.fill(0);
    return JSON.stringify(payload);
  }
  /**
   * Import an exported vault blob, merging entries by id (existing entries win
   * unless `overwrite`). Returns the number of entries added.
   */
  async importEncrypted(blob, exportPassword, overwrite = false, dryRun = false) {
    if (exportPassword.length === 0) throw new Error("vault: export password must not be empty");
    const parsed = JSON.parse(blob);
    if (parsed.format !== void 0 && parsed.format > EXPORT_FORMAT_VERSION) {
      throw new Error(`vault: export document format ${parsed.format} is newer than supported ${EXPORT_FORMAT_VERSION} \u2014 upgrade dsh-vault and retry`);
    }
    if (!parsed.kdf || !Array.isArray(parsed.entries)) {
      throw new Error("vault: invalid export document \u2014 expected { kdf, entries[] } from vault_export");
    }
    if (parsed.entries.length === 0) {
      return 0;
    }
    const exportKey = await deriveKey(exportPassword, parsed.kdf);
    let added = 0;
    try {
      for (const blobEntry of parsed.entries) {
        const plaintext = decrypt(blobEntry, exportKey);
        const entry = JSON.parse(plaintext.toString("utf8"));
        const existing = this.entries.get(entry.id);
        if (existing !== void 0 && !overwrite) {
          if (dryRun) {
            added++;
            continue;
          }
          const merged = { ...existing };
          const er = merged;
          for (const [k, v] of Object.entries(entry)) {
            const cur = er[k];
            if ((cur === void 0 || cur === "") && v !== void 0 && v !== "") er[k] = v;
          }
          merged.updatedAt = Date.now();
          delete merged.deletedAt;
          this.entries.set(entry.id, merged);
          added++;
          continue;
        }
        if (dryRun) {
          added++;
          continue;
        }
        const { deletedAt, ...active } = entry;
        this.entries.set(entry.id, { ...active, updatedAt: Date.now() });
        added++;
      }
    } catch {
      throw new Error("vault_import: export password is incorrect or the document is corrupted");
    } finally {
      exportKey.fill(0);
    }
    if (!dryRun) await this.persist();
    return added;
  }
  /**
   * Persist the current in-memory state: encrypt every entry under the vault
   * key, then atomically replace the document under the cross-process lock.
   * Calls are serialized through an in-process chain so concurrent mutations
   * never contend for the lock and each write snapshots the entries visible
   * when it runs — the final file always reflects every completed mutation.
   * The derived key is cached after load and reused, so a mutation does not
   * re-run scrypt; only a fresh vault (no cached key yet) derives once.
   */
  /**
   * Re-key the vault with fresh scrypt KDF parameters (cost upgrade): derive a
   * new key from the master password under `newKdfParams()` and re-encrypt
   * every entry under it, atomically. The old key buffer is wiped. Returns the
   * new cost parameter `n` for reporting.
   */
  async rekey() {
    if (this.keyMaterial) throw new Error("请先使用主密码手动解锁后再更改主密码");
    if (this.key === void 0) {
      await this.load();
    }
    const newKdf = newKdfParams();
    const newKey = await deriveKey(this.masterPassword, newKdf);
    const reEncrypted = [...this.entries.values()].map((entry) => ({
      id: entry.id,
      ...encrypt(Buffer.from(JSON.stringify(entry), "utf8"), newKey)
    }));
    await mkdir2(dirname2(this.path), { recursive: true, mode: 448 });
    const { withFileLock: withFileLock2, writeFileAtomic: writeFileAtomic2 } = await atomicWrite();
    await withFileLock2(this.path, async () => {
      const file = {
        version: VAULT_FORMAT_VERSION,
        kdf: newKdf,
        verify: encrypt(Buffer.from(VERIFY_PLAINTEXT, "utf8"), newKey),
        entries: reEncrypted
      };
      await writeFileAtomic2(this.path, JSON.stringify(file), { mode: 384, dirMode: 448 });
    });
    this.kdf = newKdf;
    this.key?.fill(0);
    this.key = newKey;
    return { n: newKdf.n };
  }
  /**
   * Verify the on-disk vault document: decrypts the verification envelope
   * with the in-memory key and compares the encrypted entry count against the
   * live store. Returns a non-secret integrity verdict.
   */
  async integrity() {
    let fileEntries = 0;
    let verifyOk = false;
    try {
      const raw = await readFile(this.path, "utf8");
      const doc = JSON.parse(raw);
      fileEntries = doc.entries.length;
      if (this.key !== void 0) {
        try {
          decrypt(doc.verify, this.key);
          verifyOk = true;
        } catch {
          verifyOk = false;
        }
      }
    } catch {
      fileEntries = 0;
    }
    const memoryEntries = this.entries.size;
    return { fileEntries, memoryEntries, verifyOk, ok: verifyOk && fileEntries === memoryEntries };
  }
  async persist() {
    const run = async () => {
      const kdf = this.kdf ?? newKdfParams();
      this.kdf = kdf;
      if (this.key === void 0) {
        this.key = await deriveKey(this.masterPassword, kdf);
      }
      const key = this.key;
      await mkdir2(dirname2(this.path), { recursive: true, mode: 448 });
      const { withFileLock: withFileLock2, writeFileAtomic: writeFileAtomic2 } = await atomicWrite();
      await withFileLock2(this.path, async () => {
        const file = {
          version: VAULT_FORMAT_VERSION,
          kdf,
          verify: encrypt(Buffer.from(VERIFY_PLAINTEXT, "utf8"), key),
          entries: [...this.entries.values()].map((entry) => ({
            id: entry.id,
            ...encrypt(Buffer.from(JSON.stringify(entry), "utf8"), key)
          }))
        };
        await writeFileAtomic2(this.path, JSON.stringify(file), {
          mode: 384,
          dirMode: 448
        });
      });
      await this.flushAuditLog();
    };
    const next = this.persistChain.then(run, run);
    this.persistChain = next.catch(() => {
    });
    return next;
  }
  /** Read and parse the vault document, tolerating first-run absence. */
  async readDocument() {
    let raw;
    try {
      raw = await readFile(this.path, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        return { file: { version: VAULT_FORMAT_VERSION, kdf: newKdfParams(), verify: EMPTY_BLOB, entries: [] }, created: true };
      }
      throw error;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`${this.path} is not valid JSON \u2014 it is corrupt or not a vault file`);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`${this.path} is not a vault file (expected a JSON object)`);
    }
    if (parsed.version !== VAULT_FORMAT_VERSION) {
      throw new Error(`${this.path} has unsupported vault format version ${JSON.stringify(parsed.version)} (expected ${VAULT_FORMAT_VERSION})`);
    }
    if (!parsed.kdf || parsed.kdf.algo !== "scrypt" || !parsed.kdf.saltHex) {
      throw new Error(`${this.path} is missing valid KDF parameters`);
    }
    if (!parsed.verify) {
      throw new Error(`${this.path} is missing its password-verification envelope`);
    }
    return { file: parsed, created: false };
  }
};
var EMPTY_BLOB = { ivHex: "", tagHex: "", dataHex: "" };
function relevanceRank(entry, terms) {
  const title = entry.title.toLowerCase();
  const primary = terms[0];
  if (title.startsWith(primary)) return 0;
  if (title.includes(primary)) return 1;
  return terms.some((term) => matches(entry, term)) ? 2 : -1;
}
function regexMatches(entry, re) {
  const fieldValues = [];
  collectSearchable(entry.fields ?? {}, fieldValues);
  const haystack = [
    entry.title,
    entry.kind,
    entry.username,
    entry.email,
    entry.phone,
    entry.host,
    entry.port,
    entry.url,
    entry.notes,
    ...entry.tags ?? [],
    ...fieldValues
  ].filter(Boolean).join("\n");
  re.lastIndex = 0;
  return re.test(haystack);
}
function matches(entry, needle) {
  const fieldValues = [];
  collectSearchable(entry.fields ?? {}, fieldValues);
  return [
    entry.title,
    entry.kind,
    entry.username,
    entry.email,
    entry.phone,
    entry.host,
    entry.port,
    entry.url,
    entry.notes,
    ...entry.tags ?? [],
    ...fieldValues
  ].some((value) => value?.toLowerCase().includes(needle));
}
function collectSearchable(value, out) {
  if (typeof value === "string") {
    out.push(value);
  } else if (typeof value === "number" || typeof value === "boolean") {
    out.push(String(value));
  } else if (Array.isArray(value)) {
    for (const item of value) collectSearchable(item, out);
  } else if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) collectSearchable(item, out);
  }
}
function toSummary(entry) {
  return {
    id: entry.id,
    title: entry.title,
    updatedAt: entry.updatedAt,
    ...entry.sensitivity !== void 0 ? { sensitivity: entry.sensitivity } : {},
    ...entry.favorite !== void 0 ? { favorite: entry.favorite } : {},
    ...entry.icon !== void 0 ? { icon: entry.icon } : {},
    ...entry.color !== void 0 ? { color: entry.color } : {},
    ...entry.kind !== void 0 ? { kind: entry.kind } : {},
    ...entry.username !== void 0 ? { username: entry.username } : {},
    ...entry.email !== void 0 ? { email: entry.email } : {},
    ...entry.phone !== void 0 ? { phone: entry.phone } : {},
    ...entry.host !== void 0 ? { host: entry.host } : {},
    ...entry.port !== void 0 ? { port: entry.port } : {},
    ...entry.url !== void 0 ? { url: entry.url } : {},
    ...entry.tags !== void 0 ? { tags: entry.tags } : {},
    ...entry.cardExpiry !== void 0 ? { cardExpiry: entry.cardExpiry } : {},
    ...entry.cardHolder !== void 0 ? { cardHolder: entry.cardHolder } : {},
    ...entry.otpSecret !== void 0 ? { hasOtp: true } : {},
    ...entry.attachments !== void 0 && Object.keys(entry.attachments).length > 0 ? { attachmentCount: Object.keys(entry.attachments).length } : {},
    ...Array.isArray(entry.cookies) ? { cookieCount: entry.cookies.length } : {},
    ...entry.fields !== void 0 && Object.keys(entry.fields).length > 0 ? { fields: entry.fields } : {}
  };
}
function validatePatchTypes(patch) {
  const kindSet = /* @__PURE__ */ new Set(["login", "ssh", "api-key", "secret", "oauth", "cookie", "card", "custom"]);
  for (const [key, value] of Object.entries(patch)) {
    if (value === void 0 || value === "") continue;
    switch (key) {
      case "kind":
        if (typeof value !== "string" || !kindSet.has(value)) {
          throw new Error(`vault: kind must be one of ${[...kindSet].join(", ")}`);
        }
        break;
      case "sensitivity":
        if (value !== "normal" && value !== "high") {
          throw new Error('vault: sensitivity must be "normal" or "high"');
        }
        break;
      case "rotationDays":
      case "expiresAt":
        if (typeof value !== "number" || !Number.isFinite(value)) {
          throw new Error(`vault: ${key} must be a finite number`);
        }
        break;
      case "envKey":
        if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
          throw new Error("vault: envKey must match [A-Za-z_][A-Za-z0-9_]* (e.g. DASHSCOPE_API_KEY)");
        }
        break;
      case "envKeys":
        if (!Array.isArray(value) || value.length > MAX_ENV_KEYS) {
          throw new Error(`vault: envKeys must be an array of at most ${MAX_ENV_KEYS} names`);
        }
        for (const name of value) {
          if (typeof name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
            throw new Error(`vault: envKeys entries must match [A-Za-z_][A-Za-z0-9_]* (got ${JSON.stringify(name)})`);
          }
        }
        if (new Set(value).size !== value.length) {
          throw new Error("vault: envKeys must not repeat a name");
        }
        break;
      case "port":
        if (typeof value !== "string" && typeof value !== "number") {
          throw new Error("vault: port must be a string or number");
        }
        break;
      case "favorite":
        if (typeof value !== "boolean") {
          throw new Error("vault: favorite must be a boolean");
        }
        break;
      case "icon":
      case "color":
      case "cardNumber":
      case "cardExpiry":
      case "cardCvv":
      case "cardHolder":
        if (typeof value !== "string") throw new Error(`vault: ${key} must be a string`);
        break;
      case "tags":
        if (!Array.isArray(value) || value.some((t) => typeof t !== "string")) {
          throw new Error("vault: tags must be an array of strings");
        }
        break;
      case "cookies":
        if (!Array.isArray(value) || value.some((c) => typeof c !== "object" || c === null || typeof c.name !== "string" || typeof c.value !== "string" || typeof c.domain !== "string")) {
          throw new Error("vault: cookies must be an array of { name, value, domain, \u2026 }");
        }
        break;
      case "passwordHistory":
        if (!Array.isArray(value) || value.some((h) => typeof h !== "object" || h === null || typeof h.password !== "string" || typeof h.at !== "number")) {
          throw new Error("vault: passwordHistory must be an array of { password, at }");
        }
        break;
      case "attachments":
        if (typeof value !== "object" || value === null || Array.isArray(value)) {
          throw new Error("vault: attachments must be an object");
        }
        for (const [name, att] of Object.entries(value)) {
          const a = att;
          if (typeof att !== "object" || att === null || typeof a.data !== "string" || typeof a.size !== "number") {
            throw new Error(`vault: attachment "${name}" must be { data, size, \u2026 }`);
          }
        }
        break;
      case "fields":
        if (typeof value !== "object" || value === null || Array.isArray(value)) {
          throw new Error("vault: fields must be an object");
        }
        break;
    }
  }
}
function pickDefined(patch, options = {}) {
  const result = {};
  for (const [key, value] of Object.entries(patch)) {
    const identityField = key === "id" || key === "createdAt" || key === "updatedAt" || !options.allowTitle && key === "title";
    if (value === void 0 || identityField) continue;
    if (options.skipEmpty && (value === "" || Array.isArray(value) && value.length === 0)) continue;
    result[key] = value;
  }
  return result;
}
var atomicWriteModule;
async function atomicWrite() {
  if (atomicWriteModule !== void 0) return atomicWriteModule;
  try {
    atomicWriteModule = await Promise.resolve().then(() => (init_atomic_write(), atomic_write_exports));
    return atomicWriteModule;
  } catch {
    throw new Error("dsh-vault: writing needs the DSH runtime (@deepseek-ai/dsh-atomic-write is not installed); reads work standalone");
  }
}
var MAX_ENV_KEYS = 8;
function normalizeEnvKeys(record) {
  const legacy = record.envKey;
  const list = record.envKeys;
  if (Array.isArray(list)) {
    const clean = list.filter((name) => typeof name === "string" && name.length > 0);
    if (clean.length > 0) record.envKeys = clean;
    else delete record.envKeys;
  }
  if (typeof legacy === "string" && legacy.length > 0) {
    const current = Array.isArray(record.envKeys) ? record.envKeys : [];
    if (!current.includes(legacy)) record.envKeys = [legacy, ...current];
  }
  delete record.envKey;
}
function normalizeTimestamps(record) {
  normalizeEnvKeys(record);
  for (const key of ["expiresAt", "rotationDays"]) {
    const value = record[key];
    if (value === void 0 || value === null) continue;
    const n = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(n) || n <= 0) delete record[key];
    else record[key] = n;
  }
}

// src/totp.ts
import { createHmac, randomBytes as randomBytes3 } from "node:crypto";
var DEFAULT_PERIOD_SECONDS = 30;
var DEFAULT_DIGITS = 6;
var BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  const cleaned = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
  if (cleaned.length === 0) {
    throw new Error("invalid Base32 secret: secret is empty");
  }
  if (cleaned.length < 8) {
    throw new Error("invalid Base32 secret: too short (expected at least 8 characters)");
  }
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw new Error("invalid Base32 secret: contains characters outside A-Z2-7");
  }
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error(`invalid Base32 character: ${char}`);
    value = value << 5 | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push(value >>> bits - 8 & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
function digitsOf(raw) {
  if (raw === void 0) return DEFAULT_DIGITS;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isInteger(parsed) && parsed >= 6 && parsed <= 10) return parsed;
  return DEFAULT_DIGITS;
}
function periodOf(raw) {
  if (raw === void 0) return DEFAULT_PERIOD_SECONDS;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isInteger(parsed) && parsed >= 5) return parsed;
  return DEFAULT_PERIOD_SECONDS;
}
function parseTotpSecret(input) {
  const trimmed = input.trim();
  if (trimmed.startsWith("otpauth://")) {
    const url = new URL(trimmed);
    if (url.protocol !== "otpauth:" || url.host !== "totp") {
      throw new Error("unsupported otpauth URI: only otpauth://totp is supported");
    }
    const secret = url.searchParams.get("secret");
    if (!secret) throw new Error("otpauth URI is missing the secret parameter");
    const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
    const colon = label.indexOf(":");
    const issuer = url.searchParams.get("issuer") ?? (colon >= 0 ? label.slice(0, colon) : void 0);
    const account = colon >= 0 ? label.slice(colon + 1) : label;
    return {
      secret,
      periodSeconds: periodOf(url.searchParams.get("period") ?? void 0),
      digits: digitsOf(url.searchParams.get("digits") ?? void 0),
      ...issuer !== void 0 ? { issuer } : {},
      ...account !== void 0 && account.length > 0 ? { account } : {}
    };
  }
  return {
    secret: trimmed,
    periodSeconds: DEFAULT_PERIOD_SECONDS,
    digits: DEFAULT_DIGITS
  };
}
function hotp(secret, counter, digits) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(Math.floor(counter)));
  const hmac = createHmac("sha1", secret).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 15;
  const binary = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}
function totp(input, nowMs = Date.now()) {
  const parsed = parseTotpSecret(input);
  const key = base32Decode(parsed.secret);
  const counter = Math.floor(nowMs / 1e3 / parsed.periodSeconds);
  return hotp(key, counter, parsed.digits);
}
function bytesToBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = value << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[value >>> bits - 5 & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[value << 5 - bits & 31];
  }
  return output;
}
function generateTotpSecret() {
  return bytesToBase32(randomBytes3(20));
}

// src/password.ts
import { randomInt } from "node:crypto";
var LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
var UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
var DIGITS = "0123456789";
var SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~";
function filterPool(options) {
  const pools = [];
  if (options.lowercase) pools.push(LOWERCASE);
  if (options.uppercase) pools.push(UPPERCASE);
  if (options.digits) pools.push(DIGITS);
  if (options.symbols) pools.push(SYMBOLS);
  const classes = options.excludeAmbiguous ? pools.map((pool) => [...pool].filter((char) => !AMBIGUOUS_CHARS.has(char)).join("")) : pools;
  return { merged: classes.join(""), classes };
}
var AMBIGUOUS_CHARS = new Set("0O1lI");
function generatePassword(options = {}) {
  const length = options.length ?? 20;
  const config = {
    lowercase: options.lowercase ?? true,
    uppercase: options.uppercase ?? true,
    digits: options.digits ?? true,
    symbols: options.symbols ?? true,
    excludeAmbiguous: options.excludeAmbiguous ?? false
  };
  const { merged, classes } = filterPool(config);
  const selected = classes.filter((pool) => pool.length > 0);
  if (selected.length === 0) throw new Error("password generation requires at least one character class");
  if (!Number.isInteger(length) || length < 1) throw new Error("password length must be a positive integer");
  if (length < selected.length) {
    throw new Error(`password length ${length} is shorter than the ${selected.length} selected character classes`);
  }
  if (options.group !== void 0 && (!Number.isInteger(options.group) || options.group < 2)) {
    throw new Error("password group must be an integer >= 2 when provided");
  }
  const chars = selected.map((pool) => pool[randomInt(pool.length)]);
  const source = merged.length > 0 ? merged : selected[0];
  while (chars.length < length) {
    chars.push(source[randomInt(source.length)]);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  let password = chars.join("");
  const coreLength = length;
  void coreLength;
  if (options.prefix !== void 0 && options.prefix.length > 0) {
    password = options.prefix + password;
  }
  if (options.suffix !== void 0 && options.suffix.length > 0) {
    password = password + options.suffix;
  }
  if (options.group !== void 0 && options.group > 1 && password.length > options.group) {
    password = password.match(new RegExp(`.{1,${options.group}}`, "g")).join("-");
  }
  return password;
}
var PASSPHRASE_WORDS = [
  "abacus",
  "acorn",
  "alpine",
  "anchor",
  "apricot",
  "archer",
  "aspen",
  "autumn",
  "bamboo",
  "banyan",
  "beacon",
  "birch",
  "biscuit",
  "blossom",
  "bravo",
  "breeze",
  "cactus",
  "canyon",
  "cascade",
  "cedar",
  "charm",
  "cherry",
  "cinder",
  "cobalt",
  "coral",
  "cricket",
  "crimson",
  "crystal",
  "cypress",
  "dahlia",
  "dandelion",
  "delta",
  "denim",
  "diamond",
  "dolphin",
  "drift",
  "eagle",
  "ember",
  "falcon",
  "fennel",
  "ferret",
  "fjord",
  "flint",
  "foxtrot",
  "garden",
  "garnet",
  "gecko",
  "ginkgo",
  "glacier",
  "granite",
  "gull",
  "harbor",
  "hazel",
  "heron",
  "honey",
  "horizon",
  "iris",
  "island",
  "ivory",
  "jaguar",
  "jasmine",
  "juniper",
  "kayak",
  "kestrel",
  "lagoon",
  "larch",
  "lilac",
  "lotus",
  "magpie",
  "maple",
  "marble",
  "meadow",
  "mentor",
  "mosaic",
  "nectar",
  "nimbus",
  "oak",
  "obsidian",
  "olive",
  "onyx",
  "orchid",
  "otter",
  "panda",
  "papaya",
  "pebble",
  "pepper",
  "phoenix",
  "pine",
  "plum",
  "quartz",
  "quill",
  "raven",
  "reed",
  "river",
  "robin",
  "ruby",
  "saffron",
  "sage",
  "salamander",
  "sand",
  "sapphire",
  "sequoia",
  "shale",
  "silver",
  "snow",
  "sparrow",
  "spruce",
  "starling",
  "stone",
  "sunset",
  "tiger",
  "topaz",
  "tulip",
  "umber",
  "velvet",
  "violet",
  "walnut",
  "willow",
  "winter",
  "xenon",
  "yarrow",
  "zephyr",
  "zinnia"
];
function generatePassphrase(options = {}) {
  const words = options.words ?? 4;
  const separator = options.separator ?? "-";
  const withDigits = options.wordDigits ?? true;
  if (!Number.isInteger(words) || words < 2 || words > 12) {
    throw new Error("passphrase: words must be an integer 2\u201312");
  }
  if (separator.length === 0) throw new Error("passphrase: separator must not be empty");
  const parts = [];
  for (let i = 0; i < words; i++) {
    parts.push(PASSPHRASE_WORDS[randomInt(PASSPHRASE_WORDS.length)]);
  }
  let phrase = parts.join(separator);
  if (withDigits) phrase += separator + String(randomInt(10)) + String(randomInt(10));
  return phrase;
}

// src/breach.ts
import { createHash } from "node:crypto";
var HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";
var QUERY_TIMEOUT_MS = 12e3;
var CACHE_TTL_MS = 60 * 60 * 1e3;
var WEAK_PASSWORDS = /* @__PURE__ */ new Set([
  "123456",
  "password",
  "12345678",
  "qwerty",
  "123456789",
  "12345",
  "1234",
  "111111",
  "1234567",
  "dragon",
  "123123",
  "baseball",
  "abc123",
  "football",
  "monkey",
  "letmein",
  "shadow",
  "master",
  "666666",
  "qwertyuiop",
  "123321",
  "mustang",
  "1234567890",
  "michael",
  "654321",
  "superman",
  "1qaz2wsx",
  "7777777",
  "121212",
  "000000",
  "qazwsx",
  "123qwe",
  "killer",
  "trustno1",
  "jordan",
  "jennifer",
  "zxcvbnm",
  "asdfgh",
  "hunter",
  "buster",
  "soccer",
  "harley",
  "batman",
  "andrew",
  "tigger",
  "sunshine",
  "iloveyou",
  "2000",
  "charlie",
  "robert",
  "thomas",
  "hockey",
  "ranger",
  "daniel",
  "starwars",
  "klaster",
  "112233",
  "george",
  "computer",
  "michelle",
  "jessica",
  "pepper",
  "1111",
  "zxcvbn",
  "555555",
  "11111111",
  "131313",
  "freedom",
  "777777",
  "pass",
  "fuck",
  "maggie",
  "159753",
  "aaaaaa",
  "ginger",
  "princess",
  "joshua",
  "cheese",
  "amanda",
  "summer",
  "love",
  "ashley",
  "nicole",
  "chelsea",
  "biteme",
  "matthew",
  "access",
  "yankees",
  "987654321",
  "dallas",
  "austin",
  "thunder",
  "taylor",
  "matrix",
  "mobilemail",
  "mom",
  "monitor",
  "monitoring",
  "montana",
  "moon",
  "moscow"
]);
var rangeCache = /* @__PURE__ */ new Map();
function sha1Hex(password) {
  return createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
}
async function queryRange(prefix) {
  const res = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
    signal: AbortSignal.timeout(QUERY_TIMEOUT_MS),
    headers: {
      "User-Agent": "dsh-vault",
      // HIBP's own privacy knob: pad every response to a similar size so an
      // observer cannot correlate a lookup with how many passwords share that
      // prefix (which would leak information about how common yours is).
      "Add-Padding": "true"
    }
  });
  if (!res.ok) throw new Error(`Pwned Passwords returned HTTP ${res.status}`);
  const text = await res.text();
  const suffixes = /* @__PURE__ */ new Set();
  for (const line of text.split("\n")) {
    const suffix = line.split(":")[0];
    if (suffix) suffixes.add(suffix.toLowerCase());
  }
  return suffixes;
}
async function checkPassword(password, now = Date.now()) {
  if (typeof password !== "string" || password.length === 0) {
    return { breached: false, count: 0, source: "none" };
  }
  if (WEAK_PASSWORDS.has(password.toLowerCase())) {
    return { breached: true, reason: "weak", count: 0, source: "local" };
  }
  const hash = sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5).toLowerCase();
  const cached = rangeCache.get(prefix);
  if (cached !== void 0 && now - cached.at < CACHE_TTL_MS && cached.suffixes !== null) {
    return {
      breached: cached.suffixes.has(suffix),
      reason: cached.suffixes.has(suffix) ? "pwned" : void 0,
      count: cached.suffixes.has(suffix) ? 1 : 0,
      source: "hibp"
    };
  }
  try {
    const suffixes = await queryRange(prefix);
    rangeCache.set(prefix, { at: now, suffixes });
    const hit = suffixes.has(suffix);
    return { breached: hit, reason: hit ? "pwned" : void 0, count: hit ? 1 : 0, source: "hibp" };
  } catch {
    return { breached: false, count: 0, source: "local" };
  }
}
function clearCache() {
  rangeCache.clear();
}

// src/password-strength.ts
function deLeet(password) {
  return password.toLowerCase().replace(/[4@]/g, "a").replace(/[3€]/g, "e").replace(/[1!|]/g, "i").replace(/0/g, "o").replace(/[5$]/g, "s").replace(/7\+/g, "t");
}
function coreLetters(password) {
  return password.toLowerCase().replace(/^[^a-z]+|[^a-z]+$/g, "");
}
var KEYBOARD_RUNS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsx", "1qaz2wsx"];
var SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "01234567890"];
function hasRun(text, source) {
  for (let i = 0; i + 4 <= text.length; i++) {
    const chunk = text.slice(i, i + 4);
    if (source.includes(chunk)) return true;
    if (source.includes([...chunk].reverse().join(""))) return true;
  }
  return false;
}
function isRepeatedBlock(password) {
  for (let size = 1; size <= Math.floor(password.length / 3); size++) {
    const block = password.slice(0, size);
    if (block.repeat(Math.ceil(password.length / size)).slice(0, password.length) === password) return true;
  }
  return false;
}
function hasDate(text) {
  if (/(19|20)\d{2}/.test(text)) return true;
  return /\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}/.test(text);
}
function estimateStrength(password, common = WEAK_PASSWORDS) {
  const feedback = [];
  const patterns = [];
  const lower = password.toLowerCase();
  const deLeeted = deLeet(password);
  const letters = coreLetters(password);
  let score = Math.min(45, password.length * 3);
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  score += classes * 8;
  score += Math.min(15, new Set(password).size);
  if (password.length < 8) feedback.push("too short (aim \u2265 12)");
  if (/^\d+$/.test(password)) {
    score -= 15;
    feedback.push("digits only");
  } else if (/^[a-z]+$/i.test(password)) {
    score -= 10;
    feedback.push("letters only");
  }
  if (/(.)\1{2,}/.test(password)) {
    score -= 8;
    patterns.push("repeats");
    feedback.push("repeated characters");
  }
  const long = password.length >= 20;
  let cap = 100;
  const isCommon = (value) => common.has(value) || common.has(deLeet(value));
  if (isCommon(lower) || isCommon(deLeeted)) {
    cap = Math.min(cap, 5);
    patterns.push("common");
    feedback.push("found in common-password lists");
  } else if (letters.length >= 4 && isCommon(letters)) {
    cap = Math.min(cap, long ? 50 : 25);
    patterns.push("common-word");
    feedback.push("a common password with numbers or symbols around it");
  } else if (/^[a-z]{5,}\d{1,4}!?$/i.test(password) || /^\d{1,4}[a-z]{5,}!?$/i.test(password)) {
    cap = Math.min(cap, long ? 65 : 45);
    patterns.push("word+digits");
    feedback.push("looks like a word plus digits \u2014 a dictionary attack covers it");
  }
  if (KEYBOARD_RUNS.some((run) => hasRun(lower, run))) {
    cap = Math.min(cap, long ? 50 : 30);
    patterns.push("keyboard");
    feedback.push("keyboard pattern (qwerty / asdf / 1234)");
  }
  if (SEQUENCES.some((seq) => hasRun(lower, seq))) {
    cap = Math.min(cap, long ? 50 : 35);
    patterns.push("sequence");
    feedback.push("sequential characters (abcd / 4321)");
  }
  if (hasDate(password)) {
    cap = Math.min(cap, long ? 70 : 45);
    patterns.push("date");
    feedback.push("contains a date or year");
  }
  if (isRepeatedBlock(password)) {
    cap = Math.min(cap, 30);
    patterns.push("repeat-block");
    feedback.push("a short block repeated over and over");
  }
  if (new Set(password).size <= Math.max(3, Math.floor(password.length / 2))) {
    patterns.push("low-diversity");
    feedback.push("low character diversity");
  }
  score = Math.max(0, Math.min(100, Math.round(Math.min(score, cap))));
  const verdict = score >= 80 ? "very strong" : score >= 60 ? "strong" : score >= 40 ? "fair" : "weak";
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  const bits = password.length > 0 && pool > 0 ? Math.round(password.length * Math.log2(pool)) : 0;
  return {
    score,
    verdict,
    feedback: feedback.length > 0 ? feedback : ["no obvious weaknesses"],
    bits,
    patterns
  };
}

// src/watchtower.ts
var KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "0987654321", "!@#$%^&*()"];
var COMMON_PASSWORDS = /* @__PURE__ */ new Set([
  "password",
  "password1",
  "password123",
  "123456",
  "1234567",
  "12345678",
  "123456789",
  "1234567890",
  "qwerty",
  "qwerty123",
  "abc123",
  "111111",
  "123123",
  "admin",
  "letmein",
  "welcome",
  "monkey",
  "dragon",
  "iloveyou",
  "sunshine",
  "princess",
  "football",
  "shadow",
  "superman",
  "batman",
  "trustno1",
  "master",
  "hello",
  "charlie",
  "aa123456",
  "000000"
]);
function estimatePasswordBits(password) {
  if (password.length === 0) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  if (pool === 0) pool = 1;
  return Math.floor(password.length * Math.log2(pool) * 10) / 10;
}
function hasRepeatedRun(password) {
  return /(.)\1{2,}/.test(password);
}
function hasKeyboardSequence(password) {
  const lower = password.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - 4; i++) {
      const seq = row.slice(i, i + 4);
      if (lower.includes(seq)) return true;
    }
  }
  return false;
}
function hasYear(password) {
  return /(19[89]\d|20[0-3]\d)/.test(password);
}
function isCommonPassword(password) {
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return true;
  const base = password.toLowerCase().replace(/[0-9!@#$%^&*]+$/g, "").replace(/^[0-9!@#$%^&*]+/g, "");
  return base.length >= 3 && COMMON_PASSWORDS.has(base);
}
function analyzePassword(password) {
  const flags = [];
  if (password.length === 0) return { flags, bits: 0 };
  if (password.length < 8) flags.push("short-password");
  else if (password.length < 12) flags.push("weak-password");
  if (hasRepeatedRun(password)) flags.push("repeated-chars");
  if (hasKeyboardSequence(password)) flags.push("keyboard-sequence");
  if (hasYear(password)) flags.push("contains-year");
  if (isCommonPassword(password)) flags.push("common-password");
  return { flags, bits: estimatePasswordBits(password) };
}
function scoreFor(flags, bits) {
  let score = 100;
  score -= flags.length * 12;
  if (bits !== void 0 && bits < 40) score -= 15;
  score = Math.max(0, score);
  return score;
}
function analyzeEntry(entry, passwordCounts) {
  const flags = [];
  let bits;
  const kind = entry.kind ?? "login";
  if (entry.password !== void 0 && entry.password.length > 0) {
    const pw = analyzePassword(entry.password);
    flags.push(...pw.flags);
    bits = pw.bits;
    const count = passwordCounts.get(entry.password) ?? 0;
    if (count > 1) flags.push("reused-password");
  }
  if (typeof entry.url === "string" && /^http:\/\//i.test(entry.url)) flags.push("http-site");
  if (entry.password !== void 0 && entry.password.length > 0 && (kind === "login" || kind === "ssh") && (entry.otpSecret === void 0 || entry.otpSecret.length === 0)) {
    flags.push("no-2fa");
  }
  if (entry.expiresAt !== void 0 && entry.expiresAt < Date.now()) flags.push("expired");
  const score = scoreFor(flags, bits);
  const verdict = score >= 80 ? "good" : score >= 50 ? "warn" : "poor";
  return {
    id: entry.id,
    title: entry.title,
    kind,
    flags,
    score,
    verdict,
    ...bits !== void 0 ? { bits } : {}
  };
}
function analyzeVault(entries) {
  const counts = /* @__PURE__ */ new Map();
  for (const e of entries) {
    if (e.password !== void 0 && e.password.length > 0) {
      counts.set(e.password, (counts.get(e.password) ?? 0) + 1);
    }
  }
  return entries.map((e) => analyzeEntry(e, counts));
}

// src/urlmatch.ts
function normalizedHost(input) {
  const trimmed = input.trim().toLowerCase();
  let host = trimmed;
  const scheme = /^https?:\/\//.exec(trimmed);
  if (scheme !== null) {
    const after = trimmed.slice(scheme[0].length);
    const slash = after.indexOf("/");
    host = slash >= 0 ? after.slice(0, slash) : after;
    const at = host.lastIndexOf("@");
    if (at >= 0) host = host.slice(at + 1);
    const colon = host.lastIndexOf(":");
    if (colon >= 0 && /^\d+$/.test(host.slice(colon + 1))) host = host.slice(0, colon);
  } else {
    const slash = host.indexOf("/");
    if (slash >= 0) host = host.slice(0, slash);
    const colon = host.lastIndexOf(":");
    if (colon >= 0 && /^\d+$/.test(host.slice(colon + 1))) host = host.slice(0, colon);
  }
  if (host.startsWith("www.")) host = host.slice(4);
  return host;
}
function urlMatches(target, stored) {
  const targetHost = normalizedHost(target);
  const storedHost = normalizedHost(stored);
  if (targetHost.length === 0 || storedHost.length === 0) return false;
  if (targetHost === storedHost) return true;
  if (targetHost.endsWith(`.${storedHost}`) || storedHost.endsWith(`.${targetHost}`)) return true;
  const targetPath = pathOf(target);
  const storedPath = pathOf(stored);
  if (storedPath.length > 1 && storedPath.length <= targetPath.length && targetPath.startsWith(storedPath)) return true;
  return false;
}
function pathOf(input) {
  const trimmed = input.trim().toLowerCase();
  const scheme = /^https?:\/\//.exec(trimmed);
  let rest = scheme !== null ? trimmed.slice(scheme[0].length) : trimmed;
  const slash = rest.indexOf("/");
  const path = slash >= 0 ? rest.slice(slash) : "/";
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}
function matchScore(target, stored) {
  const targetHost = normalizedHost(target);
  const storedHost = normalizedHost(stored);
  if (targetHost.length === 0 || storedHost.length === 0) return 0;
  if (targetHost === storedHost) return 100;
  if (targetHost.endsWith(`.${storedHost}`)) return 80;
  if (storedHost.endsWith(`.${targetHost}`)) return 60;
  const targetPath = pathOf(target);
  const storedPath = pathOf(stored);
  if (storedPath.length > 1 && targetPath.startsWith(storedPath)) return 40;
  return 0;
}

// src/env-export.ts
var ENV_FIELD_ORDER = ["apiKey", "secret", "accessToken", "refreshToken", "privateKey", "password", "cardNumber", "cardCvv"];
var ENV_FIELD_SUFFIX = {
  apiKey: "API_KEY",
  secret: "SECRET",
  accessToken: "ACCESS_TOKEN",
  refreshToken: "REFRESH_TOKEN",
  privateKey: "PRIVATE_KEY",
  password: "PASSWORD",
  cardNumber: "CARD_NUMBER",
  cardCvv: "CARD_CVV",
  otpSecret: "OTP_SECRET"
};
function envKeyFrom(text) {
  return text.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}
function shellQuote(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
function explicitNames(entry) {
  const list = Array.isArray(entry.envKeys) ? entry.envKeys.filter((name) => typeof name === "string" && name.length > 0) : [];
  if (list.length > 0) return list;
  return typeof entry.envKey === "string" && entry.envKey.length > 0 ? [entry.envKey] : [];
}
function envPairsForEntry(entry, prefix = "") {
  const names = explicitNames(entry);
  const base = names[0] ?? prefix + envKeyFrom(entry.title);
  if (base.length === 0) return [];
  const pairs = [];
  const record = entry;
  const present = ENV_FIELD_ORDER.filter((field) => {
    const value = record[field];
    return typeof value === "string" && value.length > 0;
  });
  present.forEach((field, index) => {
    const value = record[field];
    const suffix = ENV_FIELD_SUFFIX[field] ?? envKeyFrom(field);
    const key = names[index] ?? `${base}_${suffix}`;
    pairs.push({ key, field, value });
  });
  for (const [field, value] of Object.entries(entry.fields ?? {})) {
    if (typeof value !== "string" || value.length === 0) continue;
    pairs.push({ key: `${base}_${envKeyFrom(field)}`, field: `fields.${field}`, value });
  }
  return pairs;
}
function envLinesFor(entries, options = {}) {
  const { kind, ids, prefix = "" } = options;
  const lines = [];
  const seen = /* @__PURE__ */ new Set();
  for (const entry of entries) {
    if (kind !== void 0 && (entry.kind ?? "login") !== kind) continue;
    if (ids !== void 0 && ids.length > 0 && !ids.includes(entry.id)) continue;
    if (!(entry.tags ?? []).includes("env")) continue;
    for (const pair of envPairsForEntry(entry, prefix)) {
      if (pair.key.length === 0 || seen.has(pair.key)) continue;
      seen.add(pair.key);
      lines.push(`${pair.key}=${shellQuote(pair.value)}`);
    }
  }
  return lines;
}
function primarySecret(entry) {
  for (const field of ENV_FIELD_ORDER) {
    const value = entry[field];
    if (typeof value === "string" && value.length > 0) return { field, value };
  }
  return void 0;
}
function maskSecret(value) {
  return value.length > 4 ? `${value.slice(0, 4)}***` : "***";
}
export const openVaultWithKey = (options) => openVault({ ...options, keyMaterial: options.key });
export {
  DEFAULT_DIGITS,
  DEFAULT_PERIOD_SECONDS,
  ENV_FIELD_ORDER,
  ENV_FIELD_SUFFIX,
  IV_LENGTH,
  KEY_LENGTH,
  SCRYPT_N,
  SCRYPT_P,
  SCRYPT_R,
  VAULT_FORMAT_VERSION,
  VaultStore,
  WEAK_PASSWORDS,
  analyzeEntry,
  analyzePassword,
  analyzeVault,
  base32Decode,
  bytesToBase32,
  checkPassword,
  clearCache as clearBreachCache,
  decrypt,
  defaultVaultPath,
  deriveKey,
  encrypt,
  envKeyFrom,
  envLinesFor,
  envPairsForEntry,
  estimatePasswordBits,
  estimateStrength as estimateStrengthPure,
  generatePassphrase,
  generatePassword,
  generateTotpSecret,
  hotp,
  maskSecret,
  matchScore,
  newKdfParams,
  normalizedHost,
  openVault,
  parseTotpSecret,
  pathOf,
  primarySecret,
  safeEqual,
  sha1Hex,
  shellQuote,
  totp,
  urlMatches
};
