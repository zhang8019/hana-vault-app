import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import * as vaultCore from "./vault-core.js";
const { openVault } = vaultCore;

const serviceSlot = "__hanaVaultV2Service";
const metaSlot = "__hanaVaultV2Meta";
export function safeSummary(entry) {
  const out = { id: entry.id, title: entry.title, kind: entry.kind, username: entry.username, email: entry.email, host: entry.host, port: entry.port, url: entry.url, tags: entry.tags, sensitivity: entry.sensitivity, createdAt: entry.createdAt, updatedAt: entry.updatedAt, hasOtp: Boolean(entry.hasOtp ?? entry.otpSecret) };
  for (const field of ["password", "apiKey", "privateKey", "secret", "accessToken", "refreshToken", "cardNumber", "cardCvv"]) if (field in entry) out[`has${field[0].toUpperCase()}${field.slice(1)}`] = Boolean(entry[field]);
  return out;
}
function safeName(value) { return String(value || "default").replace(/[^A-Za-z0-9._-]/g, "_") || "default"; }
export function installVaultService(sdk) {
  if (globalThis[serviceSlot]) return globalThis[serviceSlot];
  const meta = globalThis[metaSlot] || (globalThis[metaSlot] = {});
  let vault = null, unlockedAt = 0, lastTouch = 0, idleMs = 900000, autoLockTimer = null, audit = [], auditChain = Promise.resolve();
  let mode = "ask", autoCapture = false, vaultName = "default", failedUnlocks = 0, blockedUntil = 0, mutationsConfirmed = false;
  const auditPath = join(sdk.dataDir, "audit.json");
  const clearTimer = () => { if (autoLockTimer) clearTimeout(autoLockTimer); autoLockTimer = null; };
  const scheduleTimer = () => { clearTimer(); autoLockTimer = setTimeout(() => { void lock("idle-timeout"); }, idleMs); autoLockTimer.unref?.(); };
  async function readSettings() {
    const cfg = await sdk.config.getAll();
    mode = ["readonly", "ask", "auto"].includes(cfg.accessMode) ? cfg.accessMode : "ask";
    mutationsConfirmed = Boolean(cfg.mutationsConfirmed);
    autoCapture = Boolean(cfg.autoCapture); vaultName = safeName(cfg.vaultName);
    const seconds = Number(cfg.lockTimeoutSeconds); idleMs = Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 86400) * 1000 : 900000;
    if (vault && !vault.isLocked) vault.setAutoLock(idleMs);
    return cfg;
  }
  async function auditEvent(kind, extra = {}) {
    audit.push({ at: new Date().toISOString(), kind, ...extra }); if (audit.length > 500) audit = audit.slice(-500);
    auditChain = auditChain.then(async () => { await mkdir(dirname(auditPath), { recursive: true }); await writeFile(auditPath, JSON.stringify(audit, null, 2), { mode: 0o600 }); }); await auditChain;
  }
  async function loadAudit() { if (meta.auditLoaded) return; try { audit = JSON.parse(await readFile(auditPath, "utf8")); } catch { audit = []; } meta.auditLoaded = true; }
  async function lock(reason = "manual") {
    const wasOpen = Boolean(vault); if (vault) await vault.lock(); vault = null; unlockedAt = 0; lastTouch = 0; clearTimer();
    if (wasOpen) await auditEvent("lock", { reason }); return { open: false, vaultName };
  }
  async function requireVault() {
    await readSettings();
    if (vault && Date.now() - lastTouch > idleMs) { await lock("idle-timeout"); throw new Error("保险库已自动锁定，请重新解锁"); }
    if (!vault || vault.isLocked) throw new Error("保险库已锁定，请先输入主密码解锁");
    lastTouch = Date.now(); scheduleTimer(); return vault;
  }
  async function status() {
    await readSettings(); const open = Boolean(vault && !vault.isLocked && Date.now() - lastTouch <= idleMs);
    if (!open && vault) await lock("idle-timeout"); const stats = open ? vault.stats() : { total: 0, withTotp: 0 };
    return { open, vaultName: meta.vaultName || vaultName, accessMode: mode, autoCapture, lockTimeoutSeconds: Math.round(idleMs / 1000), configuredMasterPassword: false, total: stats.total, withTotp: stats.withTotp, unlockedAt: open ? new Date(unlockedAt).toISOString() : null };
  }
  async function unlock(password, requestedName) {
    const now = Date.now(); if (now < blockedUntil) throw new Error(`连续解锁失败，请 ${Math.ceil((blockedUntil - now) / 1000)} 秒后重试`);
    const cfg = await readSettings(), selected = safeName(requestedName || meta.vaultName || cfg.vaultName || "default"), path = join(sdk.dataDir, "vaults", `${selected}.json`);
    await mkdir(dirname(path), { recursive: true });
    try { const next = await openVault({ masterPassword: String(password || ""), path }); if (vault) await vault.lock(); vault = next; vaultName = selected; meta.vaultName = selected; unlockedAt = lastTouch = Date.now(); vault.setAutoLock(idleMs); scheduleTimer(); failedUnlocks = 0; blockedUntil = 0; await auditEvent("unlock", { vaultName: selected }); return await status(); }
    catch (error) { failedUnlocks++; if (failedUnlocks >= 5) blockedUntil = Date.now() + Math.min(1800000, 1000 * (2 ** Math.min(failedUnlocks - 5, 10))); await auditEvent("unlock-failed", { vaultName: selected }); throw error; }
  }
  const svc = {
    core: vaultCore, readSettings, status, unlock, lock, requireVault,
    async list({ query = "", kind, trash = false, limit = 200 } = {}) { const s = await requireVault(); let rows = query ? s.search(String(query), Math.min(Number(limit) || 50, 200)) : (trash ? s.listTrash() : s.list()); if (kind) rows = rows.filter((x) => x.kind === kind); return rows.slice(0, Math.min(Number(limit) || 50, 200)).map(safeSummary); },
    async get(id) { return (await requireVault()).getIncludingTrash(String(id)) || null; },
    async add(patch) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); if (mode === "ask" && !mutationsConfirmed) throw new Error("写入需确认：请先在面板确认允许本次会话写入，再重试。"); const e = await (await requireVault()).add(patch); await auditEvent("add", { id: e.id, title: e.title }); return safeSummary(e); },
    async update(id, patch) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); if (mode === "ask" && !mutationsConfirmed) throw new Error("写入需确认：请先在面板确认允许本次会话写入，再重试。"); const e = await (await requireVault()).update(String(id), patch); if (e) await auditEvent("update", { id: e.id, title: e.title }); return e ? safeSummary(e) : null; },
    async remove(id) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); if (mode === "ask" && !mutationsConfirmed) throw new Error("写入需确认：请先在面板确认允许本次会话写入，再重试。"); const s = await requireVault(), e = s.get(String(id)); if (!e) return false; await s.delete(String(id)); await auditEvent("trash", { id, title: e.title }); return true; },
    async restore(id) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); if (mode === "ask" && !mutationsConfirmed) throw new Error("写入需确认：请先在面板确认允许本次会话写入，再重试。"); const ok = await (await requireVault()).restore(String(id)); if (ok) await auditEvent("restore", { id }); return ok; },
    async purge(id, confirm) { if (confirm !== true) throw new Error("彻底删除必须显式确认 confirm=true"); await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); if (mode === "ask" && !mutationsConfirmed) throw new Error("写入需确认：请先在面板确认允许本次会话写入，再重试。"); const ok = await (await requireVault()).purge(String(id)); if (ok) await auditEvent("purge", { id }); return ok; },
    async totp(id) { const s = await requireVault(), e = s.get(String(id)); if (!e?.otpSecret) return null; const now = Date.now(); return { code: vaultCore.totp(e.otpSecret, now), secondsRemaining: 30 - Math.floor(now / 1000) % 30 }; },
    async auditLog(limit = 100) { await loadAudit(); return audit.slice(-Math.min(Math.max(Number(limit) || 100, 1), 500)).reverse(); },
    async exportEncrypted(password) { return (await requireVault()).exportEncrypted(String(password)); },
    async importEncrypted(blob, password, overwrite = false, dryRun = true) { await readSettings(); const s = await requireVault(); if (mode === "readonly" && !dryRun) throw new Error("保险库处于只读模式"); if (mode === "ask" && !dryRun && !mutationsConfirmed) throw new Error("写入需确认：请先在面板确认允许本次会话写入，再重试。"); const n = await s.importEncrypted(String(blob), String(password), Boolean(overwrite), Boolean(dryRun)); if (!dryRun) await auditEvent("import", { count: n }); return n; },
    async setPolicy(patch) { const allowed = ["accessMode", "autoCapture", "lockTimeoutSeconds", "vaultName"]; const clean = Object.fromEntries(Object.entries(patch || {}).filter(([key]) => allowed.includes(key))); if (clean.vaultName !== undefined && meta.vaultName && safeName(clean.vaultName) !== meta.vaultName) throw new Error("当前会话已固定到所选保险库；切换库请先锁定并解锁目标库，防止写错库。"); await sdk.config.setMany(clean); await readSettings(); return { accessMode: mode, autoCapture, lockTimeoutSeconds: Math.round(idleMs / 1000), vaultName }; },
    async confirmMutations(approved) { mutationsConfirmed = Boolean(approved); await sdk.config.set("mutationsConfirmed", mutationsConfirmed); if (approved) await auditEvent("write-consent-granted"); else await auditEvent("write-consent-revoked"); return { mutationsConfirmed }; },
    generatePassword(options = {}) { const value = options.passphrase ? vaultCore.generatePassphrase({ words: Number(options.words) || 4, separator: String(options.separator ?? "-") }) : vaultCore.generatePassword(options); return { value, strength: vaultCore.estimateStrengthPure(value) }; },
    async shutdown() { await lock("shutdown"); if (globalThis[serviceSlot] === svc) delete globalThis[serviceSlot]; },
  };
  return globalThis[serviceSlot] = svc;
}
