import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createAuthorizationStore } from "./authorization-store.js";
import * as vaultCore from "./vault-core.js";
import { createDeviceUnlock } from "./device-unlock.js";
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
  let mode = "ask", autoCapture = false, rememberDevice = false, autoUnlockSuppressed = false, vaultName = "default", failedUnlocks = 0, blockedUntil = 0;
  let deviceUnlock = createDeviceUnlock({ dataDir: sdk.dataDir, vaultName });
  const authorizationStore = createAuthorizationStore(join(sdk.dataDir, "authorization.json"));
  let authInitPromise = null;
  let authExecutionTail = Promise.resolve();
  let lockRequested = false;
  let authorizedExecutionActive = false;
  let revocationPending = 0;
  async function ensureAuthorizationStore() {
    if (!authInitPromise) authInitPromise = authorizationStore.load();
    await authInitPromise;
  }
  function currentVaultId() { return JSON.stringify([String(sdk.dataDir), String(meta.vaultName || vaultName)]); }
  async function authorizeTool(input) {
    await readSettings();
    await ensureAuthorizationStore();
    const vaultId = currentVaultId();
    if (!vault || vault.isLocked) await tryAutoUnlock();
    if (!vault || vault.isLocked) throw new Error("保险库已锁定；Agent 操作拒绝。请先在面板解锁，再重新发起调用。");
    const credentialId = String(input.credentialId || "");
    let credential = null;
    if (credentialId && credentialId !== "*" && !credentialId.startsWith("new:")) credential = vault.getIncludingTrash(credentialId);
    let result;
    try {
      result = await authorizationStore.authorize({
        vaultId,
        ...input,
        credentialId,
        credentialLabel: credential?.title || credential?.name || input.credentialLabel || credentialId,
        category: credential?.kind || input.category || "",
      });
      await auditEvent("authorization-approved", { agentId: String(input.agentId), credentialId, action: String(input.action), persistent: Boolean(result.persistent) });
    } catch (error) {
      await auditEvent("authorization-denied", { agentId: String(input.agentId), credentialId, action: String(input.action) });
      throw error;
    }
    return result;
  }
  async function runAuthorizedTool(authorization, operation) {
    const task = authExecutionTail.then(async () => {
      await ensureAuthorizationStore();
      if (lockRequested || revocationPending > 0 || !vault || vault.isLocked || authorization?.vaultId !== currentVaultId()) throw new Error("保险库已锁定、授权正在撤销或库已切换，操作已拒绝。");
      await authorizationStore.assertEpoch(authorization?.epoch, authorization?.persistent === false ? authorization : undefined);
      authorizedExecutionActive = true;
      try { return await operation(); } finally { authorizedExecutionActive = false; }
    });
    authExecutionTail = task.catch(() => {});
    return task;
  }
  const auditPath = join(sdk.dataDir, "audit.json");
  const clearTimer = () => { if (autoLockTimer) clearTimeout(autoLockTimer); autoLockTimer = null; };
  const scheduleTimer = () => { clearTimer(); autoLockTimer = setTimeout(() => { void lock("idle-timeout"); }, idleMs); autoLockTimer.unref?.(); };
  async function readSettings() {
    const cfg = await sdk.config.getAll();
    mode = ["readonly", "ask", "auto"].includes(cfg.accessMode) ? cfg.accessMode : "ask";
    autoCapture = Boolean(cfg.autoCapture); rememberDevice = Boolean(cfg.rememberDevice); vaultName = safeName(cfg.vaultName);
    deviceUnlock = createDeviceUnlock({ dataDir: sdk.dataDir, vaultName });
    const seconds = Number(cfg.lockTimeoutSeconds); idleMs = Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 86400) * 1000 : 900000;
    if (vault && !vault.isLocked) vault.setAutoLock(idleMs);
    return cfg;
  }
  async function auditEvent(kind, extra = {}) {
    const safeExtra = { ...extra };
    if (typeof safeExtra.title === "string") safeExtra.title = "[已脱敏]";
    audit.push({ at: new Date().toISOString(), kind, ...safeExtra }); if (audit.length > 500) audit = audit.slice(-500);
    auditChain = auditChain.then(async () => { await mkdir(dirname(auditPath), { recursive: true }); await writeFile(auditPath, JSON.stringify(audit, null, 2), { mode: 0o600 }); }); await auditChain;
  }
  async function loadAudit() { if (meta.auditLoaded) return; try { audit = JSON.parse(await readFile(auditPath, "utf8")); } catch { audit = []; } meta.auditLoaded = true; }
  async function lock(reason = "manual") {
    if (reason === "manual") autoUnlockSuppressed = true;
    const wasOpen = Boolean(vault);
    lockRequested = true;
    const closingVaultId = currentVaultId();
    let invalidationFailed = false;
    if (wasOpen) {
      try { await ensureAuthorizationStore(); await authorizationStore.invalidate({ vaultId: closingVaultId, preserveGrants: true }); }
      catch { invalidationFailed = true; }
    }
    await authExecutionTail;
    if (vault) await vault.lock(); vault = null; unlockedAt = 0; lastTouch = 0; clearTimer();
    if (wasOpen) await auditEvent("lock", { reason, authorizationInvalidationFailed: invalidationFailed });
    return { open: false, vaultName, authorizationInvalidationFailed: invalidationFailed };
  }
  async function tryAutoUnlock() {
    await readSettings();
    if (vault || !rememberDevice || autoUnlockSuppressed || !(await deviceUnlock.exists())) return false;
    try { const key = await deviceUnlock.loadKey(); if (!key) throw new Error("invalid device key"); const next = await vaultCore.openVaultWithKey({ path: join(sdk.dataDir, "vaults", `${vaultName}.json`), key }); key.fill(0); vault = next; meta.vaultName = vaultName; lockRequested = false; unlockedAt = lastTouch = Date.now(); vault.setAutoLock(idleMs); scheduleTimer(); return true; }
    catch { await deviceUnlock.clear(); await auditEvent("device-unlock-failed", { vaultName }); return false; }
  }
  async function requireVault({ fromAuthorizedExecution = false } = {}) {
    await readSettings();
    if (!vault || vault.isLocked) await tryAutoUnlock();
    if (vault && Date.now() - lastTouch > idleMs) {
      if (fromAuthorizedExecution) throw new Error("保险库已自动锁定，请重新解锁");
      if (authorizedExecutionActive) throw new Error("保险库已自动锁定，请重新解锁");
      await lock("idle-timeout"); throw new Error("保险库已自动锁定，请重新解锁");
    }
    if (!vault || vault.isLocked) throw new Error("保险库已锁定，请先输入主密码解锁");
    lastTouch = Date.now(); scheduleTimer(); return vault;
  }
  async function status() {
    await readSettings(); const open = Boolean(vault && !vault.isLocked && Date.now() - lastTouch <= idleMs);
    if (!open && vault) await lock("idle-timeout"); if (!open) await tryAutoUnlock(); const actualOpen = Boolean(vault && !vault.isLocked); const stats = open ? vault.stats() : { total: 0, withTotp: 0 };
    return { open: actualOpen, vaultName: meta.vaultName || vaultName, accessMode: mode, autoCapture, rememberDevice, autoUnlock: actualOpen && rememberDevice, lockTimeoutSeconds: Math.round(idleMs / 1000), configuredMasterPassword: false, total: actualOpen ? vault.stats().total : stats.total, withTotp: actualOpen ? vault.stats().withTotp : stats.withTotp, unlockedAt: actualOpen ? new Date(unlockedAt).toISOString() : null };
  }
  async function unlock(password, requestedName) {
    const now = Date.now(); if (now < blockedUntil) throw new Error(`连续解锁失败，请 ${Math.ceil((blockedUntil - now) / 1000)} 秒后重试`);
    const cfg = await readSettings(), selected = safeName(requestedName || meta.vaultName || cfg.vaultName || "default"), path = join(sdk.dataDir, "vaults", `${selected}.json`);
    await mkdir(dirname(path), { recursive: true });
    try { const next = await openVault({ masterPassword: String(password || ""), path }); if (vault) { lockRequested = true; await ensureAuthorizationStore(); await authorizationStore.invalidate({ vaultId: currentVaultId(), preserveGrants: true }); await authExecutionTail; await vault.lock(); } vault = next; vaultName = selected; meta.vaultName = selected; lockRequested = false; unlockedAt = lastTouch = Date.now(); vault.setAutoLock(idleMs); scheduleTimer(); failedUnlocks = 0; blockedUntil = 0; autoUnlockSuppressed = false; if (rememberDevice) { const stamp = await import("node:crypto").then(({ createHash }) => readFile(path).then((bytes) => createHash("sha256").update(bytes).digest("hex")).catch(() => null)); await deviceUnlock.saveKey(vault.key, stamp); } await auditEvent("unlock", { vaultName: selected }); return await status(); }
    catch (error) { failedUnlocks++; if (failedUnlocks >= 5) blockedUntil = Date.now() + Math.min(1800000, 1000 * (2 ** Math.min(failedUnlocks - 5, 10))); await auditEvent("unlock-failed", { vaultName: selected }); throw error; }
  }
  const svc = {
    core: vaultCore, readSettings, status, unlock, lock, requireVault, runAuthorizedTool, tryAutoUnlock,

    async list({ query = "", kind, trash = false, limit = 200 } = {}) { const s = await requireVault(); let rows = query ? s.search(String(query), Math.min(Number(limit) || 50, 200)) : (trash ? s.listTrash() : s.list()); if (kind) rows = rows.filter((x) => x.kind === kind); return rows.slice(0, Math.min(Number(limit) || 50, 200)).map(safeSummary); },
    async get(id) { return (await requireVault()).getIncludingTrash(String(id)) || null; },
    authorizeTool,
    async add(patch) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); const e = await (await requireVault()).add(patch); await auditEvent("add", { id: e.id, title: e.title }); return safeSummary(e); },
    async update(id, patch) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); const e = await (await requireVault()).update(String(id), patch); if (e) await auditEvent("update", { id: e.id, title: e.title }); return e ? safeSummary(e) : null; },
    async remove(id) { revocationPending++; try { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); const s = await requireVault(), e = s.get(String(id)); if (!e) return false; await ensureAuthorizationStore(); await authorizationStore.invalidate({ vaultId: currentVaultId(), credentialId: String(id) }); await s.delete(String(id)); await auditEvent("trash", { id, title: e.title }); return true; } finally { revocationPending--; } },
    async restore(id) { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); const ok = await (await requireVault()).restore(String(id)); if (ok) await auditEvent("restore", { id }); return ok; },
    async purge(id, confirm) { if (confirm !== true) throw new Error("彻底删除必须显式确认 confirm=true"); revocationPending++; try { await readSettings(); if (mode === "readonly") throw new Error("保险库处于只读模式"); const s = await requireVault(); if (!s.getIncludingTrash(String(id))) return false; await ensureAuthorizationStore(); await authorizationStore.invalidate({ vaultId: currentVaultId(), credentialId: String(id) }); const ok = await s.purge(String(id)); if (ok) await auditEvent("purge", { id }); return ok; } finally { revocationPending--; } },
    async totp(id) { const s = await requireVault(), e = s.get(String(id)); if (!e?.otpSecret) return null; const now = Date.now(); return { code: vaultCore.totp(e.otpSecret, now), secondsRemaining: 30 - Math.floor(now / 1000) % 30 }; },
    async auditLog(limit = 100) { await loadAudit(); return audit.slice(-Math.min(Math.max(Number(limit) || 100, 1), 500)).reverse(); },
    async exportEncrypted(password) { return (await requireVault()).exportEncrypted(String(password)); },
    async importEncrypted(blob, password, overwrite = false, dryRun = true) { await readSettings(); const s = await requireVault(); if (mode === "readonly" && !dryRun) throw new Error("保险库处于只读模式"); const n = await s.importEncrypted(String(blob), String(password), Boolean(overwrite), Boolean(dryRun)); if (!dryRun) { if (overwrite) { await deviceUnlock.clear(); revocationPending++; try { await ensureAuthorizationStore(); await authorizationStore.invalidate({ vaultId: currentVaultId() }); await authExecutionTail; } finally { revocationPending--; } } await auditEvent("import", { count: n }); } return n; },
    async setPolicy(patch, { source = "ui" } = {}) { const allowed = ["accessMode", "autoCapture", "lockTimeoutSeconds", "vaultName", ...(source === "ui" ? ["rememberDevice"] : [])]; const clean = Object.fromEntries(Object.entries(patch || {}).filter(([key]) => allowed.includes(key))); if (source === "tool" && (Object.hasOwn(clean, "accessMode") || Object.hasOwn(clean, "vaultName") || Object.hasOwn(clean, "rememberDevice"))) throw new Error("Agent 工具不得更改访问模式或目标保险库；请在保险库面板操作。"); if (clean.vaultName !== undefined && meta.vaultName && safeName(clean.vaultName) !== meta.vaultName) throw new Error("当前会话已固定到所选保险库；切换库请先锁定并解锁目标库，防止写错库。"); if (clean.rememberDevice === false) await deviceUnlock.clear(); if (clean.rememberDevice === true && (!vault || vault.isLocked)) throw new Error("请先解锁保险库后再开启本机自动解锁"); await sdk.config.setMany(clean); await readSettings(); if (clean.rememberDevice === true && vault?.key) { const path = join(sdk.dataDir, "vaults", `${vaultName}.json`); const { createHash } = await import("node:crypto"); const stamp = await readFile(path).then((bytes) => createHash("sha256").update(bytes).digest("hex")).catch(() => null); await deviceUnlock.saveKey(vault.key, stamp); } return { accessMode: mode, autoCapture, rememberDevice, lockTimeoutSeconds: Math.round(idleMs / 1000), vaultName }; },
    async revokeAgent(agentId) { if (!agentId) throw new Error("需要 Agent 身份"); revocationPending++; try { await ensureAuthorizationStore(); const result = await authorizationStore.invalidate({ agentId: String(agentId) }); await authExecutionTail; await auditEvent("agent-grants-revoked", { agentId: String(agentId) }); return result; } finally { revocationPending--; } },
    async revokeGrant(grantId) { if (!grantId) throw new Error("需要授权记录 ID"); revocationPending++; try { await ensureAuthorizationStore(); const result = await authorizationStore.invalidate({ grantId: String(grantId) }); await authExecutionTail; await auditEvent("agent-grant-revoked", { grantId: String(grantId) }); return result; } finally { revocationPending--; } },
    async listAgentGrants() { await ensureAuthorizationStore(); return authorizationStore.list(); },
    async authorizationStatus() { try { await ensureAuthorizationStore(); return { ready: true, broken: false }; } catch { return { ready: false, broken: true }; } },
    async repairAuthorizationStore() { const result = await authorizationStore.repair(); authInitPromise = Promise.resolve(); return result; },
    generatePassword(options = {}) { const value = options.passphrase ? vaultCore.generatePassphrase({ words: Number(options.words) || 4, separator: String(options.separator ?? "-") }) : vaultCore.generatePassword(options); return { value, strength: vaultCore.estimateStrengthPure(value) }; },
    async shutdown() { await lock("shutdown"); if (globalThis[serviceSlot] === svc) delete globalThis[serviceSlot]; },
  };
  return globalThis[serviceSlot] = svc;
}
