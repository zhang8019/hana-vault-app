const secretKeys = ["password", "privateKey", "apiKey", "secret", "accessToken", "refreshToken", "otpSecret", "cardNumber", "cardCvv"];
const fieldKeys = ["title", "kind", "sensitivity", "username", "email", "phone", ...secretKeys, "expiresAt", "cardExpiry", "cardHolder", "url", "notes", "tags", "fields"];
export function sanitizeHealthReport(report = {}) {
  const project = (entry) => ({ id: entry?.id, title: entry?.title, kind: entry?.kind });
  return {
    score: report.score, verdict: report.verdict, strength: report.strength,
    weak: (report.weak || []).map(project),
    reused: (report.reused || []).map((group) => ({ count: (group.entries || []).length, entries: (group.entries || []).map(project) })),
    no2fa: (report.no2fa || []).map(project),
    httpSites: (report.httpSites || []).map(project),
  };
}
function scrub(input = {}) {
  const out = {};
  for (const key of fieldKeys) if (Object.hasOwn(input, key)) out[key] = input[key];
  delete out.id; delete out.createdAt; delete out.updatedAt; delete out.deletedAt;
  return out;
}
function reply(c, data, status = 200) { return c.json({ ok: true, ...data }, status); }
function fail(c, e, status = 400) { return c.json({ ok: false, error: e instanceof Error ? e.message : String(e) }, status); }
async function json(c) { return c.req.json().catch(() => ({})); }

export function registerVaultRoutes(app, svc, sdk) {
  app.get("/status", async (c) => { try { return reply(c, { status: await svc.status() }); } catch (e) { return fail(c, e); } });
  app.get("/settings", async (c) => { try {
    const cfg = await svc.readSettings();
    const authStatus = await svc.authorizationStatus();
    return reply(c, { settings: { accessMode: ["readonly", "ask", "auto"].includes(cfg.accessMode) ? cfg.accessMode : "ask", autoCapture: Boolean(cfg.autoCapture), lockTimeoutSeconds: Number(cfg.lockTimeoutSeconds) || 900, vaultName: String(cfg.vaultName || "default"), masterPasswordStored: false, rememberDevice: Boolean(cfg.rememberDevice), autoUnlock: Boolean((await svc.status()).autoUnlock) }, grants: authStatus.ready ? await svc.listAgentGrants() : [], authorizationStore: authStatus });
  } catch (e) { return fail(c, e); } });
  app.post("/settings", async (c) => { try {
    const b = await json(c); if (Object.hasOwn(b, "masterPassword")) return fail(c, "新版不支持把主密码保存在设置中，请仅在解锁框临时输入。", 400);
    if (Array.isArray(b.revokeAgents)) for (const agentId of b.revokeAgents) await svc.revokeAgent(agentId);
    if (Array.isArray(b.revokeGrants)) for (const grantId of b.revokeGrants) await svc.revokeGrant(grantId);
    if (b.repairAuthorizationStore === true) await svc.repairAuthorizationStore();
    delete b.revokeAgents; delete b.revokeGrants; delete b.repairAuthorizationStore; delete b.credentialGrants; delete b.mutationsConfirmed;
    return reply(c, { settings: await svc.setPolicy(b) });
  } catch (e) { return fail(c, e); } });
  app.post("/unlock", async (c) => { try { const b = await json(c); if (!b.password) return fail(c, "请输入主密码"); return reply(c, { status: await svc.unlock(b.password, b.vaultName) }); } catch (e) { return fail(c, e); } });
  app.post("/lock", async (c) => { try { const b = await json(c); const reason = b?.reason === "pagehide" ? "pagehide" : "manual"; return reply(c, { status: await svc.lock(reason) }); } catch (e) { return fail(c, e); } });
  app.get("/entries", async (c) => { try {
    const rows = await svc.list({ query: c.req.query("q") || "", kind: c.req.query("kind") || undefined, trash: c.req.query("trash") === "1", limit: Number(c.req.query("limit")) || 200 });
    return reply(c, { entries: rows, count: rows.length });
  } catch (e) { return fail(c, e); } });
  app.get("/entries/:id", async (c) => { try { const entry = await svc.get(c.req.param("id")); return entry ? reply(c, { entry }) : fail(c, "未找到该条目", 404); } catch (e) { return fail(c, e); } });
  app.post("/entries", async (c) => { try { const row = await svc.add(scrub(await json(c))); return reply(c, { entry: row }); } catch (e) { return fail(c, e); } });
  app.put("/entries/:id", async (c) => { try { const row = await svc.update(c.req.param("id"), scrub(await json(c))); return row ? reply(c, { entry: row }) : fail(c, "未找到该条目", 404); } catch (e) { return fail(c, e); } });
  app.delete("/entries/:id", async (c) => { try { return await svc.remove(c.req.param("id")) ? reply(c, {}) : fail(c, "未找到该条目", 404); } catch (e) { return fail(c, e); } });
  app.post("/entries/:id/restore", async (c) => { try { return await svc.restore(c.req.param("id")) ? reply(c, {}) : fail(c, "未找到可恢复条目", 404); } catch (e) { return fail(c, e); } });
  app.post("/entries/:id/purge", async (c) => { try { const b = await json(c); return await svc.purge(c.req.param("id"), b.confirm) ? reply(c, {}) : fail(c, "未找到该条目", 404); } catch (e) { return fail(c, e); } });
  app.get("/entries/:id/totp", async (c) => { try { const value = await svc.totp(c.req.param("id")); return value ? reply(c, value) : fail(c, "该条目没有 TOTP 密钥", 404); } catch (e) { return fail(c, e); } });
  app.get("/audit", async (c) => { try { return reply(c, { events: await svc.auditLog(Number(c.req.query("limit")) || 100) }); } catch (e) { return fail(c, e); } });
  app.get("/grants", async (c) => { try { return reply(c, { grants: await svc.listAgentGrants() }); } catch (e) { return fail(c, e); } });
  app.post("/grants/revoke", async (c) => { try { const b = await json(c); return reply(c, await svc.revokeAgent(String(b.agentId || ""))); } catch (e) { return fail(c, e); } });
  app.post("/grants/revoke-grant", async (c) => { try { const b = await json(c); return reply(c, await svc.revokeGrant(String(b.grantId || ""))); } catch (e) { return fail(c, e); } });
  app.post("/generate-password", async (c) => { try { return reply(c, svc.generatePassword(await json(c))); } catch (e) { return fail(c, e); } });
  app.post("/export", async (c) => { try {
    const b = await json(c); if (!b.password || String(b.password).length < 12) return fail(c, "导出密码至少需要 12 个字符");
    const blob = await svc.exportEncrypted(b.password); return reply(c, { encryptedBackup: blob, warning: "此备份仍需单独的导出密码解密。请勿发送到不可信位置。" });
  } catch (e) { return fail(c, e); } });
  app.post("/import", async (c) => { try {
    const b = await json(c); if (!b.backup || !b.password) return fail(c, "需要加密备份内容和导出密码");
    return reply(c, { imported: await svc.importEncrypted(String(b.backup), b.password, Boolean(b.overwrite), b.dryRun !== false), dryRun: b.dryRun !== false });
  } catch (e) { return fail(c, e); } });
  app.get("/health", async (c) => { try { const store = await svc.requireVault(); const r = store.health ? store.health() : (store.stats ? store.stats() : {}); return reply(c, { report: sanitizeHealthReport(r) }); } catch (e) { return fail(c, e); } });
}
