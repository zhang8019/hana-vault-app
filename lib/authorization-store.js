import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

const SCHEMA_VERSION = 1;
const denied = () => new Error("授权状态已变化或无法验证，操作已拒绝。请重新发起并确认。");

export function createAuthorizationStore(filePath, { now = () => new Date().toISOString() } = {}) {
  let grants = [];
  let epoch = 0;
  let loaded = false;
  let broken = false;
  let loadPromise = null;
  let writeTail = Promise.resolve();
  const consumedOnce = new WeakSet();

  async function load() {
    if (loaded) {
      if (broken) throw new Error("授权文件无效或不可读取，Agent 凭证访问已关闭。请在面板显式修复授权存储。");
      return loadPromise;
    }
    loaded = true;
    loadPromise = (async () => { try {
      const data = JSON.parse(await readFile(filePath, "utf8"));
      if (data?.schemaVersion !== SCHEMA_VERSION || !Number.isSafeInteger(data.epoch) || data.epoch < 0 || !Array.isArray(data.grants)) throw new Error("invalid authz schema");
      for (const grant of data.grants) {
        if (!grant || typeof grant.id !== "string" || !grant.id || typeof grant.vaultId !== "string" || !grant.vaultId || typeof grant.agentId !== "string" || !grant.agentId || typeof grant.credentialId !== "string" || !grant.credentialId || typeof grant.action !== "string" || !grant.action || !Array.isArray(grant.fields) || grant.fields.some((field) => typeof field !== "string") || typeof grant.createdAt !== "string" || ["agentName","credentialLabel","category"].some((key) => grant[key] !== undefined && typeof grant[key] !== "string")) throw new Error("invalid grant record");
      }
      epoch = data.epoch;
      grants = data.grants.map((grant) => ({ ...grant, fields: [...grant.fields] }));
    } catch (error) {
      if (error?.code === "ENOENT") return;
      broken = true;
      throw new Error("授权文件无效或不可读取，Agent 凭证访问已关闭。请在面板显式修复授权存储。");
    } })();
    return loadPromise;
  }

  function assertReady() {
    if (!loaded || broken) throw new Error("授权存储未就绪或损坏，Agent 凭证访问已关闭。");
  }

  function persist() {
    const task = writeTail.then(async () => {
      assertReady();
      await mkdir(dirname(filePath), { recursive: true });
      const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
      const backupPath = `${filePath}.${randomUUID()}.bak`;
      const body = JSON.stringify({ schemaVersion: SCHEMA_VERSION, epoch, grants }, null, 2);
      let movedOld = false;
      try {
        await writeFile(temporaryPath, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
        try { await rename(filePath, backupPath); movedOld = true; } catch (error) { if (error?.code !== "ENOENT") throw error; }
        await rename(temporaryPath, filePath);
        if (movedOld) await rm(backupPath, { force: true });
      } catch (error) {
        await rm(temporaryPath, { force: true }).catch(() => {});
        if (movedOld) await rename(backupPath, filePath).catch(() => {});
        broken = true;
        throw error;
      }
    });
    writeTail = task.catch(() => {});
    return task;
  }

  async function authorize({ agentId, agentName, vaultId, credentialId, credentialLabel, category, action, fields = [], sdk, sessionPath, allowPersistent = true }) {
    await load();
    assertReady();
    if (!agentId || !vaultId || !credentialId || !action || !Array.isArray(fields) || !sessionPath || typeof sdk?.userInteraction?.ask !== "function") throw new Error("宿主未提供可验证的 Agent、凭证或会话身份，已拒绝此工具操作。");
    const requested = [...new Set(fields.map(String))].sort();
    const capturedEpoch = epoch;
    const existing = allowPersistent ? grants.find((grant) => grant.vaultId === String(vaultId) && grant.agentId === String(agentId) && grant.credentialId === String(credentialId) && grant.action === String(action) && requested.every((field) => grant.fields.includes("*") || grant.fields.includes(field))) : null;
    if (existing) return { persistent: true, grantId: existing.id, epoch: capturedEpoch, vaultId: String(vaultId) };
    const answer = await sdk.userInteraction.ask({
      sessionPath,
      title: "凭证保险库授权",
      message: `Agent「${String(agentName || agentId)}」（ID: ${String(agentId)}）请求对${category ? `【${String(category)}】` : ""}凭证「${String(credentialLabel || credentialId)}」执行「${String(action)}」，字段：${requested.join("、") || "无"}。${String(credentialId) === "*" ? "范围为库内全部条目。" : ""}长期授权仅适用于本库、本动作与所列范围。`,
      requestedSchema: { type: "object", properties: { grant: { type: "string", title: "授权范围", enum: allowPersistent ? ["仅此次", "长期允许"] : ["仅此次"] } }, required: ["grant"], additionalProperties: false },
      timeoutMs: 120000,
    });
    if (answer?.action !== "confirmed") throw new Error("用户未批准该凭证操作。");
    if (epoch !== capturedEpoch) throw denied();
    const choice = answer?.value?.grant;
    const wantsPersistent = choice === "长期允许" || choice === "always";
    const wantsOnce = choice === "仅此次" || choice === "once";
    if (wantsPersistent && allowPersistent) {
      const grant = { id: randomUUID(), vaultId: String(vaultId), agentId: String(agentId), ...(agentName ? { agentName: String(agentName) } : {}), credentialId: String(credentialId), ...(credentialLabel ? { credentialLabel: String(credentialLabel) } : {}), ...(category ? { category: String(category) } : {}), action: String(action), fields: requested, createdAt: now() };
      grants.push(grant);
      try { await persist(); } catch { grants = grants.filter((item) => item.id !== grant.id); throw new Error("授权无法安全保存，已拒绝操作。"); }
      if (epoch !== capturedEpoch) throw denied();
      return { persistent: true, grantId: grant.id, epoch: capturedEpoch, vaultId: String(vaultId) };
    }
    if (!wantsOnce) throw new Error("授权选择无效，操作已拒绝。");
    if (epoch !== capturedEpoch) throw denied();
    const permit = Object.freeze({ persistent: false, epoch: capturedEpoch, vaultId: String(vaultId) });
    consumedOnce.add(permit);
    return permit;
  }

  async function invalidate({ vaultId, credentialId, agentId, grantId, preserveGrants = false } = {}) {
    await load();
    assertReady();
    epoch += 1;
    if (!preserveGrants) {
      if (vaultId && credentialId) grants = grants.filter((grant) => !(grant.vaultId === String(vaultId) && grant.credentialId === String(credentialId)));
      if (vaultId && !credentialId && !agentId && !grantId) grants = grants.filter((grant) => grant.vaultId !== String(vaultId));
      if (agentId) grants = grants.filter((grant) => grant.agentId !== String(agentId));
      if (grantId) grants = grants.filter((grant) => grant.id !== String(grantId));
    }
    await persist();
    return { revoked: true, epoch };
  }

  async function assertEpoch(expectedEpoch, permit) {
    await load();
    assertReady();
    await writeTail;
    if (!Number.isSafeInteger(expectedEpoch) || expectedEpoch !== epoch) throw denied();
    if (permit !== undefined) {
      if (!consumedOnce.has(permit)) throw denied();
      consumedOnce.delete(permit);
    }
    return true;
  }

  async function repair() {
    await writeTail;
    grants = [];
    epoch = Number.isSafeInteger(epoch) ? epoch + 1 : 1;
    broken = false;
    loaded = true;
    loadPromise = Promise.resolve();
    await persist();
    return { repaired: true, epoch };
  }

  async function list() {
    await load();
    assertReady();
    return grants.map((grant) => ({ ...grant, fields: [...grant.fields] }));
  }

  return Object.freeze({ load, authorize, invalidate, assertEpoch, repair, list, getEpoch: () => epoch, isBroken: () => broken });
}
