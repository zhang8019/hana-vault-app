import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installVaultService } from "../lib/vault-service.js";

async function fixture() {
  const dataDir = await mkdtemp(join(tmpdir(), "hana-vault-service-auth-"));
  const cfg = { accessMode: "ask", vaultName: "alpha", lockTimeoutSeconds: 86400 };
  const sdk = {
    dataDir,
    config: {
      async getAll() { return { ...cfg }; },
      async set(key, value) { cfg[key] = value; },
      async setMany(patch) { Object.assign(cfg, patch); },
    },
    userInteraction: { async ask() { return { action: "confirmed", value: { grant: "always" } }; } },
  };
  const service = installVaultService(sdk);
  await service.unlock("synthetic-only-master-passphrase-123");
  const entry = await (await service.requireVault()).add({ title: "Synthetic Entry", kind: "login", username: "fake-user" });
  const cleanup = async () => { await service.shutdown(); await rm(dataDir, { recursive: true, force: true }); };
  return { dataDir, sdk, service, entry, cleanup };
}

test("service lock invalidates a pending ask before it can run", async () => {
  const f = await fixture();
  try {
    let resolveAsk;
    f.sdk.userInteraction.ask = async () => new Promise((resolve) => { resolveAsk = resolve; });
    const pending = f.service.authorizeTool({ agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    await new Promise((resolve) => setImmediate(resolve));
    await f.service.lock();
    resolveAsk({ action: "confirmed", value: { grant: "once" } });
    await assert.rejects(pending, /授权状态已变化/);
    assert.equal((await f.service.listAgentGrants()).length, 0);
  } finally { await f.cleanup(); }
});

test("trash invalidates a credential grant; restore does not revive it", async () => {
  const f = await fixture();
  try {
    const authArgs = { agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" };
    await f.service.authorizeTool(authArgs);
    assert.equal((await f.service.listAgentGrants()).length, 1);
    await f.service.remove(f.entry.id);
    assert.equal((await f.service.listAgentGrants()).length, 0);
    await f.service.restore(f.entry.id);
    f.sdk.userInteraction.ask = async () => ({ action: "confirmed", value: { grant: "once" } });
    const next = await f.service.authorizeTool(authArgs);
    assert.equal(next.persistent, false);
    assert.equal((await f.service.listAgentGrants()).length, 0);
  } finally { await f.cleanup(); }
});

test("lock while authorization ask is pending rejects the approved once permit", async () => {
  const f = await fixture();
  try {
    let resolveAsk;
    f.sdk.userInteraction.ask = async () => new Promise((resolve) => { resolveAsk = resolve; });
    const pending = f.service.authorizeTool({ agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    await new Promise((resolve) => setImmediate(resolve));
    await f.service.lock();
    resolveAsk({ action: "confirmed", value: { grant: "once" } });
    await assert.rejects(pending, /授权状态已变化/);
  } finally { await f.cleanup(); }
});

test("expired vault check inside authorized execution rejects without waiting on its own tail", async () => {
  const f = await fixture();
  const originalNow = Date.now;
  try {
    const auth = await f.service.authorizeTool({ agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    Date.now = () => originalNow() + 100_000_000;
    await assert.rejects(f.service.runAuthorizedTool(auth, async () => f.service.requireVault()), /自动锁定/);
  } finally {
    Date.now = originalNow;
    await f.cleanup();
  }
});

test("purge removes a credential already in trash", async () => {
  const f = await fixture();
  try {
    await f.service.remove(f.entry.id);
    const result = await f.service.purge(f.entry.id, true);
    assert.equal(result, true);
    assert.equal(await f.service.get(f.entry.id), null);
  } finally { await f.cleanup(); }
});

test("overwriting import revokes all grants for the current vault", async () => {
  const f = await fixture();
  try {
    await f.service.authorizeTool({ agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    assert.equal((await f.service.listAgentGrants()).length, 1);
    const vault = await f.service.requireVault();
    let resolveImport;
    vault.importEncrypted = async (_blob, _password, overwrite, dryRun) => {
      assert.equal(overwrite, true);
      assert.equal(dryRun, false);
      return new Promise((resolve) => { resolveImport = resolve; });
    };
    const importing = f.service.importEncrypted("synthetic-backup", "synthetic-password", true, false);
    await new Promise((resolve) => setImmediate(resolve));
    resolveImport(1);
    assert.equal(await importing, 1);
    assert.equal((await f.service.listAgentGrants()).length, 0);
  } finally { await f.cleanup(); }
});

test("a settings vault switch scopes a new grant to a different vault identity", async () => {
  const f = await fixture();
  try {
    const first = await f.service.authorizeTool({ agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    await f.service.lock();
    f.sdk.config.setMany({ vaultName: "beta" });
    await f.service.unlock("synthetic-only-master-passphrase-123", "beta");
    const second = await f.service.authorizeTool({ agentId: "agent-a", credentialId: f.entry.id, action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    assert.notEqual(first.vaultId, second.vaultId);
    assert.equal(second.persistent, true);
    const grants = await f.service.listAgentGrants();
    assert.equal(grants.length, 2);
    assert.notEqual(grants[0].vaultId, grants[1].vaultId);
  } finally { await f.cleanup(); }
});
