import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createDeviceUnlock } from "../lib/device-unlock.js";
import { openVault } from "../lib/vault-core.js";
import { installVaultService } from "../lib/vault-service.js";
const stamp = async (p) => createHash("sha256").update(await readFile(p)).digest("hex");
test("device wrapper roundtrip, tamper rejection, stamp binding, clear", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vault-device-test-"));
  try {
    const file = join(dir, "vaults", "synthetic.json"); const store = await openVault({ path: file, masterPassword: "synthetic test-only password" });
    const wrapper = createDeviceUnlock({ dataDir: dir, vaultName: "synthetic" }); const key = store.key;
    const s = await stamp(file); await wrapper.saveKey(key, s); assert.deepEqual(await wrapper.loadKey(s), key); assert.equal(await wrapper.loadKey("wrong-stamp"), null);
    const original = JSON.parse(await readFile(wrapper.path, "utf8"));
    for (const field of ["ctHex", "tagHex"]) { const altered = { ...original, [field]: "00".repeat(field === "ctHex" ? 32 : 16) }; await writeFile(wrapper.path, JSON.stringify(altered)); assert.equal(await wrapper.loadKey(), null); }
    await writeFile(wrapper.path, JSON.stringify({ ...original, fileStamp: "tampered" })); assert.equal(await wrapper.loadKey(), null);
    await writeFile(wrapper.path, JSON.stringify(original)); await wrapper.clear(); assert.equal(await wrapper.exists(), false);
    await store.lock();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
function makeSdk(dataDir, cfg) { return { dataDir, config: { async getAll() { return { ...cfg }; }, async setMany(x) { Object.assign(cfg, x); }, async set(k,v) { cfg[k]=v; } } }; }
test("service remembers locally, restarts, suppresses manual lock and clears on disable", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vault-device-service-")); const cfg = { vaultName: "synthetic", rememberDevice: false, lockTimeoutSeconds: 86400 };
  try {
    let svc = installVaultService(makeSdk(dir, cfg)); await svc.unlock("synthetic only test password"); await svc.setPolicy({ rememberDevice: true }); await svc.shutdown();
    svc = installVaultService(makeSdk(dir, cfg)); assert.equal((await svc.status()).open, true); await svc.lock("manual"); assert.equal((await svc.status()).open, false);
    await svc.unlock("synthetic only test password"); assert.equal((await svc.status()).open, true); await svc.shutdown();
    cfg.rememberDevice = false; svc = installVaultService(makeSdk(dir, cfg)); assert.equal((await svc.status()).open, false); await svc.shutdown();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test("a pagehide lock does not suppress device auto-unlock", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vault-device-pagehide-")); const cfg = { vaultName: "synthetic", rememberDevice: true, lockTimeoutSeconds: 86400 };
  try {
    const svc = installVaultService(makeSdk(dir, cfg));
    await svc.unlock("synthetic only test password");
    await svc.lock("pagehide");
    assert.equal((await svc.status()).open, true);
    assert.equal((await svc.status()).autoUnlock, true);
    await svc.shutdown();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test("auto-unlock after an idle lock does not leave the authorized-execution gate closed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vault-device-idle-")); const cfg = { vaultName: "synthetic", rememberDevice: true, lockTimeoutSeconds: 86400 };
  try {
    const prompts = [];
    const sdk = makeSdk(dir, cfg);
    sdk.userInteraction = { async ask(request) { prompts.push(request); return { action: "confirmed", value: { grant: "once" } }; } };
    const svc = installVaultService(sdk);
    await svc.unlock("synthetic only test password");
    await svc.lock("idle-timeout");
    assert.equal((await svc.status()).open, true);
    const auth = await svc.authorizeTool({ agentId: "synthetic-agent", credentialId: "synthetic", action: "get", fields: ["username"], sdk, sessionPath: "/synthetic/session" });
    assert.equal(await svc.runAuthorizedTool(auth, async () => "ok"), "ok");
    await svc.shutdown();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
