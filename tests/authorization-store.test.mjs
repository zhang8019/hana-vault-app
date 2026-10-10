import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthorizationStore } from "../lib/authorization-store.js";

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "hana-vault-authz-"));
  const file = join(dir, "authorization.json");
  const answers = [];
  const sdk = { userInteraction: { async ask(req) { const next = answers.shift(); return next(req); } } };
  const base = { agentId: "agent-a", agentName: "A", vaultId: "vault-A", credentialId: "cred-1", credentialLabel: "Synthetic entry", category: "login", action: "get", fields: ["username"], sdk, sessionPath: "/synthetic/session" };
  return { dir, file, answers, sdk, base, store: createAuthorizationStore(file), close: () => rm(dir, { recursive: true, force: true }) };
}
const always = async () => ({ action: "confirmed", value: { grant: "长期允许" } });
const once = async () => ({ action: "confirmed", value: { grant: "仅此次" } });

test("persistent grants survive reload with schemaVersion and metadata", async () => {
  const f = await fixture();
  try {
    f.answers.push(always);
    const created = await f.store.authorize(f.base);
    const saved = JSON.parse(await readFile(f.file, "utf8"));
    assert.equal(saved.schemaVersion, 1);
    assert.equal(saved.grants[0].credentialLabel, "Synthetic entry");
    const reloaded = createAuthorizationStore(f.file);
    await reloaded.load();
    const result = await reloaded.authorize({ ...f.base, sdk: { userInteraction: { ask: async () => { throw new Error("must use stored grant"); } } } });
    assert.equal(result.persistent, true);
    assert.equal(result.grantId, created.grantId);
  } finally { await f.close(); }
});

test("grant-scoped revoke removes only the targeted grant, agent revoke clears the rest", async () => {
  const f = await fixture();
  try {
    f.answers.push(always, always);
    const first = await f.store.authorize(f.base);
    await f.store.authorize({ ...f.base, credentialId: "cred-2", credentialLabel: "Second" });
    assert.equal((await f.store.list()).length, 2);
    await f.store.invalidate({ grantId: first.grantId });
    const left = await f.store.list();
    assert.equal(left.length, 1);
    assert.equal(left[0].credentialId, "cred-2");
    await f.store.invalidate({ agentId: "agent-a" });
    assert.equal((await f.store.list()).length, 0);
  } finally { await f.close(); }
});

test("grant never crosses vault boundary", async () => {
  const f = await fixture();
  try {
    f.answers.push(always, once);
    await f.store.authorize(f.base);
    const result = await f.store.authorize({ ...f.base, vaultId: "vault-B" });
    assert.equal(result.persistent, false);
    assert.equal(f.store.getEpoch(), 0);
  } finally { await f.close(); }
});

test("revocation while ask is pending invalidates both once and persistent answers", async () => {
  for (const grant of ["once", "always"]) {
    const f = await fixture();
    try {
      let resolveAsk;
      f.answers.push(() => new Promise((resolve) => { resolveAsk = resolve; }));
      const pending = f.store.authorize(f.base);
      await new Promise((resolve) => setImmediate(resolve));
      await f.store.invalidate({ agentId: "agent-a" });
      resolveAsk({ action: "confirmed", value: { grant } });
      await assert.rejects(pending, /授权状态已变化/);
      assert.equal((await f.store.list()).length, 0);
    } finally { await f.close(); }
  }
});

test("concurrent persistent authorizations serialize without lost records", async () => {
  const f = await fixture();
  try {
    const results = await Promise.all(Array.from({ length: 12 }, async (_, index) => {
      f.answers.push(always);
      return f.store.authorize({ ...f.base, credentialId: `cred-${index}` });
    }));
    assert.equal(results.length, 12);
    const persisted = JSON.parse(await readFile(f.file, "utf8"));
    assert.equal(persisted.grants.length, 12);
    const reloaded = createAuthorizationStore(f.file);
    assert.equal((await reloaded.list()).length, 12);
  } finally { await f.close(); }
});

test("lock epoch invalidates pending ask but preserves persistent grants", async () => {
  const f = await fixture();
  try {
    f.answers.push(always);
    await f.store.authorize(f.base);
    let resolveAsk;
    f.answers.push(() => new Promise((resolve) => { resolveAsk = resolve; }));
    const pending = f.store.authorize({ ...f.base, credentialId: "cred-pending" });
    await new Promise((resolve) => setImmediate(resolve));
    await f.store.invalidate({ vaultId: "vault-A", preserveGrants: true });
    resolveAsk({ action: "confirmed", value: { grant: "once" } });
    await assert.rejects(pending, /授权状态已变化/);
    const grants = await f.store.list();
    assert.equal(grants.length, 1);
    assert.equal(grants[0].credentialId, "cred-1");
  } finally { await f.close(); }
});

test("delete and restore lifecycle invalidation removes old grants", async () => {
  const f = await fixture();
  try {
    f.answers.push(always);
    await f.store.authorize(f.base);
    await f.store.invalidate({ vaultId: "vault-A", credentialId: "cred-1" });
    assert.equal((await f.store.list()).length, 0);
    f.answers.push(once);
    const afterRestore = await f.store.authorize(f.base);
    assert.equal(afterRestore.persistent, false);
    assert.equal(f.answers.length, 0);
  } finally { await f.close(); }
});

test("purge and delete never offer persistent authorization", async () => {
  const f = await fixture();
  try {
    for (const action of ["delete", "purge"]) {
      let request;
      f.answers.push(async (req) => { request = req; return { action: "confirmed", value: { grant: "always" } }; });
      await assert.rejects(f.store.authorize({ ...f.base, action, allowPersistent: false }), /授权选择无效/);
      assert.deepEqual(request.requestedSchema.properties.grant.enum, ["仅此次"]);
    }
  } finally { await f.close(); }
});

test("allowPersistent false always asks even when an equivalent disk grant exists", async () => {
  const f = await fixture();
  try {
    f.answers.push(always, once);
    await f.store.authorize(f.base);
    const result = await f.store.authorize({ ...f.base, allowPersistent: false });
    assert.equal(result.persistent, false);
    assert.equal(f.answers.length, 0);
  } finally { await f.close(); }
});

test("a one-time permit can be consumed only once", async () => {
  const f = await fixture();
  try {
    f.answers.push(once);
    const permit = await f.store.authorize(f.base);
    assert.equal(await f.store.assertEpoch(permit.epoch, permit), true);
    await assert.rejects(f.store.assertEpoch(permit.epoch, permit), /授权状态已变化/);
    await assert.rejects(f.store.assertEpoch(permit.epoch, { persistent: false, epoch: permit.epoch }), /授权状态已变化/);
  } finally { await f.close(); }
});

test("corrupt authorization file fails closed until explicit repair", async () => {
  const f = await fixture();
  try {
    await writeFile(f.file, "{broken", "utf8");
    const broken = createAuthorizationStore(f.file);
    await assert.rejects(broken.load(), /授权文件无效/);
    await assert.rejects(broken.authorize(f.base), /授权文件无效/);
    const repair = await broken.repair();
    assert.equal(repair.repaired, true);
    assert.equal((await broken.list()).length, 0);
    assert.equal(JSON.parse(await readFile(f.file, "utf8")).schemaVersion, 1);
  } finally { await f.close(); }
});
