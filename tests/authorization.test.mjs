import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { installVaultService } from "../lib/vault-service.js";
import { sanitizeHealthReport } from "../lib/routes.js";
import { createAuthorizedToolExecutor } from "../lib/tools.js";

async function fixture(answer = { action: "confirmed", value: { grant: "once" } }) {
  const dataDir = await mkdtemp(join(tmpdir(), "hana-vault-auth-"));
  const values = { accessMode: "ask", credentialGrants: [] };
  const prompts = [];
  const sdk = {
    dataDir,
    config: {
      async getAll() { return structuredClone(values); },
      async set(key, value) { values[key] = structuredClone(value); },
      async setMany(patch) { Object.assign(values, structuredClone(patch)); },
    },
    userInteraction: { async ask(request) { prompts.push(request); return structuredClone(answer); } },
  };
  const service = installVaultService(sdk);
  await service.unlock("synthetic-test-master-passphrase-000");
  return { dataDir, values, prompts, sdk, service, dispose: async () => { await service.shutdown(); await rm(dataDir, { recursive: true, force: true }); } };
}

test("fails closed when authenticated identity or host ask context is absent", async () => {
  const f = await fixture();
  try {
    await assert.rejects(f.service.authorizeTool({ agentId: "", credentialId: "c1", action: "get", sdk: f.sdk, sessionPath: "/s/a" }), /已拒绝/);
    await assert.rejects(f.service.authorizeTool({ agentId: "agent-a", credentialId: "c1", action: "get", sdk: {}, sessionPath: "/s/a" }), /已拒绝/);
    assert.equal(f.prompts.length, 0);
  } finally { await f.dispose(); }
});

test("one-time approval asks for bounded choice and is not persisted", async () => {
  const f = await fixture();
  try {
    const result = await f.service.authorizeTool({ agentId: "agent-a", credentialId: "cred-1", action: "get", fields: ["password"], sdk: f.sdk, sessionPath: "/s/a" });
    assert.equal(result.persistent, false);
    assert.ok(Number.isSafeInteger(result.epoch));
    assert.deepEqual(f.prompts[0].requestedSchema.properties.grant.enum, ["仅此次", "长期允许"]);
    assert.equal((await f.service.listAgentGrants()).length, 0);
  } finally { await f.dispose(); }
});

test("persistent approval is scoped to agent, credential, action, and field set; revoke removes it", async () => {
  const f = await fixture({ action: "confirmed", value: { grant: "always" } });
  try {
    await f.service.authorizeTool({ agentId: "agent-a", credentialId: "cred-1", action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/s/a" });
    assert.equal((await f.service.listAgentGrants()).length, 1);
    assert.equal((await f.service.authorizeTool({ agentId: "agent-a", credentialId: "cred-1", action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/s/a" })).persistent, true);
    await f.service.authorizeTool({ agentId: "agent-a", credentialId: "cred-1", action: "get", fields: ["password"], sdk: f.sdk, sessionPath: "/s/a" });
    await f.service.authorizeTool({ agentId: "agent-b", credentialId: "cred-1", action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/s/b" });
    assert.equal(f.prompts.length, 3);
    await f.service.revokeAgent("agent-a");
    assert.equal((await f.service.listAgentGrants()).some((x) => x.agentId === "agent-a"), false);
  } finally { await f.dispose(); }
});

test("health projection never exposes reused secret values", () => {
  const report = sanitizeHealthReport({
    score: 50, verdict: "fair", strength: { weak: 1 },
    reused: [{ value: "SYNTHETIC-SECRET", entries: [{ id: "1", title: "one", password: "SYNTHETIC-SECRET" }] }],
    weak: [{ id: "2", title: "two", password: "SYNTHETIC-SECRET" }],
  });
  assert.equal(JSON.stringify(report).includes("SYNTHETIC-SECRET"), false);
});

test("tool execution uses only host-injected session identity and ignores model identity fields", async () => {
  const f = await fixture({ action: "rejected" });
  try {
    let called = false;
    const sdk = { ...f.sdk, sessions: { async list() { return { sessions: [{ sessionId: "s-verified", path: "/trusted/session.jsonl", agentId: "verified-agent" }] }; }, async get(input) { assert.deepEqual(input, { sessionId: "s-verified", scope: "all" }); return { session: { agentId: "verified-agent", agentName: "Verified", path: "/trusted/session.jsonl" } }; } } };
    const executor = createAuthorizedToolExecutor("vault_get", async (args) => { called = true; return args.id; }, f.service, sdk);
    await assert.rejects(executor({ id: "cred-1", agentId: "attacker", context: { sessionPath: "/trusted/session.jsonl", callToken: "synthetic-token" } }), /未批准/);
    assert.equal(called, false);
    assert.equal(f.prompts[0].sessionPath, "/trusted/session.jsonl");
    assert.equal(f.prompts[0].message.includes("verified-agent"), true);
    assert.equal(f.prompts[0].message.includes("attacker"), false);
  } finally { await f.dispose(); }
});

test("tool request parameters are snapshotted and deeply frozen while approval waits", async () => {
  const f = await fixture();
  try {
    let resolveAsk;
    f.sdk.userInteraction.ask = async (request) => { f.prompts.push(structuredClone(request)); return new Promise((resolve) => { resolveAsk = resolve; }); };
    let captured;
    const sdk = { ...f.sdk, sessions: { async list({ scope }) { assert.equal(scope, "all"); return { sessions: [{ sessionId: "s-1", path: "/s" }] }; }, async get({ sessionId }) { return { session: { sessionId, agentId: "verified-agent", path: "/s" } }; } } };
    const fakeService = {
      async authorizeTool(input) { const answer=await input.sdk.userInteraction.ask({ sessionPath: input.sessionPath, title:"test", message:"test" }); if(answer.action!=="confirmed") throw Error("rejected"); return { epoch: 1, vaultId: "v" }; },
      async runAuthorizedTool(_auth, operation) { return operation(); },
    };
    const execute = createAuthorizedToolExecutor("vault_update", async (args) => { captured = args; return true; }, fakeService, sdk);
    const input = { id: "cred-1", notes: "original", fields: { custom: "original" }, context: { sessionPath: "/s", callToken: "synthetic" } };
    const pending = execute(input);
    await new Promise((resolve) => setImmediate(resolve));
    input.notes = "changed"; input.fields.custom = "changed";
    resolveAsk({ action: "confirmed", value: { grant: "once" } });
    await pending;
    assert.equal(captured.notes, "original");
    assert.equal(captured.fields.custom, "original");
    assert.equal(Object.isFrozen(captured.fields), true);
  } finally { await f.dispose(); }
});

test("tools authorize and execute through the service permit exactly once", async () => {
  const f = await fixture();
  try {
    let calls = 0;
    const sdk = { ...f.sdk, sessions: { async list() { return { sessions: [{ sessionId: "s-syn", path: "/synthetic/session" }] }; }, async get({ sessionId }) { return { session: { sessionId, agentId: "verified-agent", path: "/synthetic/session" } }; } } };
    const auth = await f.service.authorizeTool({ agentId: "verified-agent", credentialId: "synthetic", action: "get", fields: ["username"], sdk: f.sdk, sessionPath: "/synthetic/session" });
    assert.equal(auth.persistent, false);
    assert.equal(await f.service.runAuthorizedTool(auth, async () => ++calls), 1);
    await assert.rejects(f.service.runAuthorizedTool(auth, async () => ++calls), /授权状态已变化/);
    assert.equal(calls, 1);
    const executor = createAuthorizedToolExecutor("vault_get", async () => ++calls, f.service, sdk);
    const result = await executor({ id: "synthetic", context: { sessionPath: "/synthetic/session", callToken: "synthetic-call-token" } });
    assert.equal(result, 2);
  } finally { await f.dispose(); }
});

test("wide-scope metadata reads can be granted persistently, bulk export cannot", async () => {
  const f = await fixture();
  try {
    const sdk = { ...f.sdk, sessions: { async list() { return { sessions: [{ sessionId: "s-w", path: "/w" }] }; }, async get({ sessionId }) { return { session: { sessionId, agentId: "verified-agent", path: "/w" } }; } } };
    const seen = [];
    const svc = { async authorizeTool(input) { seen.push(input); return { epoch: 1, vaultId: "v" }; }, async runAuthorizedTool(_auth, op) { return op(); } };
    const ctx = { context: { sessionPath: "/w", callToken: "synthetic" } };
    await createAuthorizedToolExecutor("vault_list", async () => "ok", svc, sdk)(ctx);
    await createAuthorizedToolExecutor("vault_export", async () => "ok", svc, sdk)({ password: "synthetic-password-123", ...ctx });
    assert.equal(seen[0].allowPersistent, true);
    assert.equal(seen[0].credentialId, "*");
    assert.equal(seen[1].allowPersistent, false);
  } finally { await f.dispose(); }
});

test("Agent policy writes cannot switch access mode or vault", async () => {
  const f = await fixture();
  try {
    await assert.rejects(f.service.setPolicy({ accessMode: "auto" }, { source: "tool" }), /不得更改访问模式/);
    await assert.rejects(f.service.setPolicy({ vaultName: "other" }, { source: "tool" }), /不得更改访问模式/);
    let changed = false;
    const execute = createAuthorizedToolExecutor("vault_config", async () => { changed = true; }, f.service, f.sdk);
    await assert.rejects(execute({ action: "set", values: { accessMode: "auto" } }), /不得更改访问模式/);
    assert.equal(changed, false);
  } finally { await f.dispose(); }
});
