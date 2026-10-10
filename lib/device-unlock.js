import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCallback, createHash } from "node:crypto";
import { promisify } from "node:util";
import { readFile, writeFile, rename, rm, mkdir, chmod } from "node:fs/promises";
import { join, dirname } from "node:path";
import { userInfo, hostname, homedir } from "node:os";
import { newKdfParams, deriveKey } from "./vault-core.js";
const scrypt = promisify(scryptCallback);
const PREFIX = "hana-vault-device-unlock-v1";
function safeName(value) { return String(value || "default").replace(/[^A-Za-z0-9._-]/g, "_") || "default"; }
export function createDeviceUnlock({ dataDir, vaultName }) {
  const path = join(dataDir, "vaults", `${safeName(vaultName)}.device.json`);
  async function stamp() { try { return createHash("sha256").update(await readFile(join(dirname(path), `${safeName(vaultName)}.json`))).digest("hex"); } catch { return null; } }
  async function wrappingKey(kdf) { const id = [userInfo().username, hostname(), homedir(), PREFIX].join("\0"); return scrypt(Buffer.from(id, "utf8"), Buffer.from(kdf.saltHex, "hex"), 32, { N: kdf.n, r: kdf.r, p: kdf.p, maxmem: 1024 * 1024 * 1024 }); }
  return {
    path,
    async saveKey(keyBuffer, fileStamp) {
      if (!Buffer.isBuffer(keyBuffer) || keyBuffer.length !== 32) throw new Error("invalid vault key");
      const kdf = newKdfParams(), wrap = await wrappingKey(kdf), iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", wrap, iv);
      const ct = Buffer.concat([cipher.update(keyBuffer), cipher.final()]);
      const record = { v: 1, algo: "aes-256-gcm+scrypt", kdf, ivHex: iv.toString("hex"), ctHex: ct.toString("hex"), tagHex: cipher.getAuthTag().toString("hex"), savedAt: new Date().toISOString(), fileStamp: fileStamp ?? await stamp() };
      await mkdir(dirname(path), { recursive: true, mode: 0o700 }); const tmp = `${path}.${randomBytes(8).toString("hex")}.tmp`;
      try { await writeFile(tmp, JSON.stringify(record), { mode: 0o600 }); await chmod(tmp, 0o600).catch(() => {}); await rename(tmp, path); } catch (e) { await rm(tmp, { force: true }); throw e; } finally { wrap.fill(0); }
    },
    async loadKey(expectedFileStamp) {
      let wrap;
      try {
        const record = JSON.parse(await readFile(path, "utf8"));
        if (record.v !== 1 || record.algo !== "aes-256-gcm+scrypt" || !record.kdf || (expectedFileStamp !== undefined && record.fileStamp !== expectedFileStamp)) return null;
        if (record.fileStamp !== null && await stamp() !== record.fileStamp) return null;
        wrap = await wrappingKey(record.kdf); const decipher = createDecipheriv("aes-256-gcm", wrap, Buffer.from(record.ivHex, "hex")); decipher.setAuthTag(Buffer.from(record.tagHex, "hex"));
        const key = Buffer.concat([decipher.update(Buffer.from(record.ctHex, "hex")), decipher.final()]); return key.length === 32 ? key : null;
      } catch { return null; } finally { wrap?.fill(0); }
    },
    async clear() { await rm(path, { force: true }); },
    async exists() { try { await readFile(path); return true; } catch { return false; } },
  };
}
