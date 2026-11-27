import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ConfigManager } from "./config-manager.js";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../.."
);
const contentSource = fs.readFileSync(
  path.join(root, "scripts/content.js"),
  "utf8"
);

test("enterprise policy overrides local blocking and allowlist", () => {
  const manager = new ConfigManager();
  const merged = manager.mergeConfigurations(
    {
      enablePageBlocking: false,
      urlAllowlist: ["*"],
    },
    {
      enablePageBlocking: true,
      urlAllowlist: ["https://intranet.example/*"],
    },
    {}
  );

  assert.equal(merged.enablePageBlocking, true);
  assert.deepEqual(merged.urlAllowlist, ["https://intranet.example/*"]);
});

test("local blocking stays off when policy does not set it", () => {
  const manager = new ConfigManager();
  const merged = manager.mergeConfigurations(
    { enablePageBlocking: false, urlAllowlist: ["https://intranet.example/*"] },
    { showNotifications: false },
    {}
  );

  assert.equal(merged.enablePageBlocking, false);
  assert.deepEqual(merged.urlAllowlist, ["https://intranet.example/*"]);
});

test("content script asks for the merged config before deciding to scan", () => {
  const start = contentSource.indexOf("async function runProtection");
  assert.notEqual(start, -1);
  const body = contentSource.slice(start, start + 1800);

  assert.match(body, /loadProtectionConfig\(\)/);
  assert.equal(body.includes('chrome.storage.local.get(["config"]'), false);
  assert.match(contentSource, /type:\s*"GET_CONFIG"/);
});
