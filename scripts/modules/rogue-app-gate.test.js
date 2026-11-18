import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const contentSource = readFileSync(
  new URL("../content.js", import.meta.url),
  "utf8"
);

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing function ${name}`);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) {
        const body = source.slice(start, i + 1);
        return new Function(`${body}\nreturn ${name};`)();
      }
    }
  }
  throw new Error(`unterminated function ${name}`);
}

const responseToRogueAppOnLoginPage = extractFunction(
  contentSource,
  "responseToRogueAppOnLoginPage"
);

test("a rogue client on the real Microsoft login host is a warning", () => {
  assert.equal(responseToRogueAppOnLoginPage(true, true), "warn");
  assert.equal(responseToRogueAppOnLoginPage(true, false), "warn");
});

test("a rogue client on any other host is blocked when protection is on", () => {
  assert.equal(responseToRogueAppOnLoginPage(false, true), "block");
  assert.equal(responseToRogueAppOnLoginPage(false, false), "warn");
});

test("the untrusted login path blocks instead of returning after a warning", () => {
  const start = contentSource.indexOf(
    "ROGUE OAUTH APP DETECTED ON MICROSOFT LOGIN PAGE"
  );
  const end = contentSource.indexOf("Step 4: Check blocking rules");
  assert.ok(start > 0 && end > start);
  const branch = contentSource.slice(start, end);

  assert.match(branch, /responseToRogueAppOnLoginPage\(/);
  assert.match(branch, /showBlockingOverlay\(/);
  assert.match(branch, /disableFormSubmissions\(/);
  assert.match(branch, /disableCredentialInputs\(/);
  assert.equal(
    branch.includes("isBlocked: false, // Rogue apps get warnings, not blocks"),
    false
  );
});

test("the trusted Microsoft login path still only warns", () => {
  const start = contentSource.indexOf(
    "ROGUE OAUTH APP DETECTED ON LEGITIMATE MICROSOFT DOMAIN"
  );
  const end = contentSource.indexOf("Only show valid badge if no rogue app");
  assert.ok(start > 0 && end > start);
  const branch = contentSource.slice(start, end);

  assert.equal(branch.includes("showBlockingOverlay"), false);
  assert.match(branch, /showWarningBanner\(/);
  assert.match(branch, /return;/);
});
