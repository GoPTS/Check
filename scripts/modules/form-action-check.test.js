import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  formActionTargetsHost,
  indicatorScanSucceeded,
  shouldScanPhishingIndicators,
} from "./form-action-check.js";
import { evaluatePageWithRules } from "./rules-engine-core.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const rules = JSON.parse(
  fs.readFileSync(path.join(root, "rules/detection-rules.json"), "utf8")
);
const contentSource = fs.readFileSync(
  path.join(root, "scripts/content.js"),
  "utf8"
);

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing function ${name}`);
  let open = source.indexOf("{", start);
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

const contentFormActionTargetsHost = extractFunction(
  contentSource,
  "formActionTargetsHost"
);
const contentIndicatorScanSucceeded = extractFunction(
  contentSource,
  "indicatorScanSucceeded"
);
const contentShouldScan = extractFunction(
  contentSource,
  "shouldScanPhishingIndicators"
);

function originMatches(origin, patterns) {
  return patterns.some((pattern) => new RegExp(pattern).test(origin));
}

test("customer-controlled Azure hostnames are not trusted Microsoft origins", () => {
  const patterns = rules.microsoft_domain_patterns;
  assert.equal(
    originMatches("https://phish.azurewebsites.net", patterns),
    false
  );
  assert.equal(
    originMatches("https://login-secure.azureedge.net", patterns),
    false
  );
  assert.equal(originMatches("https://portal.office.com", patterns), true);
  assert.equal(
    originMatches("https://login.microsoftonline.com", rules.trusted_login_patterns),
    true
  );
});

test("form action match is by hostname, shared by content script and module", () => {
  const cases = [
    ["https://login.microsoftonline.com/common/login", "https://login.microsoftonline.com/login", true],
    ["https://evil.test/login.microsoftonline.com", "https://evil.test/signin", false],
    ["https://evil.test/collect?next=https://login.microsoftonline.com", "https://evil.test/signin", false],
    ["https://login.microsoftonline.com.evil.test/login", "https://evil.test/signin", false],
    ["/common/login", "https://login.microsoftonline.com/foo", true],
    ["", "https://evil.test/harvest", false],
    ["", "https://login.microsoftonline.com/common/login", true],
    ["https://region.login.microsoftonline.com/common/login", "https://phish.test/", true],
    ["javascript:alert(1)", "https://phish.test/", false],
  ];

  for (const [action, base, expected] of cases) {
    assert.equal(
      formActionTargetsHost(action, "login.microsoftonline.com", base),
      expected,
      `module ${action} @ ${base}`
    );
    assert.equal(
      contentFormActionTargetsHost(action, "login.microsoftonline.com", base),
      expected,
      `content.js ${action} @ ${base}`
    );
  }
});

test("indicator worker failure is not a clean scan", () => {
  const failed = { threats: [], score: 0 };
  assert.equal(indicatorScanSucceeded(failed), false);
  assert.equal(contentIndicatorScanSucceeded(failed), false);
  assert.equal(
    indicatorScanSucceeded({ threats: [], score: 0, success: true }),
    true
  );
  assert.equal(contentSource.includes("backgroundResult.score >= 0"), false);
  assert.equal(contentSource.includes("indicatorScanSucceeded(backgroundResult)"), true);
});

test("high legitimacy scores on untrusted origins still scan indicators", () => {
  assert.equal(shouldScanPhishingIndicators(85), true);
  assert.equal(shouldScanPhishingIndicators(70), true);
  assert.equal(contentShouldScan(85), true);
  assert.equal(shouldScanPhishingIndicators(25), false);
  assert.equal(shouldScanPhishingIndicators(0), false);
  assert.equal(contentSource.includes("skipping ALL phishing indicators"), false);
});

test("playground blocks credential forms that only mention Microsoft in the action URL", () => {
  const phishing = evaluatePageWithRules({
    rulesJson: rules,
    pageSource:
      '<form action="https://evil.test/collect?ref=login.microsoftonline.com" method="POST"><input type="password" name="passwd"></form>',
    url: "https://evil.test/login",
  });
  assert.equal(phishing.blocking.shouldBlock, true);
  assert.ok(phishing.blocking.triggeredRuleIds.includes("form_post_not_microsoft"));

  const pathBypass = evaluatePageWithRules({
    rulesJson: rules,
    pageSource:
      '<form action="https://evil.test/login.microsoftonline.com" method="POST"><input type="password" name="passwd"></form>',
    url: "https://evil.test/login",
  });
  assert.equal(pathBypass.blocking.shouldBlock, true);

  const legitimate = evaluatePageWithRules({
    rulesJson: rules,
    pageSource:
      '<form action="https://login.microsoftonline.com/common/login" method="POST"><input type="password" name="passwd"></form>',
    url: "https://login.microsoftonline.com/common/login",
  });
  assert.equal(
    legitimate.blocking.triggeredRuleIds.includes("form_post_not_microsoft"),
    false
  );
  assert.equal(legitimate.blocking.shouldBlock, false);
});
