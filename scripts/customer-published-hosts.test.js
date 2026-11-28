import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rules = JSON.parse(
  readFileSync(join(root, "rules/detection-rules.json"), "utf8")
);
const contentSource = readFileSync(join(root, "scripts/content.js"), "utf8");

function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) {
    throw new Error(`missing function ${name}`);
  }
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    const ch = source[i];
    if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) {
        const body = source.slice(start, i + 1);
        return new Function(`${body}\nreturn ${name};`)();
      }
    }
  }
  throw new Error(`unterminated function ${name}`);
}

const mustScanCustomerPublishedPage = extractFunction(
  contentSource,
  "mustScanCustomerPublishedPage"
);

function originMatches(origin, patterns) {
  return patterns.some((pattern) => new RegExp(pattern).test(origin));
}

function exclusionMatches(url, patterns) {
  return patterns.some((pattern) => new RegExp(pattern, "i").test(url));
}

test("customer-published hosts are not skipped when they can host a login clone", () => {
  const scriptUrl = "https://script.google.com/macros/s/AKfycb/exec";
  const sitesUrl = "https://sites.google.com/view/microsoft-365-login";
  const sharePointUrl = "https://contoso.sharepoint.com/sites/hr/login.html";

  assert.equal(mustScanCustomerPublishedPage(scriptUrl, false), true);
  assert.equal(mustScanCustomerPublishedPage(scriptUrl, true), true);
  assert.equal(
    exclusionMatches(scriptUrl, rules.exclusion_system.domain_patterns),
    true,
    "Apps Script still matches the broad Google exclusion pattern"
  );

  assert.equal(mustScanCustomerPublishedPage(sitesUrl, false), false);
  assert.equal(mustScanCustomerPublishedPage(sitesUrl, true), true);
  assert.equal(
    exclusionMatches(sitesUrl, rules.exclusion_system.domain_patterns),
    true
  );

  assert.equal(mustScanCustomerPublishedPage(sharePointUrl, false), false);
  assert.equal(mustScanCustomerPublishedPage(sharePointUrl, true), true);
  assert.equal(
    originMatches(
      "https://contoso.sharepoint.com",
      rules.microsoft_domain_patterns
    ),
    true,
    "SharePoint tenants still match the Microsoft domain patterns"
  );

  assert.equal(
    mustScanCustomerPublishedPage(
      "https://contoso-my.sharepoint.com/personal/a/Documents/login.html",
      true
    ),
    true
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://script.google.com./macros/s/x/exec", true),
    true
  );
});

test("operated Microsoft and Google hosts stay eligible for the fast path", () => {
  assert.equal(
    mustScanCustomerPublishedPage("https://www.google.com/search?q=microsoft+login", true),
    false
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://accounts.google.com/", true),
    false
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://portal.office.com/login", true),
    false
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://outlook.office.com/mail/", true),
    false
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://login.microsoftonline.com/common", true),
    false
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://evil.sharepoint.com.attacker.test/login", true),
    false
  );
  assert.equal(
    mustScanCustomerPublishedPage("https://notsharepoint.com/login", true),
    false
  );
  assert.equal(mustScanCustomerPublishedPage("not a url", true), false);
});

test("both skip paths consult the customer-published guard", () => {
  const exclusionStart = contentSource.indexOf("function checkDomainExclusion");
  const exclusionEnd = contentSource.indexOf("function checkUserUrlAllowlist");
  const exclusionSource = contentSource.slice(exclusionStart, exclusionEnd);
  assert.match(exclusionSource, /mustScanCustomerPublishedPage/);

  const trustStart = contentSource.indexOf(
    "Check for general Microsoft domains (non-login pages)"
  );
  const trustEnd = contentSource.indexOf("Step 3: Check for domain exclusion");
  const trustSource = contentSource.slice(trustStart, trustEnd);
  assert.match(trustSource, /mustScanCustomerPublishedPage/);
});
