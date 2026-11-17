import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const rules = JSON.parse(
  readFileSync(new URL("../../rules/detection-rules.json", import.meta.url), "utf8")
);
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

const matchesDomainExclusion = extractFunction(
  contentSource,
  "matchesDomainExclusion"
);
const patterns = rules.exclusion_system.domain_patterns;

test("a query or fragment cannot impersonate an excluded domain", () => {
  const bypasses = [
    "https://evil.example?.google.com",
    "https://evil.example?.google.com/login",
    "https://phish.test?.google.co.uk/signin",
    "https://phish.test?.bing.com/signin",
    "https://phish.test?.zoom.us",
    "https://cred-harvest.invalid?.cyberdrain.com/a",
    "https://attacker.example?.linkedin.com",
    "https://attacker.example#.google.com",
    "https://attacker.example?.GOOGLE.com/login",
  ];

  for (const url of bypasses) {
    assert.equal(
      matchesDomainExclusion(url, patterns),
      false,
      url
    );
  }
});

test("legitimate excluded domains still skip detection", () => {
  const allowed = [
    "https://accounts.google.com/ServiceLogin",
    "https://www.google.com/search?q=microsoft+login",
    "https://cyberdrain.com/blog",
    "https://www.cyberdrain.com/",
    "https://sub.zoom.us/j/123",
    "https://contoso.zoom.us/signin",
    "https://login.microsoftonline.com/.google.com",
  ];

  assert.equal(matchesDomainExclusion(allowed[0], patterns), true);
  assert.equal(matchesDomainExclusion(allowed[1], patterns), true);
  assert.equal(matchesDomainExclusion(allowed[2], patterns), true);
  assert.equal(matchesDomainExclusion(allowed[3], patterns), true);
  assert.equal(matchesDomainExclusion(allowed[4], patterns), true);
  assert.equal(matchesDomainExclusion(allowed[5], patterns), true);
  // login.microsoftonline.com is not an exclusion pattern; only the real host counts.
  assert.equal(matchesDomainExclusion(allowed[6], patterns), false);
});

test("unrelated hosts and opaque urls are not excluded", () => {
  assert.equal(
    matchesDomainExclusion("https://notgoogle.com/login", patterns),
    false
  );
  assert.equal(
    matchesDomainExclusion("https://accounts.google.com.evil.example/", patterns),
    false
  );
  assert.equal(
    matchesDomainExclusion("https://evil.example/path?.google.com", patterns),
    false
  );
  assert.equal(matchesDomainExclusion("about:blank", patterns), false);
  assert.equal(matchesDomainExclusion("not a url", patterns), false);
});

test("content script exclusion uses origin matching", () => {
  const exclusionStart = contentSource.indexOf("function checkDomainExclusion");
  const allowlistStart = contentSource.indexOf("function checkUserUrlAllowlist");
  const exclusionSource = contentSource.slice(exclusionStart, allowlistStart);
  assert.match(exclusionSource, /matchesDomainExclusion\(/);
  assert.equal(exclusionSource.includes("regex.test(url)"), false);
});
