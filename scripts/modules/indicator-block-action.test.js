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

// Microsoft-styled password page that is not a full AAD clone: no loginfmt,
// idSIButton9, or type="submit", and the form posts to the current origin.
const PHISHING_PAGE = `<!DOCTYPE html><html><head><style>
body { font-family: Segoe UI; }
.card { max-width: 440px; }
button { background-color: #0067b8; }
</style></head><body>
<h1>Sign in to your Microsoft account</h1>
<form method="post">
<input type="password" name="password">
<button>Sign in</button>
</form>
</body></html>`;

function elementFound(element, pageSource) {
  if (element.type === "source_content") {
    return new RegExp(element.pattern, "i").test(pageSource);
  }
  if (element.type === "css_pattern") {
    return element.patterns.some((pattern) =>
      new RegExp(pattern, "i").test(pageSource)
    );
  }
  return false;
}

function classifyPage(pageSource) {
  const requirements = rules.m365_detection_requirements;
  const allElements = [
    ...(requirements.primary_elements || []),
    ...(requirements.secondary_elements || []),
  ];
  let weight = 0;
  let elements = 0;
  let primary = 0;
  for (const element of allElements) {
    if (!elementFound(element, pageSource)) continue;
    weight += element.weight || 1;
    elements += 1;
    if (element.category === "primary") primary += 1;
  }
  const thresholds = requirements.detection_thresholds;
  const isLogon =
    primary > 0
      ? primary >= thresholds.minimum_primary_elements &&
        weight >= thresholds.minimum_total_weight &&
        elements >= thresholds.minimum_elements_overall
      : weight >= thresholds.minimum_secondary_only_weight &&
        elements >= thresholds.minimum_secondary_only_elements;
  const hasMicrosoftElements =
    primary > 0 || weight >= 4 || (elements >= 3 && weight >= 3);
  return { isLogon, hasMicrosoftElements, weight, elements, primary };
}

function matchingIndicators(pageSource) {
  const threats = [];
  for (const indicator of rules.phishing_indicators) {
    let matches = false;
    try {
      matches = new RegExp(indicator.pattern, indicator.flags || "i").test(
        pageSource
      );
    } catch {
      matches = false;
    }
    if (!matches && indicator.additional_checks) {
      matches = indicator.additional_checks.some((check) =>
        pageSource.includes(check)
      );
    }
    if (matches && indicator.context_required) {
      const found = indicator.context_required.some((required) =>
        pageSource.toLowerCase().includes(required.toLowerCase())
      );
      if (!found) matches = false;
    }
    if (matches) {
      threats.push({
        id: indicator.id,
        severity: indicator.severity,
        action: indicator.action,
      });
    }
  }
  return threats;
}

function nonLogonBlockPredicate() {
  const marker = "PHISHING INDICATORS FOUND on non-Microsoft page";
  const start = contentSource.indexOf(marker);
  assert.notEqual(start, -1);
  const slice = contentSource.slice(start, start + 900);
  const match = slice.match(
    /const criticalThreats = phishingResult\.threats\.filter\(\s*\(t\) => ([^;]+?)\s*\);/
  );
  assert.ok(match, "non-logon block filter not found");
  return new Function("t", `return (${match[1]});`);
}

test("microsoft-styled password page is scanned but is not a full logon", () => {
  const classification = classifyPage(PHISHING_PAGE);
  assert.equal(classification.hasMicrosoftElements, true);
  assert.equal(classification.isLogon, false);
  assert.equal(classification.primary, 0);
});

test("phi_017 is the only match and the non-logon path blocks it", () => {
  const threats = matchingIndicators(PHISHING_PAGE);
  assert.deepEqual(
    threats.map((threat) => threat.id),
    ["phi_017_microsoft_brand_abuse"]
  );
  assert.equal(threats[0].severity, "high");
  assert.equal(threats[0].action, "block");

  const blocks = nonLogonBlockPredicate();
  assert.equal(threats.some(blocks), true);
  assert.equal(
    threats.some((threat) => threat.severity === "critical" && threat.action === "block"),
    false
  );
  assert.equal(threats.length >= 3, false);
});

test("warn actions stay out of the non-logon block filter", () => {
  const blocks = nonLogonBlockPredicate();
  assert.equal(blocks({ severity: "high", action: "block" }), true);
  assert.equal(blocks({ severity: "critical", action: "block" }), true);
  assert.equal(blocks({ severity: "high", action: "warn" }), false);
  assert.equal(blocks({ severity: "critical", action: "warn" }), false);
  assert.equal(blocks({ severity: "medium", action: "warn" }), false);
});
