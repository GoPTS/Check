/**
 * Credential submission targets.
 *
 * Blocking rules historically read only form.action. A submit button can
 * override that with formaction, and a submit handler can replace the action
 * before the browser posts. Those URLs are the ones that receive the password.
 */
(function () {
  "use strict";

  function isAllowedCredentialDestination(rawUrl, allowedHost, baseUrl) {
    const allowed = String(allowedHost || "")
      .trim()
      .toLowerCase()
      .replace(/^\.+|\.+$/g, "");
    if (!allowed || /[\s/]/.test(allowed)) return false;

    const base = baseUrl || "https://invalid.invalid/";
    let url;
    try {
      const raw = rawUrl == null ? "" : String(rawUrl).trim();
      url = new URL(raw === "" ? base : raw, base);
    } catch (error) {
      return false;
    }

    if (url.protocol !== "https:" && url.protocol !== "http:") return false;
    const host = url.hostname.toLowerCase().replace(/\.+$/, "");
    return host === allowed || host.endsWith("." + allowed);
  }

  function isSubmittingControl(node) {
    if (!node || typeof node.getAttribute !== "function") return false;
    const tag = String(node.tagName || "").toLowerCase();
    const type = String(node.getAttribute("type") || "").toLowerCase();
    if (tag === "button") return type === "" || type === "submit";
    if (tag === "input") return type === "submit" || type === "image";
    return false;
  }

  function controlBelongsToForm(control, form) {
    if (!control || !form) return false;
    if (control.form) return control.form === form;
    const formId = control.getAttribute && control.getAttribute("form");
    return Boolean(formId) && formId === form.id;
  }

  /**
   * First formaction on this password form whose host is not allowedHost.
   * The form's own action is intentionally not inspected here.
   */
  function findUntrustedFormaction(form, allowedHost, baseUrl) {
    if (!form || !allowedHost || typeof form.querySelector !== "function") {
      return null;
    }
    if (!form.querySelector('input[type="password"]')) return null;

    const doc = form.ownerDocument;
    if (!doc || typeof doc.querySelectorAll !== "function") return null;

    const controls = doc.querySelectorAll("button[formaction], input[formaction]");
    for (const control of controls) {
      if (!isSubmittingControl(control)) continue;
      if (!controlBelongsToForm(control, form)) continue;
      const raw = control.getAttribute("formaction");
      if (raw == null) continue;
      if (!isAllowedCredentialDestination(raw, allowedHost, baseUrl)) {
        let resolved = raw;
        try {
          resolved = new URL(String(raw).trim() || baseUrl, baseUrl).href;
        } catch (error) {
          resolved = raw;
        }
        return { raw: raw, resolved: resolved };
      }
    }
    return null;
  }

  /**
   * URL the browser will post to for this submit event.
   * Prefers a submitter formaction, then the submitter's effective formAction,
   * then the form action attribute, then the page URL.
   */
  function effectiveSubmissionUrl(form, submitter, baseUrl) {
    if (
      submitter &&
      typeof submitter.hasAttribute === "function" &&
      submitter.hasAttribute("formaction")
    ) {
      return submitter.getAttribute("formaction") || "";
    }
    if (
      submitter &&
      typeof submitter.formAction === "string" &&
      submitter.formAction
    ) {
      return submitter.formAction;
    }
    if (form && typeof form.getAttribute === "function" && form.hasAttribute("action")) {
      const action = form.getAttribute("action");
      if (action != null) return action;
    }
    return baseUrl || "";
  }

  globalThis.CheckSubmissionTargets = {
    isAllowedCredentialDestination: isAllowedCredentialDestination,
    findUntrustedFormaction: findUntrustedFormaction,
    effectiveSubmissionUrl: effectiveSubmissionUrl,
  };
})();
