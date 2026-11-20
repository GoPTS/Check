/**
 * Read DOM that light-DOM APIs skip.
 * Phishing pages hide Microsoft login clones inside open or closed shadow
 * roots. document.outerHTML and querySelector do not cross those boundaries,
 * and element.shadowRoot is null when the root is closed. Content scripts can
 * still read closed roots through chrome.dom.openOrClosedShadowRoot.
 */
(function initCheckDeepDom(global) {
  "use strict";

  function getHostShadowRoot(element) {
    if (!element || element.nodeType !== 1) return null;

    try {
      const domApi = global.chrome && global.chrome.dom;
      if (domApi && typeof domApi.openOrClosedShadowRoot === "function") {
        const root = domApi.openOrClosedShadowRoot(element);
        if (root) return root;
      }
    } catch (error) {
      // Fall through to the open-root accessor.
    }

    try {
      return element.shadowRoot || null;
    } catch (error) {
      return null;
    }
  }

  function forEachShadowRoot(start, visit) {
    const seen = new Set();
    const stack = [start];

    while (stack.length) {
      const node = stack.pop();
      if (!node || seen.has(node)) continue;
      seen.add(node);

      if (node.nodeType === 1) {
        const ownShadow = getHostShadowRoot(node);
        if (ownShadow && !seen.has(ownShadow)) {
          visit(ownShadow);
          stack.push(ownShadow);
        }
      }

      let elements = [];
      try {
        if (node.querySelectorAll) elements = node.querySelectorAll("*");
      } catch (error) {
        elements = [];
      }

      for (const element of elements) {
        const shadow = getHostShadowRoot(element);
        if (shadow && !seen.has(shadow)) {
          visit(shadow);
          stack.push(shadow);
        }
      }
    }
  }

  function listShadowRoots(start) {
    const roots = [];
    forEachShadowRoot(start, (root) => {
      roots.push(root);
    });
    return roots;
  }

  function queryAllDeep(start, selector) {
    const matches = [];
    const seen = new Set();
    const roots = [start];
    const seenRoots = new Set();

    while (roots.length) {
      const root = roots.pop();
      if (!root || seenRoots.has(root)) continue;
      seenRoots.add(root);

      try {
        if (root.nodeType === 1 && root.matches && root.matches(selector)) {
          if (!seen.has(root)) {
            seen.add(root);
            matches.push(root);
          }
        }
      } catch (error) {
        // Invalid selector or non-element root. Keep searching other trees.
      }

      try {
        if (root.querySelectorAll) {
          for (const element of root.querySelectorAll(selector)) {
            if (!seen.has(element)) {
              seen.add(element);
              matches.push(element);
            }
          }
        }
      } catch (error) {
        // Invalid selector in this tree.
      }

      forEachShadowRoot(root, (shadow) => {
        if (!seenRoots.has(shadow)) roots.push(shadow);
      });
    }

    return matches;
  }

  function getDeepPageSource(doc) {
    const documentNode = doc && doc.nodeType === 9 ? doc : doc.ownerDocument;
    let html = "";
    try {
      html = documentNode.documentElement
        ? documentNode.documentElement.outerHTML
        : "";
    } catch (error) {
      html = "";
    }

    const extras = [];
    forEachShadowRoot(documentNode, (shadow) => {
      try {
        extras.push(shadow.innerHTML || "");
      } catch (error) {
        // Skip roots that cannot be serialized.
      }
    });

    if (!extras.length) return html;
    return html + "\n" + extras.join("\n");
  }

  function getDeepPageText(doc) {
    const documentNode = doc && doc.nodeType === 9 ? doc : doc.ownerDocument;
    const parts = [];
    try {
      parts.push(
        documentNode.body ? documentNode.body.textContent || "" : ""
      );
    } catch (error) {
      // Ignore a missing body.
    }

    forEachShadowRoot(documentNode, (shadow) => {
      try {
        parts.push(shadow.textContent || "");
      } catch (error) {
        // Skip unreadable roots.
      }
    });

    return parts.join("\n");
  }

  global.checkDeepDom = {
    getHostShadowRoot: getHostShadowRoot,
    listShadowRoots: listShadowRoots,
    queryAllDeep: queryAllDeep,
    getDeepPageSource: getDeepPageSource,
    getDeepPageText: getDeepPageText,
  };
})(typeof globalThis !== "undefined" ? globalThis : window);
