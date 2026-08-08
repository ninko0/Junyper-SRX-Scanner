"use strict";
// Static frontend — vanilla JS, no framework, no eval, no inline JS
// (consistent with the strict CSP set server-side, task 05).
//
// Systematic rule: anything coming from the API is inserted via
// `textContent`, never `innerHTML`, so an object name, error message, or
// warning from the uploaded conf is never interpreted as HTML (cf task 06,
// frontend security constraints).

// ----------------------------- Tabs -----------------------------------------

document.getElementById("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab-btn");
  if (!btn) return;
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
});

// ----------------------------- Helpers --------------------------------------

async function postForm(url, formData) {
  const resp = await fetch(url, { method: "POST", body: formData });
  return resp;
}

async function readErrorMessage(resp) {
  try {
    const body = await resp.json();
    if (body && typeof body.error === "string") return body.error;
  } catch (_) {
    /* non-JSON body: generic message */
  }
  return "An error occurred (code " + resp.status + ").";
}

function showError(el, message) {
  el.textContent = message;
  el.hidden = false;
}

function hideError(el) {
  el.hidden = true;
  el.textContent = "";
}

function downloadBlob(filename, content, mime) {
  const blob = new Blob([content], { type: mime || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function filenameFromContentDisposition(resp, fallback) {
  const cd = resp.headers.get("Content-Disposition") || "";
  const m = /filename="?([^"]+)"?/.exec(cd);
  return m ? m[1] : fallback;
}

// clientRenamedFilename: backlog item 4, client-side half. Used only for
// downloads built entirely in the browser (rename.set, cleanup.set, and
// their rollbacks) — there is no server-side file behind these, so this
// is pure UX, not a security boundary. The equivalent, security-relevant
// sanitization for server-served downloads lives in
// internal/api/filename.go's sanitizeDownloadName, applied via the "as"
// query/form parameter (see setLink and the rename-suggest-form's "as"
// field below).
function clientRenamedFilename(rawName, fallback) {
  const trimmed = (rawName || "").trim();
  if (!trimmed) return fallback;
  const ext = fallback.slice(fallback.lastIndexOf("."));
  const base = trimmed
    .replace(/^.*[\\/]/, "") // drop any path-looking prefix
    .replace(/\.[^.]*$/, "") // drop a client-typed extension, real one is forced below
    .replace(/[^A-Za-z0-9 _.-]/g, "_")
    .trim()
    .slice(0, 80);
  return base ? base + ext : fallback;
}

// Display order of severity badges, matching the XLSX palette.
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_CLASS = {
  CRITICAL: "b-crit", HIGH: "b-high", MEDIUM: "b-med", LOW: "b-low", INFO: "b-info",
};

// ----------------------------- Analyze tab -----------------------------------

const analyzeForm = document.getElementById("analyze-form");
const analyzeError = document.getElementById("analyze-error");
const analyzeLoading = document.getElementById("analyze-loading");
const analyzeResults = document.getElementById("analyze-results");
const warnBanner = document.getElementById("warn-banner");

analyzeForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError(analyzeError);
  analyzeResults.hidden = true;
  analyzeLoading.hidden = false;

  const fd = new FormData(analyzeForm);
  try {
    const resp = await postForm("/api/analyze", fd);
    if (!resp.ok) {
      showError(analyzeError, await readErrorMessage(resp));
      return;
    }
    const data = await resp.json();
    renderAnalyzeResults(data);
  } catch (err) {
    showError(analyzeError, "Could not reach the server.");
  } finally {
    analyzeLoading.hidden = true;
  }
});

function renderAnalyzeResults(data) {
  // Warning banner (model's source_format + warnings) — useful to know
  // whether the conf was read as XML/curly/set and whether unresolved
  // groups exist (cf task 06, preserving useful content).
  if (data.warnings && data.warnings.length > 0) {
    warnBanner.textContent =
      "Detected format: " + data.source_format + ". " +
      data.warnings.length + " parsing warning(s): " +
      data.warnings.join(" | ");
    warnBanner.hidden = false;
  } else {
    warnBanner.hidden = true;
  }

  document.getElementById("audit-total").textContent = data.audit.total;
  const badgeContainer = document.getElementById("audit-badges");
  badgeContainer.replaceChildren();
  for (const sev of SEVERITY_ORDER) {
    const n = (data.audit.summary && data.audit.summary[sev]) || 0;
    const span = document.createElement("span");
    span.className = "badge " + (SEVERITY_CLASS[sev] || "");
    span.textContent = sev + ": " + n;
    badgeContainer.appendChild(span);
  }

  document.getElementById("inv-zones").textContent = data.inventory.zones;
  document.getElementById("inv-vlans").textContent = data.inventory.vlans;
  document.getElementById("inv-policies").textContent = data.inventory.policies;
  document.getElementById("inv-addrs").textContent = data.inventory.address_objects;

  setLink("dl-audit-txt", data.downloads.audit_report_txt, "audit-dl-name", "-audit-report");
  setLink("dl-audit-json", data.downloads.audit_report_json, "audit-dl-name", "-audit-report");
  setLink("dl-audit-xlsx", data.downloads.audit_report_xlsx, "audit-dl-name", "-audit-report");
  setLink("dl-audit-fix", data.downloads.audit_fix_set, "audit-dl-name", "-audit-fix");
  setLink("dl-inv-txt", data.downloads.inventory_report_txt, "inv-dl-name", "-inventory");
  setLink("dl-inv-json", data.downloads.inventory_report_json, "inv-dl-name", "-inventory");
  setLink("dl-inv-xlsx", data.downloads.inventory_report_xlsx, "inv-dl-name", "-inventory");

  // Keep the inventory JSON at hand for the cleanup tab: saves the user
  // from having to manually re-download then re-upload it.
  fetch(data.downloads.inventory_report_json)
    .then((r) => (r.ok ? r.blob() : null))
    .then((blob) => {
      if (blob) window.__lastInventoryBlob = blob;
    })
    .catch(() => {});

  analyzeResults.hidden = false;
}

// setLink wires a download link to its base URL (as returned by the API,
// with the server-generated sid — never built from free-form client-side
// input, cf task 06) and, if a "rename downloads" input is given, keeps
// the link's "?as=" query param in sync with what the user types there.
// The actual sanitization of that value happens server-side
// (internal/api/filename.go's sanitizeDownloadName) — the client only
// ever supplies a hint, never anything that changes which file is read.
function setLink(id, baseHref, renameInputId, suffix) {
  const a = document.getElementById(id);
  const apply = () => {
    const raw = renameInputId ? (document.getElementById(renameInputId).value || "").trim() : "";
    a.href = raw ? baseHref + "?as=" + encodeURIComponent(raw + (suffix || "")) : baseHref;
  };
  apply();
  if (renameInputId) {
    // oninput (not addEventListener) so re-running analyze doesn't stack
    // duplicate listeners on the same input across submissions.
    document.getElementById(renameInputId).oninput = apply;
  }
}

// ----------------------------- Rename tab -------------------------------------

const renameSuggestForm = document.getElementById("rename-suggest-form");
const renameSuggestError = document.getElementById("rename-suggest-error");

renameSuggestForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError(renameSuggestError);
  const fd = new FormData(renameSuggestForm);
  if (!document.getElementById("rename-dns").checked) fd.delete("dns");
  try {
    const resp = await postForm("/api/rules/rename/suggest", fd);
    if (!resp.ok) {
      showError(renameSuggestError, await readErrorMessage(resp));
      return;
    }
    const text = await resp.text();
    const filename = filenameFromContentDisposition(resp, "rename-plan.csv");
    downloadBlob(filename, text, "text/csv");
  } catch (err) {
    showError(renameSuggestError, "Could not reach the server.");
  }
});

const renameApplyForm = document.getElementById("rename-apply-form");
const renameApplyError = document.getElementById("rename-apply-error");
const renameApplyResults = document.getElementById("rename-apply-results");
const renameRejected = document.getElementById("rename-rejected");
const renameSetOutput = document.getElementById("rename-set-output");
const renameRollbackOutput = document.getElementById("rename-rollback-output");

renameApplyForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError(renameApplyError);
  renameApplyResults.hidden = true;
  const fd = new FormData(renameApplyForm);
  try {
    const resp = await postForm("/api/rules/rename/apply", fd);
    if (!resp.ok) {
      showError(renameApplyError, await readErrorMessage(resp));
      return;
    }
    const data = await resp.json();
    if (data.rejected && data.rejected.length > 0) {
      renameRejected.textContent =
        data.rejected.length + " line(s) rejected — no command generated for these:\n" +
        data.rejected.join("\n");
      renameRejected.hidden = false;
    } else {
      renameRejected.hidden = true;
    }
    const setText = (data.set_commands || []).join("\n");
    const rbText = (data.rollback || []).join("\n");
    renameSetOutput.textContent = setText;
    renameRollbackOutput.textContent = rbText;
    document.getElementById("rename-download-set").onclick = () =>
      downloadBlob(
        clientRenamedFilename(document.getElementById("rename-set-name").value, "rename.set"),
        setText, "text/plain");
    document.getElementById("rename-download-rollback").onclick = () =>
      downloadBlob(
        clientRenamedFilename(document.getElementById("rename-rollback-name").value, "rename-rollback.set"),
        rbText, "text/plain");
    renameApplyResults.hidden = false;
  } catch (err) {
    showError(renameApplyError, "Could not reach the server.");
  }
});

// ----------------------------- Cleanup tab ------------------------------------

const cleanupForm = document.getElementById("cleanup-form");
const cleanupError = document.getElementById("cleanup-error");
const cleanupResults = document.getElementById("cleanup-results");

cleanupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError(cleanupError);
  cleanupResults.hidden = true;
  document.getElementById("cleanup-warning").hidden = true;

  const fd = new FormData(cleanupForm);
  // "exclude" is a multi-line textarea on the form; the API expects a
  // repeated field.
  const excludeRaw = fd.get("exclude") || "";
  fd.delete("exclude");
  for (const line of String(excludeRaw).split("\n")) {
    const v = line.trim();
    if (v) fd.append("exclude", v);
  }
  if (!document.getElementById("cleanup-include-deny").checked) fd.delete("include_deny");

  try {
    const resp = await postForm("/api/rules/cleanup", fd);
    if (!resp.ok) {
      showError(cleanupError, await readErrorMessage(resp));
      return;
    }
    const data = await resp.json();
    renderCleanupResults(data);
  } catch (err) {
    showError(cleanupError, "Could not reach the server.");
  }
});

function fillPolicyList(ulId, countId, policies) {
  const ul = document.getElementById(ulId);
  ul.replaceChildren();
  for (const p of policies) {
    const li = document.createElement("li");
    li.textContent = p.from_zone + " -> " + p.to_zone + " : " + p.name + " [" + p.action + "]";
    ul.appendChild(li);
  }
  document.getElementById(countId).textContent = policies.length;
}

function renderCleanupResults(data) {
  const warningEl = document.getElementById("cleanup-warning");
  if (data.warning) {
    warningEl.textContent = data.warning;
    warningEl.hidden = false;
  } else {
    warningEl.hidden = true;
  }

  fillPolicyList("cleanup-list-candidates", "cleanup-count-candidates", data.candidates || []);
  fillPolicyList("cleanup-list-denied", "cleanup-count-denied", data.kept_deny || []);
  fillPolicyList("cleanup-list-excluded", "cleanup-count-excluded", data.excluded || []);
  fillPolicyList("cleanup-list-unknown", "cleanup-count-unknown", data.unknown || []);

  const setText = (data.set_commands || []).join("\n");
  const rbText = (data.rollback || []).join("\n");
  document.getElementById("cleanup-set-output").textContent = setText;
  document.getElementById("cleanup-rollback-output").textContent = rbText;
  document.getElementById("cleanup-download-set").onclick = () =>
    downloadBlob(
      clientRenamedFilename(document.getElementById("cleanup-set-name").value, "cleanup.set"),
      setText, "text/plain");
  document.getElementById("cleanup-download-rollback").onclick = () =>
    downloadBlob(
      clientRenamedFilename(document.getElementById("cleanup-rollback-name").value, "cleanup-rollback.set"),
      rbText, "text/plain");

  cleanupResults.hidden = false;
}
