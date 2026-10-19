"use strict";

const HEX_PREVIEW_BYTES = 128;

// The CSP enforces Trusted Types, so this is the only way to write HTML.
// Its one caller, renderCard, escapes every file-derived value first.
const html = window.trustedTypes
  ? trustedTypes.createPolicy("neonsig", { createHTML: (s) => s })
  : { createHTML: (s) => s };
const BIG_FILE_BYTES = 200 * 1024 * 1024;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return (i === 0 ? val : val.toFixed(2)) + " " + units[i];
}

const reports = [];
const el = (id) => document.getElementById(id);
const resultsEl = el("results");
const emptyEl = resultsEl.querySelector(".empty");
const dropEl = el("drop");
const inputEl = el("fileInput");

function buildHexPreview(bytes) {
  const limit = Math.min(bytes.length, HEX_PREVIEW_BYTES);
  const rows = [];
  for (let base = 0; base < limit; base += 16) {
    const off = base.toString(16).padStart(8, "0").toUpperCase();
    let hex = "";
    let asc = "";
    for (let i = 0; i < 16; i++) {
      if (base + i < limit) {
        const b = bytes[base + i];
        hex += b.toString(16).padStart(2, "0").toUpperCase() + " ";
        asc += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
      } else {
        hex += "   ";
        asc += " ";
      }
    }
    rows.push('<span class="off">' + off + '</span>  ' + hex + ' <span class="asc">' + escapeHtml(asc) + "</span>");
  }
  return rows.join("\n");
}

function field(key, value, cls) {
  return '<div class="field"><span class="k">' + escapeHtml(key) + '</span>' +
    '<span class="v ' + (cls || "") + '">' + escapeHtml(value) + "</span></div>";
}

function renderCard(report, hexBytes) {
  const card = document.createElement("div");
  card.className = "card s-" + report.status;

  const badge = '<span class="badge ' + report.status + '">' + report.status.toUpperCase() + "</span>";
  const head = '<div class="card-head"><span class="fname">' + escapeHtml(report.filename) + "</span>" + badge + "</div>";

  const warn = report.warning
    ? '<div class="warn ' + (report.status === "ambiguous" ? "ambiguous" : "") + '">' + escapeHtml(report.warning) + "</div>"
    : "";

  const grid = '<div class="grid">' +
    field("Claimed extension", report.extension ? "." + report.extension : "(none)") +
    field("Browser MIME (claim)", report.browserMime || "(not provided)") +
    field("Detected type", report.detectedType, "cyan") +
    field("Detected MIME", report.detectedMime || "(n/a)", "cyan") +
    field("Confidence", report.confidence) +
    field("Signature", report.signature, "magenta") +
    field("Offset", report.offset === null ? "(n/a)" : String(report.offset)) +
    field("Size", formatSize(report.size)) +
    (report.notes ? field("Evidence", report.notes) : "") +
    "</div>";

  const hex = hexBytes
    ? '<details><summary>Hex preview (first ' + Math.min(hexBytes.length, HEX_PREVIEW_BYTES) + ' bytes)</summary>' +
        '<div class="hex">' + buildHexPreview(hexBytes) + "</div></details>"
    : "";

  card.innerHTML = html.createHTML(head + warn + grid + hex);
  return card;
}

function clearEmptyState() {
  emptyEl.remove();
}

function updateSummary() {
  const counts = { total: reports.length, match: 0, mismatch: 0, ambiguous: 0, unknown: 0 };
  for (const r of reports) {
    const key = r.status === "error" ? "unknown" : r.status;
    counts[key] = (counts[key] || 0) + 1;
  }
  el("statTotal").textContent = counts.total;
  el("statMatch").textContent = counts.match;
  el("statMismatch").textContent = counts.mismatch;
  el("statAmbiguous").textContent = counts.ambiguous;
  el("statUnknown").textContent = counts.unknown;
  const hasData = reports.length > 0;
  el("copyBtn").disabled = !hasData;
  el("clearBtn").disabled = !hasData;
}

async function scanFile(file) {
  try {
    const header = await readHeader(file);
    const detection = detectType(file, header);
    const hexBytes = header.subarray(0, Math.min(header.length, HEX_PREVIEW_BYTES));
    const actualExt = getExtension(file.name);
    const evaluation = evaluate(detection, actualExt);

    const report = {
      filename: file.name,
      size: file.size,
      extension: actualExt,
      browserMime: file.type || "",
      detectedType: detection.label,
      detectedMime: detection.mime || null,
      status: evaluation.status,
      confidence: detection.confidence,
      signature: detection.signature,
      offset: detection.offset,
      notes: detection.notes || "",
      warning: evaluation.warning
    };
    if (file.size > BIG_FILE_BYTES) {
      report.notes = (report.notes ? report.notes + " " : "") + "(Large file: only the header window was read.)";
    }

    reports.push(report);
    resultsEl.prepend(renderCard(report, hexBytes));
    updateSummary();
  } catch (err) {
    const msg = (err && err.message) ? err.message : String(err);
    const report = {
      filename: file.name, size: file.size, extension: getExtension(file.name),
      browserMime: file.type || "", detectedType: "Unreadable", detectedMime: null,
      status: "error", confidence: "n/a", signature: "(read error)", offset: null,
      notes: msg, warning: "The file could not be read: " + msg
    };
    reports.push(report);
    resultsEl.prepend(renderCard(report, null));
    updateSummary();
  }
}

async function scanFiles(fileList) {
  const files = Array.from(fileList || []);
  if (files.length === 0) return;
  clearEmptyState();
  for (const file of files) {
    // Sequential to keep memory low and preserve stable ordering.
    await scanFile(file);
  }
}

function buildReport() {
  return reports.map(({ warning, ...r }) => ({
    ...r,
    extension: r.extension || null,
    browserMime: r.browserMime || null,
    notes: r.notes || null
  }));
}

function showToast(message) {
  const t = el("toast");
  t.textContent = message;
  t.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => t.classList.remove("show"), 1800);
}

async function copyReport() {
  const json = JSON.stringify(buildReport(), null, 2);
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(json);
    } else {
      // Fallback for non-secure contexts / older browsers.
      const ta = document.createElement("textarea");
      ta.value = json;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    showToast("Report copied (" + reports.length + " file" + (reports.length === 1 ? "" : "s") + ")");
  } catch (e) {
    showToast("Copy failed \u2014 see console");
    console.error("Copy failed:", e);
  }
}

function clearResults() {
  reports.length = 0;
  resultsEl.replaceChildren(emptyEl);
  updateSummary();
}

function onDropEvent(e) {
  e.preventDefault();
  e.stopPropagation();
  if (e.type === "dragenter" || e.type === "dragover") dropEl.classList.add("drag");
  if (e.type === "dragleave" || e.type === "drop") dropEl.classList.remove("drag");
  if (e.type === "drop" && e.dataTransfer?.files?.length) scanFiles(e.dataTransfer.files);
}
["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => dropEl.addEventListener(evt, onDropEvent));

const openPicker = () => inputEl.click();
dropEl.addEventListener("click", openPicker);
dropEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openPicker(); }
});
el("pickBtn").addEventListener("click", openPicker);

inputEl.addEventListener("change", (e) => {
  scanFiles(e.target.files);
  e.target.value = "";
});

el("copyBtn").addEventListener("click", copyReport);
el("clearBtn").addEventListener("click", clearResults);

["dragover", "drop"].forEach((evt) => {
  window.addEventListener(evt, (e) => { e.preventDefault(); }, false);
});

updateSummary();
