"use strict";
// Guards the CSP: the page must stay free of inline code and third-party resources,
// and every local file it loads must actually be deployed.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(root, f), "utf8");
const page = read("index.html");

test("no inline scripts, styles or event handlers", () => {
  assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)[^>]*>/i, "inline <script>");
  assert.doesNotMatch(page, /<style/i, "inline <style>");
  assert.doesNotMatch(page, /\sstyle=/i, "style attribute");
  assert.doesNotMatch(page, /\son[a-z]+=/i, "inline event handler");
});

test("no third-party scripts or stylesheets", () => {
  const external = [...page.matchAll(/<(?:script|link)[^>]+(?:src|href)="(https?:)?\/\//gi)];
  assert.deepEqual(external.map((m) => m[0]), []);
});

test("every local asset the page loads is deployed", () => {
  const allowed = read(".assetsignore").split("\n").filter((l) => l.startsWith("!")).map((l) => l.slice(1));
  const local = [...page.matchAll(/(?:src|href)="([^":#]+)"/g)].map((m) => m[1]);
  assert.ok(local.length > 0);
  for (const f of local) {
    assert.ok(allowed.includes(f), f + " is missing from .assetsignore");
    assert.ok(fs.existsSync(path.join(root, f)), f + " does not exist");
  }
});

test("CSP blocks network access and enforces Trusted Types", () => {
  const csp = read("_headers").match(/Content-Security-Policy: (.*)/)[1];
  for (const d of ["default-src 'none'", "script-src 'self'", "connect-src 'none'", "require-trusted-types-for 'script'"]) {
    assert.ok(csp.includes(d), "missing " + d);
  }
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https?:/);
});
