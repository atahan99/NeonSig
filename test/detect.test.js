"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { hexToBytes, getExtension, revealName, readHeader, detectType, evaluate } = require("../detect.js");

const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
// Pad a header with zeros so offset-based checks (TAR at 257, PE at 0x3C) have room.
const pad = (bytes, n = 512) => { const a = new Uint8Array(Math.max(n, bytes.length)); a.set(bytes); return a; };

async function scan(content, name) {
  const file = new File([content], name);
  const d = detectType(file, await readHeader(file));
  return { id: d.id, status: evaluate(d, name).status };
}

function zipWith(...names) {
  const parts = [];
  for (const n of names) {
    const h = new Uint8Array(30 + n.length);
    h.set([0x50, 0x4b, 0x03, 0x04]);
    h[26] = n.length;
    h.set(ascii(n), 30);
    parts.push(...h);
  }
  return new Uint8Array(parts);
}

function peFile(characteristics) {
  const b = pad([0x4d, 0x5a]);
  b[0x3c] = 0x80;
  b.set(ascii("PE\0\0"), 0x80);
  b[0x80 + 22] = characteristics & 0xff;
  b[0x80 + 23] = characteristics >> 8;
  return b;
}

function ftyp(brand) { return pad([0, 0, 0, 0x18, ...ascii("ftyp" + brand), 0, 0, 0, 0, ...ascii(brand + "isom")], 64); }
function riff(form) { return pad([...ascii("RIFF"), 0, 0, 0, 0, ...ascii(form)], 64); }

const tar = pad([...ascii("file.txt")], 512);
tar.set(ascii("ustar"), 257);

// [description, content, file name, expected id, expected status]
const cases = [
  ["PNG", pad(hexToBytes("89 50 4E 47 0D 0A 1A 0A 00 00 00 0D")), "a.png", "png", "match"],
  ["JPEG, uppercase extension", pad([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), "IMG.JPG", "jpeg", "match"],
  ["GIF", pad(ascii("GIF89a")), "a.gif", "gif", "match"],
  ["real BMP", pad([...ascii("BM"), 0x46, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0, 0x28, 0, 0, 0]), "a.bmp", "bmp", "match"],
  ["PDF", "%PDF-1.7\n%\xe2\xe3\n", "a.pdf", "pdf", "match"],
  ["PDF renamed to .png", "%PDF-1.7\n", "invoice.png", "pdf", "mismatch"],
  ["PDF with no extension", "%PDF-1.4\n", "invoice", "pdf", "ambiguous"],
  ["DOCX", zipWith("[Content_Types].xml", "word/document.xml"), "a.docx", "docx", "match"],
  ["XLSX", zipWith("xl/workbook.xml"), "a.xlsx", "xlsx", "match"],
  ["APK beats JAR", zipWith("META-INF/MANIFEST.MF", "AndroidManifest.xml"), "app.apk", "apk", "match"],
  ["JAR", zipWith("META-INF/MANIFEST.MF"), "lib.jar", "jar", "match"],
  ["plain ZIP", zipWith("photo.jpg"), "a.zip", "zip", "match"],
  ["GZIP", pad([0x1f, 0x8b, 0x08, 0x00]), "a.tar.gz", "gzip", "match"],
  ["real BZIP2", pad([...ascii("BZh9"), 0x31, 0x41, 0x59, 0x26, 0x53, 0x59]), "a.bz2", "bzip2", "match"],
  ["TAR (ustar at 257)", tar, "a.tar", "tar", "match"],
  ["real ID3 MP3", pad([...ascii("ID3"), 3, 0, 0, 0, 0, 0x1f, 0x76]), "a.mp3", "mp3id3", "match"],
  ["WAV", riff("WAVE"), "a.wav", "wav", "match"],
  ["WebP", riff("WEBP"), "a.webp", "webp", "match"],
  ["MP4", ftyp("mp42"), "a.mp4", "mp4", "match"],
  ["HEIC", ftyp("heic"), "a.heic", "heic", "match"],
  ["WebM", pad([0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x82, 0x84, ...ascii("webm")]), "a.webm", "webm", "match"],
  ["EXE", peFile(0x0102), "a.exe", "exe", "match"],
  ["DLL", peFile(0x2102), "a.dll", "dll", "match"],
  ["EXE disguised as PDF", peFile(0x0102), "invoice.pdf", "exe", "mismatch"],
  ["ELF", pad([0x7f, ...ascii("ELF"), 2, 1, 1]), "lib.so", "elf", "match"],
  ["Java class", pad([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), "A.class", "javaclass", "match"],
  ["SQLite", pad([...ascii("SQLite format 3"), 0]), "a.db", "sqlite", "match"],
  ["JSON", '{"a": 1, "b": [2, 3]}', "a.json", "json", "match"],
  ["CSV", "a,b\n1,2\n3,4\n", "a.csv", "csv", "match"],
  ["Markdown", "# Title\n\nSome text.\n", "README.md", "markdown", "match"],
  ["SVG", '<?xml version="1.0"?>\n<!-- logo -->\n<svg xmlns="http://www.w3.org/2000/svg"></svg>', "logo.svg", "svg", "match"],
  ["empty file", "", "a.txt", null, "unknown"],
  ["random binary", pad([0x13, 0x37, 0x00, 0x99, 0x01]), "a.bin", null, "unknown"],
  ["hostile file name is just a name", "hi\n", "<img src=x onerror=alert(1)>.txt", "txt", "match"],

  // Regressions: text whose first letters collide with short magic numbers.
  ["text starting with BM", "BMW service log\n2024-01-02 oil change\n", "service-log.txt", "txt", "match"],
  ["text starting with BZh", "BZh is a thing\nhello\n", "notes.txt", "txt", "match"],
  ["text starting with ID3", "ID3 tags explained\nmore\n", "readme.txt", "txt", "match"],
  ["text starting with MZ", "MZ start of doc\nyes\n", "doc.txt", "txt", "match"],
  // Regressions: <svg> inside other text formats is not an SVG file.
  ["HTML with inline SVG", '<!doctype html><html><body><svg viewBox="0 0 1 1"></svg></body></html>', "index.html", "html", "match"],
  ["XML mentioning <svg>", '<?xml version="1.0"?><doc><note>use <svg> tags</note></doc>', "a.xml", "xml", "match"],
  ["Markdown mentioning <svg>", "# Icons\nUse <svg> inline\n", "a.md", "markdown", "match"],
  // Regressions: 4-byte ASCII magics in ordinary text.
  ["text starting with OTTO", "OTTO meeting notes\nagenda\n", "otto.txt", "txt", "match"],
  ["text starting with RIFF", "RIFF raff\nhello\n", "riff.txt", "txt", "match"],

  // Containers: other ZIP-based names stay open, unrelated names are lies.
  ["ZIP named .jpg", zipWith("photo.jpg"), "cat.jpg", "zip", "mismatch"],
  ["ZIP named .docx, parts not in window", zipWith("[Content_Types].xml"), "a.docx", "zip", "ambiguous"],
  ["legacy Office named .pdf", pad(hexToBytes("D0 CF 11 E0 A1 B1 1A E1")), "invoice.pdf", "ole", "mismatch"],
  ["MZ without PE header named .pdf", pad([0x4d, 0x5a, 0x90, 0, 3]), "invoice.pdf", "pe", "mismatch"],

  // No extension claims nothing, so it is never a mismatch.
  ["ELF with no extension", pad([0x7f, ...ascii("ELF"), 2, 1, 1]), "ls", "elf", "ambiguous"],

  // Text family: any text extension fits any text content.
  ["text list in .txt", "Groceries\n- milk\n- eggs\n", "todo.txt", "markdown", "match"],
  ["JavaScript", "const a = 1;\nconsole.log(a);\n", "app.js", "txt", "match"],
  ["Python with # comments", "import os\n# list files\nprint(os.name)\n", "main.py", "markdown", "match"],
  ["YAML", "name: x\nversion: 1\n", "config.yaml", "txt", "match"],
  ["shebang script", "#!/usr/bin/env python3\nprint(1)\n", "deploy.py", "script", "match"],
  ["shebang script, no extension", "#!/bin/sh\necho hi\n", "run", "script", "ambiguous"],
  ["text renamed to .png", "<?php system($_GET['c']); ?>\n", "avatar.png", "txt", "mismatch"],
  ["text with an unfamiliar extension", "hello\n", "notes.zzz", "txt", "ambiguous"],

  // Deceptive file names.
  ["right-to-left override name", peFile(0x0102), "invoice\u202Efdp.exe", "exe", "mismatch"],
  ["double extension, real EXE", peFile(0x0102), "invoice.pdf.exe", "exe", "mismatch"],
  ["double extension, padded with spaces", peFile(0x0102), "invoice.pdf      .exe", "exe", "mismatch"],
  ["double extension on a risky text type", "WScript.Echo(1)\n", "photo.jpg.js", "txt", "mismatch"],
  ["ordinary double extension", pad([0x1f, 0x8b, 0x08, 0x00]), "backup.tar.gz", "gzip", "match"],
  ["dotted name that isn't a decoy", "x\n", "jquery.min.js", "txt", "match"],
];

for (const [desc, content, name, id, status] of cases) {
  test(desc, async () => {
    assert.deepEqual(await scan(content, name), { id, status });
  });
}

test("revealName shows hidden bidi characters", () => {
  assert.equal(revealName("invoice\u202Efdp.exe"), "invoice[U+202E]fdp.exe");
  assert.equal(revealName("plain.txt"), "plain.txt");
});

test("getExtension", () => {
  assert.equal(getExtension("photo.PNG"), "png");
  assert.equal(getExtension(".bashrc"), "");
  assert.equal(getExtension("archive.tar.gz"), "gz");
  assert.equal(getExtension("noext"), "");
  assert.equal(getExtension("trailing."), "");
  assert.equal(getExtension("perl5.34"), "");
});
