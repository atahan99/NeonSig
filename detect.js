// NeonSig detection engine: magic-byte signatures, container refiners, text heuristics.
// Loaded as a classic <script> by index.html (works over file://) and require()d by the tests.
"use strict";

const MAX_HEADER_BYTES = 16 * 1024;

function hexToBytes(hexPattern) {
  const clean = hexPattern.replace(/\s+/g, "");
  const out = [];
  for (let i = 0; i < clean.length; i += 2) {
    out.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return out;
}

function bytesMatchAt(bytes, pattern, offset = 0) {
  if (!bytes || offset < 0) return false;
  if (offset + pattern.length > bytes.length) return false;
  for (let i = 0; i < pattern.length; i++) {
    if (bytes[offset + i] !== pattern[i]) return false;
  }
  return true;
}

function asciiAt(bytes, offset, length) {
  if (!bytes || offset < 0 || offset >= bytes.length) return "";
  let s = "";
  const end = Math.min(offset + length, bytes.length);
  for (let i = offset; i < end; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

function indexOfAscii(bytes, text) {
  if (!bytes || !text) return -1;
  const first = text.charCodeAt(0);
  const limit = bytes.length - text.length;
  for (let i = 0; i <= limit; i++) {
    if (bytes[i] !== first) continue;
    let ok = true;
    for (let j = 1; j < text.length; j++) {
      if (bytes[i + j] !== text.charCodeAt(j)) { ok = false; break; }
    }
    if (ok) return i;
  }
  return -1;
}

function getExtension(filename) {
  const name = String(filename || "");
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return "";
  return name.slice(dot + 1).trim().replace(/^\./, "").toLowerCase();
}

function compareExtension(detectedExtensions, actualExt) {
  if (!detectedExtensions || detectedExtensions.length === 0) return "unknown";
  if (!actualExt) return "mismatch";
  return detectedExtensions.includes(actualExt) ? "match" : "mismatch";
}
// Signature registry: { id, label, mime, extensions, patterns, offset, confidence, notes }
const SIGNATURES = [
  /* ---------------- Images ---------------- */
  { id: "png", label: "PNG image", mime: "image/png", extensions: ["png"],
    patterns: ["89 50 4E 47 0D 0A 1A 0A"], offset: 0, confidence: "high",
    notes: "PNG 8-byte signature." },
  { id: "jpeg", label: "JPEG image", mime: "image/jpeg", extensions: ["jpg", "jpeg", "jpe", "jfif"],
    patterns: ["FF D8 FF"], offset: 0, confidence: "high",
    notes: "JPEG SOI marker." },
  { id: "gif", label: "GIF image", mime: "image/gif", extensions: ["gif"],
    patterns: ["47 49 46 38 37 61", "47 49 46 38 39 61"], offset: 0, confidence: "high",
    notes: "GIF87a / GIF89a header." },
  { id: "bmp", label: "BMP image", mime: "image/bmp", extensions: ["bmp", "dib"],
    patterns: ["42 4D"], offset: 0, confidence: "medium",
    notes: "Windows bitmap 'BM'." },
  { id: "tiff", label: "TIFF image", mime: "image/tiff", extensions: ["tif", "tiff"],
    patterns: ["49 49 2A 00", "4D 4D 00 2A"], offset: 0, confidence: "high",
    notes: "TIFF little- or big-endian." },
  { id: "ico", label: "Windows icon", mime: "image/x-icon", extensions: ["ico"],
    patterns: ["00 00 01 00"], offset: 0, confidence: "medium",
    notes: "ICO icon resource." },
  { id: "cur", label: "Windows cursor", mime: "image/x-icon", extensions: ["cur"],
    patterns: ["00 00 02 00"], offset: 0, confidence: "medium",
    notes: "CUR cursor resource." },

  /* ---------------- Documents ---------------- */
  { id: "pdf", label: "PDF document", mime: "application/pdf", extensions: ["pdf"],
    patterns: ["25 50 44 46 2D"], offset: 0, confidence: "high",
    notes: "'%PDF-' header." },
  { id: "rtf", label: "Rich Text Format", mime: "application/rtf", extensions: ["rtf"],
    patterns: ["7B 5C 72 74 66"], offset: 0, confidence: "high",
    notes: "'{\\rtf' header." },
  { id: "ole", label: "Legacy MS Office (OLE/CFB)", mime: "application/x-ole-storage",
    extensions: ["doc", "xls", "ppt", "msg", "msi"],
    patterns: ["D0 CF 11 E0 A1 B1 1A E1"], offset: 0, confidence: "medium",
    notes: "Compound File Binary; DOC/XLS/PPT and others share this container." },

  /* ---------------- Archives / compressed ---------------- */
  { id: "zip", label: "ZIP archive", mime: "application/zip", extensions: ["zip"],
    patterns: ["50 4B 03 04", "50 4B 05 06", "50 4B 07 08"], offset: 0, confidence: "high",
    notes: "ZIP local/central/spanned header. Refined by inspecting entries." },
  { id: "rar4", label: "RAR archive (v4)", mime: "application/vnd.rar", extensions: ["rar"],
    patterns: ["52 61 72 21 1A 07 00"], offset: 0, confidence: "high",
    notes: "RAR 1.5-4.x signature." },
  { id: "rar5", label: "RAR archive (v5)", mime: "application/vnd.rar", extensions: ["rar"],
    patterns: ["52 61 72 21 1A 07 01 00"], offset: 0, confidence: "high",
    notes: "RAR 5.x signature." },
  { id: "sevenzip", label: "7-Zip archive", mime: "application/x-7z-compressed", extensions: ["7z"],
    patterns: ["37 7A BC AF 27 1C"], offset: 0, confidence: "high", notes: "7z signature." },
  { id: "gzip", label: "GZIP compressed", mime: "application/gzip", extensions: ["gz", "tgz"],
    patterns: ["1F 8B"], offset: 0, confidence: "high", notes: "GZIP member header." },
  { id: "bzip2", label: "BZIP2 compressed", mime: "application/x-bzip2", extensions: ["bz2"],
    patterns: ["42 5A 68"], offset: 0, confidence: "high", notes: "'BZh' header." },
  { id: "xz", label: "XZ compressed", mime: "application/x-xz", extensions: ["xz"],
    patterns: ["FD 37 7A 58 5A 00"], offset: 0, confidence: "high", notes: "XZ stream header." },
  { id: "tar", label: "TAR archive", mime: "application/x-tar", extensions: ["tar"],
    patterns: ["75 73 74 61 72"], offset: 257, confidence: "medium",
    notes: "'ustar' magic at offset 257." },

  /* ---------------- Audio ---------------- */
  { id: "mp3id3", label: "MP3 audio (ID3)", mime: "audio/mpeg", extensions: ["mp3"],
    patterns: ["49 44 33"], offset: 0, confidence: "high", notes: "ID3v2 tag." },
  { id: "mp3frame", label: "MP3 audio (frame sync)", mime: "audio/mpeg", extensions: ["mp3"],
    patterns: ["FF FB", "FF F3", "FF F2", "FF FA"], offset: 0, confidence: "medium",
    notes: "MPEG audio frame sync (no ID3 tag)." },
  { id: "flac", label: "FLAC audio", mime: "audio/flac", extensions: ["flac"],
    patterns: ["66 4C 61 43"], offset: 0, confidence: "high", notes: "'fLaC' header." },
  { id: "ogg", label: "OGG container", mime: "audio/ogg", extensions: ["ogg", "oga", "ogv", "opus"],
    patterns: ["4F 67 67 53"], offset: 0, confidence: "high", notes: "'OggS' page header." },
  { id: "midi", label: "MIDI audio", mime: "audio/midi", extensions: ["mid", "midi"],
    patterns: ["4D 54 68 64"], offset: 0, confidence: "high", notes: "'MThd' header." },

  /* ---------------- Video (non-container specifics) ---------------- */
  { id: "mpeg", label: "MPEG program/video stream", mime: "video/mpeg", extensions: ["mpg", "mpeg"],
    patterns: ["00 00 01 BA", "00 00 01 B3"], offset: 0, confidence: "medium",
    notes: "MPEG pack / sequence header start code." },

  /* ---------------- Container roots (refined later) ---------------- */
  { id: "riff", label: "RIFF container", mime: "application/octet-stream", extensions: [],
    patterns: ["52 49 46 46"], offset: 0, confidence: "medium",
    notes: "RIFF root; refined to WAV/AVI/WebP by the form-type." },
  { id: "isobmff", label: "ISO Base Media (ftyp)", mime: "application/octet-stream", extensions: [],
    patterns: ["66 74 79 70"], offset: 4, confidence: "medium",
    notes: "ISO BMFF 'ftyp' box; refined to MP4/MOV/HEIC/AVIF/M4A by brand." },
  { id: "ebml", label: "Matroska/WebM (EBML)", mime: "video/x-matroska", extensions: ["mkv", "webm"],
    patterns: ["1A 45 DF A3"], offset: 0, confidence: "medium",
    notes: "EBML header; refined to WebM vs MKV by DocType." },

  /* ---------------- Executables / binaries ---------------- */
  { id: "pe", label: "Windows PE (MZ)", mime: "application/vnd.microsoft.portable-executable",
    extensions: ["exe", "dll", "sys", "scr", "com", "ocx"],
    patterns: ["4D 5A"], offset: 0, confidence: "medium",
    notes: "'MZ' DOS header; PE header parsed to split EXE/DLL." },
  { id: "elf", label: "ELF executable", mime: "application/x-elf",
    extensions: ["elf", "so", "o", "out", "bin", "ko"],
    patterns: ["7F 45 4C 46"], offset: 0, confidence: "high", notes: "'\\x7fELF' header." },
  { id: "macho", label: "Mach-O binary", mime: "application/x-mach-binary",
    extensions: ["dylib", "o", "bundle"],
    patterns: ["FE ED FA CE", "FE ED FA CF", "CE FA ED FE", "CF FA ED FE"], offset: 0,
    confidence: "high", notes: "Mach-O 32/64-bit, big/little endian." },
  { id: "machofat", label: "Mach-O universal binary", mime: "application/x-mach-binary",
    extensions: ["dylib", "o"], patterns: ["CA FE BA BE"], offset: 0, confidence: "low",
    notes: "FAT/universal magic (shares bytes with Java class; disambiguated by size field)." },
  { id: "javaclass", label: "Java class", mime: "application/java-vm", extensions: ["class"],
    patterns: ["CA FE BA BE"], offset: 0, confidence: "low",
    notes: "Shares magic with Mach-O FAT; disambiguated via major/minor version." },
  { id: "wasm", label: "WebAssembly module", mime: "application/wasm", extensions: ["wasm"],
    patterns: ["00 61 73 6D"], offset: 0, confidence: "high", notes: "'\\0asm' header." },
  { id: "sqlite", label: "SQLite database", mime: "application/vnd.sqlite3", extensions: ["sqlite", "sqlite3", "db"],
    patterns: ["53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00"], offset: 0, confidence: "high",
    notes: "'SQLite format 3\\0' header." },

  /* ---------------- Fonts ---------------- */
  { id: "woff", label: "WOFF font", mime: "font/woff", extensions: ["woff"],
    patterns: ["77 4F 46 46"], offset: 0, confidence: "high", notes: "'wOFF' header." },
  { id: "woff2", label: "WOFF2 font", mime: "font/woff2", extensions: ["woff2"],
    patterns: ["77 4F 46 32"], offset: 0, confidence: "high", notes: "'wOF2' header." },
  { id: "ttf", label: "TrueType font", mime: "font/ttf", extensions: ["ttf"],
    patterns: ["00 01 00 00"], offset: 0, confidence: "low",
    notes: "TrueType outline version; shares bytes with some other formats." },
  { id: "otf", label: "OpenType font", mime: "font/otf", extensions: ["otf"],
    patterns: ["4F 54 54 4F"], offset: 0, confidence: "high", notes: "'OTTO' header." }
];

// Extension lists for refined-only type ids (base types use SIGNATURES[].extensions).
const REFINED_EXTENSIONS = {
  webp: ["webp"], svg: ["svg"], avif: ["avif"], heic: ["heic", "heif"],
  docx: ["docx"], xlsx: ["xlsx"], pptx: ["pptx"],
  odt: ["odt"], ods: ["ods"], odp: ["odp"], epub: ["epub"],
  jar: ["jar"], apk: ["apk"],
  wav: ["wav"], m4a: ["m4a", "m4b", "aac"],
  mp4: ["mp4", "m4v", "mov", "3gp", "3g2"], avi: ["avi"],
  webm: ["webm"], mkv: ["mkv"],
  exe: ["exe", "scr", "com"], dll: ["dll", "ocx"], sys: ["sys"],
  txt: ["txt", "text", "log"], csv: ["csv", "tsv"], json: ["json"],
  xml: ["xml"], html: ["html", "htm"], markdown: ["md", "markdown"]
};

for (const sig of SIGNATURES) {
  sig._patterns = sig.patterns.map((pat) => {
    const bytes = hexToBytes(pat);
    return { bytes, label: pat.replace(/\s+/g, " ").trim().toUpperCase(), len: bytes.length };
  });
}
const SIG_BY_ID = Object.fromEntries(SIGNATURES.map((s) => [s.id, s]));

const BROAD_IDS = new Set([
  "zip", "riff", "isobmff", "ebml", "ole", "pe", "machofat", "ttf",
  "txt", "csv", "json", "xml", "html", "markdown", "mp3frame", "ogg", "mpeg"
]);

async function readSlice(file, start, end) {
  const clampedStart = Math.max(0, Math.min(start, file.size));
  const clampedEnd = Math.max(clampedStart, Math.min(end, file.size));
  const buf = await file.slice(clampedStart, clampedEnd).arrayBuffer();
  return new Uint8Array(buf);
}

function readHeader(file) {
  return readSlice(file, 0, MAX_HEADER_BYTES);
}

function readUint16LE(b, o) { return b[o] | (b[o + 1] << 8); }
function readUint32LE(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
function readUint32BE(b, o) { return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0; }
function readUint16BE(b, o) { return (b[o] << 8) | b[o + 1]; }

function confidenceRank(c) { return c === "high" ? 3 : c === "medium" ? 2 : 1; }

function acceptedExtensions(id) {
  if (!id) return [];
  if (REFINED_EXTENSIONS[id]) return REFINED_EXTENSIONS[id];
  const sig = SIG_BY_ID[id];
  return sig ? sig.extensions : [];
}

// Magic numbers shorter than this ("BM", "MZ", "ID3", "BZh") are ordinary letters too,
// so they only count when the header is not plausibly text.
const MIN_MAGIC_FOR_TEXT = 4;

function matchSignatures(bytes) {
  const matches = [];
  const isText = looksLikeText(bytes);
  for (const sig of SIGNATURES) {
    let matchedHex = null;
    let patternLength = 0;
    for (const pat of sig._patterns) {
      if (isText && pat.len < MIN_MAGIC_FOR_TEXT) continue;
      if (bytesMatchAt(bytes, pat.bytes, sig.offset)) {
        matchedHex = pat.label;
        patternLength = pat.len;
        break;
      }
    }
    if (matchedHex !== null) {
      matches.push({
        id: sig.id, label: sig.label, mime: sig.mime,
        confidence: sig.confidence, notes: sig.notes,
        signature: matchedHex, offset: sig.offset, patternLength
      });
    }
  }
  matches.sort((a, b) => {
    const c = confidenceRank(b.confidence) - confidenceRank(a.confidence);
    if (c !== 0) return c;
    if (b.patternLength !== a.patternLength) return b.patternLength - a.patternLength;
    return a.offset - b.offset;
  });
  return matches;
}

// Container refiners

// Scan for ZIP local file headers ("PK\x03\x04") within the window and pull
// out entry filenames. Validation keeps false positives (from compressed
// payloads) low. Enough to identify OOXML / ODF / EPUB / APK / JAR.
function scanZipLocalEntries(bytes) {
  const entries = [];
  const sig = [0x50, 0x4b, 0x03, 0x04];
  for (let i = 0; i + 30 <= bytes.length; i++) {
    if (!bytesMatchAt(bytes, sig, i)) continue;
    const fnLen = readUint16LE(bytes, i + 26);
    const extraLen = readUint16LE(bytes, i + 28);
    if (fnLen === 0 || fnLen > 512) continue;
    if (i + 30 + fnLen > bytes.length) continue;
    const name = asciiAt(bytes, i + 30, fnLen);
    if (!/^[\x20-\x7e]+$/.test(name)) continue;
    entries.push({ name, dataOffset: i + 30 + fnLen + extraLen });
    if (entries.length > 200) break;
  }
  return entries;
}

function refineZip(bytes) {
  const entries = scanZipLocalEntries(bytes);
  const names = entries.map((e) => e.name);
  const has = (n) => names.includes(n);
  const hasPrefix = (p) => names.some((n) => n.startsWith(p));

  // ODF / EPUB: first entry is a stored "mimetype" whose contents are the MIME.
  const mimeEntry = entries.find((e) => e.name === "mimetype");
  if (mimeEntry) {
    const content = asciiAt(bytes, mimeEntry.dataOffset, 80);
    if (content.startsWith("application/epub+zip"))
      return refined("epub", "EPUB e-book", "application/epub+zip", "mimetype = application/epub+zip");
    if (content.startsWith("application/vnd.oasis.opendocument.text"))
      return refined("odt", "OpenDocument Text", "application/vnd.oasis.opendocument.text", "mimetype = ODF text");
    if (content.startsWith("application/vnd.oasis.opendocument.spreadsheet"))
      return refined("ods", "OpenDocument Spreadsheet", "application/vnd.oasis.opendocument.spreadsheet", "mimetype = ODF spreadsheet");
    if (content.startsWith("application/vnd.oasis.opendocument.presentation"))
      return refined("odp", "OpenDocument Presentation", "application/vnd.oasis.opendocument.presentation", "mimetype = ODF presentation");
  }

  // Android package (check before JAR: APKs also carry META-INF/MANIFEST.MF).
  if (has("AndroidManifest.xml"))
    return refined("apk", "Android package (APK)", "application/vnd.android.package-archive", "contains AndroidManifest.xml");

  // OOXML by well-known folders / part names.
  if (hasPrefix("word/"))
    return refined("docx", "Word document (OOXML)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "contains word/ parts");
  if (hasPrefix("xl/"))
    return refined("xlsx", "Excel workbook (OOXML)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "contains xl/ parts");
  if (hasPrefix("ppt/"))
    return refined("pptx", "PowerPoint presentation (OOXML)", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "contains ppt/ parts");

  // Java archive.
  if (has("META-INF/MANIFEST.MF"))
    return refined("jar", "Java archive (JAR)", "application/java-archive", "contains META-INF/MANIFEST.MF");

  const noteList = names.length ? ("entries: " + names.slice(0, 4).join(", ")) : "no readable entries in header window";
  return refined("zip", "ZIP archive", "application/zip", noteList, "medium");

  function refined(id, label, mime, notes, confidence) {
    return { id, label, mime, confidence: confidence || "high", notes,
             signature: "50 4B 03 04", offset: 0 };
  }
}

// ISO Base Media File Format: inspect the ftyp major brand + compatible brands.
function refineIsoBmff(bytes) {
  const boxSize = Math.min(readUint32BE(bytes, 0) || 32, bytes.length, 256);
  const brands = [asciiAt(bytes, 8, 4)];
  for (let o = 16; o + 4 <= boxSize; o += 4) brands.push(asciiAt(bytes, o, 4));
  const set = brands.map((b) => b.trim().toLowerCase());
  const any = (list) => list.some((b) => set.includes(b));
  const brand = set[0] || "";
  const make = (id, label, mime) => ({ id, label, mime, confidence: "high",
    notes: "ftyp brand: " + set.filter(Boolean).slice(0, 4).join(", "), signature: "66 74 79 70", offset: 4 });

  if (any(["avif", "avis"])) return make("avif", "AVIF image", "image/avif");
  if (any(["heic", "heix", "hevc", "hevx", "heif", "mif1", "msf1"])) return make("heic", "HEIC/HEIF image", "image/heic");
  if (any(["m4a", "m4b", "m4p"])) return make("m4a", "M4A/AAC audio", "audio/mp4");
  if (any(["qt"])) return make("mp4", "QuickTime movie", "video/quicktime");
  if (any(["mp41", "mp42", "isom", "iso2", "iso4", "iso5", "iso6", "avc1", "dash", "m4v", "3gp4", "3gp5", "3g2a", "3gp6", "mmp4"]))
    return make("mp4", "MP4/QuickTime video (ISO BMFF)", "video/mp4");
  // Unknown brand: still ISO BMFF, keep broad.
  return { id: "mp4", label: "ISO BMFF media (brand '" + brand + "')", mime: "video/mp4",
    confidence: "medium", notes: "ftyp brand: " + brand, signature: "66 74 79 70", offset: 4 };
}

// RIFF: bytes 8-11 hold the form type.
function refineRiff(bytes) {
  const form = asciiAt(bytes, 8, 4).trim().toUpperCase();
  const base = { notes: "RIFF form: " + (form || "?"), signature: "52 49 46 46", offset: 0, confidence: "high" };
  if (form === "WAVE") return { ...base, id: "wav", label: "WAV audio", mime: "audio/wav" };
  if (form === "AVI") return { ...base, id: "avi", label: "AVI video", mime: "video/x-msvideo" };
  if (form === "WEBP") return { ...base, id: "webp", label: "WebP image", mime: "image/webp" };
  return { id: "riff", label: "RIFF container (form '" + form + "')", mime: "application/octet-stream",
    confidence: "low", notes: "unknown RIFF form: " + form, signature: "52 49 46 46", offset: 0 };
}

function refineEbml(bytes) {
  const window = bytes.subarray(0, Math.min(bytes.length, 64));
  if (indexOfAscii(window, "webm") !== -1)
    return { id: "webm", label: "WebM video", mime: "video/webm", confidence: "high",
      notes: "EBML DocType 'webm'", signature: "1A 45 DF A3", offset: 0 };
  return { id: "mkv", label: "Matroska video", mime: "video/x-matroska", confidence: "high",
    notes: "EBML header (matroska)", signature: "1A 45 DF A3", offset: 0 };
}

function refinePe(bytes) {
  const base = { signature: "4D 5A", offset: 0 };
  const peOff = readUint32LE(bytes, 0x3c);
  if (peOff > 0 && peOff + 24 <= bytes.length && asciiAt(bytes, peOff, 4) === "PE\u0000\u0000") {
    const characteristics = readUint16LE(bytes, peOff + 22);
    const isDll = (characteristics & 0x2000) !== 0;
    if (isDll)
      return { ...base, id: "dll", label: "Windows DLL (PE)", mime: "application/vnd.microsoft.portable-executable",
        confidence: "high", notes: "PE header, IMAGE_FILE_DLL set" };
    return { ...base, id: "exe", label: "Windows executable (PE)", mime: "application/vnd.microsoft.portable-executable",
      confidence: "high", notes: "PE header, IMAGE_FILE_DLL not set" };
  }
  return { ...base, id: "pe", label: "DOS/Windows executable (MZ)", mime: "application/vnd.microsoft.portable-executable",
    confidence: "medium", notes: "MZ header; PE header not parsed" };
}

function disambiguateCafebabe(bytes) {
  const base = { signature: "CA FE BA BE", offset: 0 };
  const major = readUint16BE(bytes, 6);
  const nfat = readUint32BE(bytes, 4);
  if (major >= 45 && major <= 100)
    return { ...base, id: "javaclass", label: "Java class", mime: "application/java-vm",
      confidence: "high", notes: "class major version " + major };
  if (nfat >= 1 && nfat <= 40)
    return { ...base, id: "machofat", label: "Mach-O universal binary", mime: "application/x-mach-binary",
      confidence: "medium", notes: nfat + " architectures" };
  return { ...base, id: "javaclass", label: "Java class / Mach-O FAT (ambiguous)", mime: "application/octet-stream",
    confidence: "low", notes: "CAFEBABE magic could not be disambiguated" };
}

function looksLikeText(bytes) {
  if (bytes.length === 0) return false;
  // Byte order marks are a strong "this is text" signal.
  if (bytesMatchAt(bytes, [0xef, 0xbb, 0xbf], 0)) return true;      // UTF-8 BOM
  if (bytesMatchAt(bytes, [0xff, 0xfe], 0)) return true;            // UTF-16 LE BOM
  if (bytesMatchAt(bytes, [0xfe, 0xff], 0)) return true;            // UTF-16 BE BOM
  const sample = Math.min(bytes.length, 4096);
  let suspicious = 0;
  for (let i = 0; i < sample; i++) {
    const b = bytes[i];
    if (b === 0) return false; // NUL byte => treat as binary
    // Control chars other than tab(9), LF(10), CR(13), FF(12) are suspicious.
    if (b < 0x09 || (b > 0x0d && b < 0x20)) suspicious++;
  }
  return suspicious / sample < 0.03;
}

function decodeTextSample(bytes) {
  let start = 0;
  if (bytesMatchAt(bytes, [0xef, 0xbb, 0xbf], 0)) start = 3;
  const end = Math.min(bytes.length, 8192);
  try {
    if (typeof TextDecoder === "function") {
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(start, end));
    }
  } catch (e) { /* fall through */ }
  return asciiAt(bytes, start, end - start);
}

function analyzeText(bytes) {
  if (!looksLikeText(bytes)) return null;
  const text = decodeTextSample(bytes);
  const trimmed = text.replace(/^\uFEFF/, "").trimStart();
  const lower = trimmed.toLowerCase();
  const base = { confidence: "low", signature: "(text heuristic)", offset: 0 };

  // SVG only when <svg> is the root element, not when HTML/Markdown merely contains one.
  const root = trimmed.replace(/^(?:<\?xml[\s\S]*?\?>|<!--[\s\S]*?-->|<!doctype svg[^>]*>|\s+)*/i, "");
  if (/^<svg[\s>]/i.test(root))
    return { ...base, id: "svg", label: "SVG image (XML)", mime: "image/svg+xml", confidence: "medium",
      notes: "<svg> root element" };

  if (lower.startsWith("<!doctype html") || lower.startsWith("<html") || /<html[\s>]/i.test(lower.slice(0, 200)))
    return { ...base, id: "html", label: "HTML document", mime: "text/html", notes: "HTML markup" };

  if (trimmed.startsWith("<?xml") || /^<[a-z!]/i.test(trimmed))
    return { ...base, id: "xml", label: "XML document", mime: "application/xml", notes: "XML markup" };

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    let ok = false;
    try { JSON.parse(text); ok = true; } catch (e) { ok = /["}\]]/.test(trimmed) && /[:,]/.test(trimmed); }
    if (ok)
      return { ...base, id: "json", label: "JSON data", mime: "application/json",
        notes: "JSON structure", confidence: bytes.length <= 8192 ? "medium" : "low" };
  }

  const lines = text.split(/\r?\n/).filter((l) => l.length > 0).slice(0, 10);
  if (lines.length >= 2) {
    const commaCounts = lines.map((l) => (l.match(/,/g) || []).length);
    if (commaCounts[0] >= 1 && commaCounts.every((c) => c === commaCounts[0]))
      return { ...base, id: "csv", label: "CSV data", mime: "text/csv", notes: "delimiter-consistent rows" };
  }

  if (/^#{1,6}\s/m.test(text) || /^\s*[-*]\s/m.test(text) || /```/.test(text) || /\[[^\]]+\]\([^)]+\)/.test(text))
    return { ...base, id: "markdown", label: "Markdown document", mime: "text/markdown", notes: "markdown markers" };

  return { ...base, id: "txt", label: "Plain text", mime: "text/plain", notes: "printable text, no strong markers" };
}

function detectType(file, header) {
  if (file.size === 0) {
    return { id: null, label: "Empty file", mime: null, confidence: "n/a",
      signature: "(none)", offset: null, notes: "The file contains zero bytes.",
      accepted: [], broad: false, empty: true };
  }

  let detection = null;
  const matches = matchSignatures(header);

  if (matches.length > 0) {
    const best = matches[0];
    detection = {
      id: best.id, label: best.label, mime: best.mime,
      confidence: best.confidence, signature: best.signature, offset: best.offset,
      notes: best.notes
    };

    let refined = null;
    if (best.id === "zip") refined = refineZip(header);
    else if (best.id === "isobmff") refined = refineIsoBmff(header);
    else if (best.id === "riff") refined = refineRiff(header);
    else if (best.id === "ebml") refined = refineEbml(header);
    else if (best.id === "pe") refined = refinePe(header);
    else if (best.id === "javaclass" || best.id === "machofat") refined = disambiguateCafebabe(header);

    if (refined) detection = { ...detection, ...refined };
  } else {
    const text = analyzeText(header);
    if (text) detection = text;
  }

  if (!detection) {
    return { id: null, label: "Unknown", mime: null, confidence: "none",
      signature: "(no match)", offset: null, notes: "No known signature or text heuristic matched.",
      accepted: [], broad: false, unknown: true };
  }

  detection.accepted = acceptedExtensions(detection.id);
  detection.broad = BROAD_IDS.has(detection.id);
  return detection;
}

function evaluate(detection, actualExt) {
  if (detection.empty)
    return { status: "unknown", warning: "The file is empty (0 bytes); no type can be determined." };
  if (detection.unknown || !detection.id)
    return { status: "unknown",
      warning: "No reliable signature was found. The file may be an unsupported format, encrypted, corrupted, or truncated." };

  const cmp = compareExtension(detection.accepted, actualExt);
  const typeName = detection.label;

  if (detection.id === "zip")
    return { status: "ambiguous",
      warning: "This appears to be a ZIP container. A more specific subtype (Office, ODF, EPUB, JAR, APK...) could not be determined from the header." +
        (actualExt && actualExt !== "zip" ? " Extension is \"." + actualExt + "\"." : "") };

  if (cmp === "match")
    return { status: "match", warning: "" };

  if (detection.broad) {
    if (!actualExt)
      return { status: "ambiguous",
        warning: "Detected " + typeName + ", but the file has no extension. Subtype could not be confirmed." };
    return { status: "ambiguous",
      warning: "Detected " + typeName + " (a broad/container type). Extension \"." + actualExt +
        "\" may or may not be correct; subtype could not be confirmed." };
  }

  if (!actualExt)
    return { status: "mismatch",
      warning: "This file has no extension but its bytes look like " + typeName + "." };
  return { status: "mismatch",
    warning: "This file is named \"." + actualExt + "\" but its bytes look like " + typeName + "." };
}

if (typeof module === "object" && module.exports) {
  module.exports = {
    hexToBytes, bytesMatchAt, getExtension, compareExtension, matchSignatures,
    looksLikeText, analyzeText, readHeader, detectType, evaluate, SIGNATURES
  };
}
