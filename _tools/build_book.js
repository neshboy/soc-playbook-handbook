const fs = require("fs");
const path = require("path");
const { marked } = require("marked");

const ROOT = "C:/Users/User/SOC-Playbook-Handbook";
const INDEX_PATH = path.join(ROOT, "BOOK-INDEX.md");
const OUT_HTML = path.join(ROOT, "_build", "book.html");

marked.setOptions({ mangle: false, headerIds: true, gfm: true });

function readFile(p) {
  return fs.readFileSync(p, "utf-8");
}

// Parse BOOK-INDEX.md into an ordered list of entries: headings + chapter file links.
function parseIndex() {
  const lines = readFile(INDEX_PATH).split("\n");
  const entries = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("## ")) {
      entries.push({ type: "part", text: line.slice(3).trim() });
      continue;
    }
    if (line.startsWith("### ")) {
      entries.push({ type: "section", text: line.slice(4).trim() });
      continue;
    }
    const boldHeading = line.match(/^\*\*(\d+.*)\*\*$/);
    if (boldHeading) {
      entries.push({ type: "section", text: boldHeading[1].trim() });
      continue;
    }
    const linkMatch = line.match(/\[([^\]]+)\]\(([^)]+)\)/);
    if (linkMatch) {
      const [, text, target] = linkMatch;
      if (target.endsWith(".md")) {
        entries.push({ type: "chapter", text, target });
        continue;
      }
      // Non-.md link (e.g. an internal #anchor cross-reference) - fall through
      // and still render the surrounding sentence as prose below.
    }
    if (line.length > 0 && line !== "---") {
      entries.push({ type: "prose", text: line });
    }
  }
  return entries;
}

function fixImagePaths(html, sourceFileDir) {
  // Chrome needs an explicit file:/// URL. Two cases from the Markdown source:
  // - already-absolute "C:/Users/..." paths (legacy convention, still supported)
  // - relative paths (the current convention) which must resolve against the
  //   ORIGINAL chapter file's own directory, not the assembled book.html's directory.
  return html.replace(/src="([^"]+)"/g, (m, p1) => {
    if (/^[A-Za-z]:\//.test(p1)) return `src="file:///${p1}"`;
    if (/^https?:\/\//.test(p1)) return m;
    const abs = path.resolve(sourceFileDir, p1).replace(/\\/g, "/");
    return `src="file:///${abs}"`;
  });
}

const DEPTH_MARKER_COLORS = {
  STAKEHOLDER: "marker-stakeholder",
  ANALYST: "marker-analyst",
  ENGINEERING: "marker-engineering",
  MANAGEMENT: "marker-management",
}

function colorizeDepthMarkers(html) {
  return html.replace(/<strong>\[(STAKEHOLDER|ANALYST|ENGINEERING|MANAGEMENT)\]<\/strong>/g, (m, role) => {
    return `<span class="depth-marker ${DEPTH_MARKER_COLORS[role]}">[${role}]</span>`
  })
}

function slugAnchor(s, seen) {
  let base = s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
  let anchor = base;
  let n = 2;
  while (seen.has(anchor)) {
    anchor = base + "-" + n;
    n++;
  }
  seen.add(anchor);
  return anchor;
}

function buildTOC(entries, anchors) {
  let toc = '<nav class="toc"><h1>Table of Contents</h1><ul class="toc-list">';
  let currentPartList = null;
  entries.forEach((e, i) => {
    const anchor = anchors[i];
    if (e.type === "part") {
      toc += `</ul><li class="toc-part"><a href="#${anchor}">${inlineMd(e.text)}</a></li><ul class="toc-list">`;
    } else if (e.type === "section") {
      toc += `<li class="toc-section"><a href="#${anchor}">${inlineMd(e.text)}</a></li>`;
    } else if (e.type === "chapter") {
      toc += `<li class="toc-chapter"><a href="#${anchor}">${inlineMd(e.text)}</a></li>`;
    }
    // "prose" entries are intro/closing narrative text, not TOC-worthy - skip them here.
  });
  toc += "</ul></nav>";
  return toc;
}

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function inlineMd(s) {
  return marked.parseInline(s);
}

function main() {
  const entries = parseIndex();
  const seenAnchors = new Set();
  const anchors = entries.map((e) => slugAnchor(e.text, seenAnchors));

  let missing = [];
  let body = "";
  entries.forEach((e, i) => {
    const anchor = anchors[i];
    if (e.type === "part") {
      body += `<section class="part-divider" id="${anchor}"><h1>${inlineMd(e.text)}</h1></section>\n`;
    } else if (e.type === "section") {
      body += `<h2 class="section-heading" id="${anchor}">${inlineMd(e.text)}</h2>\n`;
    } else if (e.type === "chapter") {
      const fullPath = path.join(ROOT, e.target.replace(/\//g, path.sep));
      if (!fs.existsSync(fullPath)) {
        missing.push(e.target);
        body += `<section class="chapter" id="${anchor}"><p><em>MISSING FILE: ${escapeHtml(e.target)}</em></p></section>\n`;
        return;
      }
      const md = readFile(fullPath);
      let html = marked.parse(md);
      html = fixImagePaths(html, path.dirname(fullPath));
      html = colorizeDepthMarkers(html);
      body += `<section class="chapter" id="${anchor}">${html}</section>\n`;
    } else if (e.type === "prose") {
      body += `<p class="index-prose">${inlineMd(e.text)}</p>\n`;
    }
  });

  const toc = buildTOC(entries, anchors);

  const css = `
  :root {
    --blue: #2a78d6; --orange: #eb6834; --aqua: #1baf7a; --yellow: #eda100;
    --magenta: #e87ba4; --green: #008300; --violet: #4a3aa7; --red: #e34948;
    --ink: #0b0b0b; --ink-secondary: #52514e; --ink-muted: #898781;
    --gridline: #e1e0d9; --baseline: #c3c2b7;
    --blue-tint: #cde2fb; --orange-tint: #f9d9c4; --aqua-tint: #bdeedb; --yellow-tint: #fce8bf; --violet-tint: #e3ddf7;
  }
  @page { size: A4; margin: 22mm 18mm 24mm 18mm; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", Calibri, Arial, sans-serif; color: var(--ink); line-height: 1.5; font-size: 10.5pt; }
  .cover { margin-top: 95mm; text-align: center; page-break-after: always; }
  .cover h1 { font-size: 30pt; margin-bottom: 10pt; letter-spacing: 0.5pt; color: var(--blue); }
  .cover .accent-rule { width: 120pt; height: 3pt; background: linear-gradient(90deg, var(--blue), var(--aqua), var(--violet)); margin: 0 auto 16pt auto; border-radius: 2pt; }
  .cover h2 { font-size: 13pt; font-weight: 400; color: var(--ink-secondary); margin-top: 0; max-width: 70%; margin-left: auto; margin-right: auto; }
  .cover .meta { margin-top: 40pt; font-size: 9pt; color: var(--ink-muted); }
  .index-prose { font-size: 10pt; color: var(--ink-secondary); margin: 0 6mm 8pt 6mm; }
  .toc { page-break-after: always; }
  .toc h1 { font-size: 20pt; border-bottom: 2pt solid var(--blue); padding-bottom: 6pt; color: var(--ink); }
  .toc-list { list-style: none; padding-left: 0; }
  .toc-part { font-weight: 700; font-size: 13pt; margin-top: 14pt; color: var(--blue); }
  .toc-section { font-weight: 600; font-size: 10.5pt; margin-top: 6pt; margin-left: 10pt; color: var(--ink); }
  .toc-chapter { font-size: 9.5pt; margin-left: 20pt; color: var(--ink-secondary); }
  .toc a { text-decoration: none; color: inherit; }
  .part-divider { page-break-before: always; page-break-after: always; margin-top: 100mm; text-align: center; }
  .part-divider h1 { font-size: 26pt; border-top: 3pt solid var(--blue); border-bottom: 3pt solid var(--blue); padding: 14pt 0; text-align: center; color: var(--ink); }
  h2.section-heading { page-break-before: always; font-size: 16pt; border-bottom: 2pt solid var(--orange); padding-bottom: 4pt; margin-top: 0; color: var(--ink); }
  section.chapter { page-break-before: always; }
  section.chapter h1 { font-size: 17pt; margin-top: 0; color: var(--ink); border-bottom: 1.5pt solid var(--blue-tint); padding-bottom: 6pt; }
  section.chapter h2 { font-size: 13pt; margin-top: 16pt; color: var(--blue); }
  section.chapter h3 { font-size: 11pt; margin-top: 12pt; color: var(--ink); }
  section.chapter img { max-width: 92%; max-height: 215mm; width: auto; height: auto; display: block; margin: 10pt auto; page-break-inside: avoid; }
  section.chapter table { border-collapse: collapse; width: 100%; font-size: 8.7pt; margin: 8pt 0; page-break-inside: avoid; }
  section.chapter th, section.chapter td { border: 0.5pt solid var(--baseline); padding: 3pt 5pt; text-align: left; vertical-align: top; }
  section.chapter th { background: var(--blue-tint); color: var(--ink); border-bottom: 1.5pt solid var(--blue); }
  section.chapter pre { background: #f4f4f4; border: 0.5pt solid var(--baseline); border-left: 3pt solid var(--violet); padding: 6pt; font-size: 8pt; overflow-wrap: break-word; white-space: pre-wrap; page-break-inside: avoid; }
  section.chapter code { font-family: Consolas, "Courier New", monospace; font-size: 8.5pt; background: var(--violet-tint); padding: 0 2pt; color: var(--ink); }
  section.chapter pre code { background: none; padding: 0; }
  section.chapter blockquote { border-left: 3pt solid var(--yellow); margin-left: 0; padding-left: 10pt; color: var(--ink-secondary); font-style: italic; background: var(--yellow-tint); padding: 6pt 10pt; border-radius: 0 3pt 3pt 0; }
  section.chapter strong { color: var(--ink); }
  section.chapter hr { border: none; border-top: 1pt solid var(--gridline); margin: 12pt 0; }
  .depth-marker { display: inline-block; font-weight: 700; font-size: 8pt; letter-spacing: 0.3pt; padding: 1.5pt 6pt; border-radius: 3pt; margin-right: 3pt; }
  .marker-stakeholder { background: var(--blue-tint); color: #164a8a; border: 0.5pt solid var(--blue); }
  .marker-analyst { background: var(--aqua-tint); color: #0d6b49; border: 0.5pt solid var(--aqua); }
  .marker-engineering { background: var(--violet-tint); color: #2e2470; border: 0.5pt solid var(--violet); }
  .marker-management { background: var(--orange-tint); color: #93401d; border: 0.5pt solid var(--orange); }
  `;

  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10);

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SIGNAL TO ACTION: The Complete SOC Playbook Handbook</title>
<style>${css}</style>
</head>
<body>
<section class="cover">
  <h1>SIGNAL TO ACTION</h1>
  <div class="accent-rule"></div>
  <h2>The Complete SOC Playbook Handbook<br>A Practitioner's Guide to Designing, Operating and Governing Modern SOC Playbooks</h2>
  <div class="meta">Build date: ${dateStr}</div>
</section>
${toc}
${body}
</body>
</html>`;

  fs.mkdirSync(path.dirname(OUT_HTML), { recursive: true });
  fs.writeFileSync(OUT_HTML, html, "utf-8");

  console.log("Entries:", entries.length, "| chapters:", entries.filter((e) => e.type === "chapter").length);
  console.log("Missing files:", missing.length);
  if (missing.length) console.log(missing.join("\n"));
  console.log("Wrote", OUT_HTML, "(", (html.length / 1024 / 1024).toFixed(2), "MB )");
}

main();
