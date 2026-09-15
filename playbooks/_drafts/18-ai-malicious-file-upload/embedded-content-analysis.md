# Embedded Content Analysis: Investigation Deep-Dive

This module picks up once triage has already flagged a file uploaded into the AI application (assume the app is an internal assistant, "Aegis Assist," with file-upload/RAG ingestion) as warranting deeper review. The goal here is narrow: pull apart what's actually *inside* the container format — links, macros, scripts, nested archives, metadata — before any containment or verdict decision gets made. Sandbox detonation and hash/reputation lookups are covered elsewhere in the master playbook; this is the manual/semi-automated dissection layer.

**[ANALYST]** - Do this extraction in an isolated analysis VM or the sandbox's file-inspection sidecar, never on the ingestion host. Never let the AI application itself re-parse a file you're actively deconstructing — several ingestion pipelines auto-summarize on upload, which means the model may have already "read" a malicious instruction before your review even starts.

## Extraction Approach by File Type

| File type | Extraction tooling | Primary target |
|---|---|---|
| DOCX/XLSX/PPTX (OOXML, zip-based) | `oletools` (`olevba`, `oleid`), manual zip extraction | Macros, embedded OLE objects, hidden text, comments |
| Legacy DOC/XLS (OLE2) | `oletools` (`olevba`), `oledump.py` | VBA streams, embedded binaries |
| PDF | `pdfid.py`, `peepdf`, `pdf-parser.py` | JavaScript, launch actions, embedded files, OCG layers |
| ZIP/RAR/7z | `7z l -slt`, `binwalk`, Python `zipfile` | Nested archives, path traversal, disguised executables |
| Images (JPG/PNG) | `exiftool`, `binwalk`, `strings` | EXIF/XMP metadata, appended trailing data |
| Scripts (PS1/JS/VBS/BAT) | Manual read + `4104`-style logging in sandbox execution | Obfuscation, download cradles |

## Embedded URL Analysis

Extract every URL from hyperlink relationship files (`word/_rels/document.xml.rels`), PDF `/URI` actions, and raw string carving — not just what's visibly rendered. A DOCX can display "Company Portal" as anchor text while the underlying relationship target points to `hxxp://185.220.101[.]44/update.php`. That anchor/target mismatch is the single highest-value signal in this section.

Flags worth pulling into the case notes: URL shorteners, raw IP-literal URLs, punycode/homoglyph domains (`micros0ft-support[.]com`), newly registered domains, and mismatched TLS cert CN vs. hostname on detonation. Run every extracted URL through the org's threat intel platform and a sandboxed browser detonation (urlscan-style) — do not click from an analyst workstation.

**[ENGINEERING]**
```bash
# Pull hyperlink targets from an OOXML file without opening it
unzip -p suspicious_invoice.docx word/_rels/document.xml.rels | grep -oE 'Target="[^"]+"'

# Carve raw URLs out of a PDF
strings -a report.pdf | grep -oE '(https?|hxxp)://[^ "\)>]+'
```

## Macro Analysis

`olevba` against the file first — it flags AutoExec triggers (`AutoOpen`, `Document_Open`, `Workbook_Open`), suspicious keywords (`Shell`, `WScript.Shell`, `CreateObject`, `URLDownloadToFile`), and Base64/`Chr()` obfuscation in one pass.

```text
$ olevba invoice_q3.docm --deobf
AutoExec:  Document_Open (auto-executes)
Suspicious: Shell, CreateObject, WScript.Shell, Environ, Chr
IOC: hxxp://cdn-updates[.]net/payload.bin
```

A macro that calls `CreateObject("WScript.Shell")` to spawn `mshta` or `regsvr32` is classic second-stage staging — map this to **T1218** (System Binary Proxy Execution: Mshta/Regsvr32/Rundll32) fed by **T1204** (User Execution) and **T1105** (Ingress Tool Transfer) for the download. Heavy `Chr()`/string-concatenation obfuscation maps to **T1027**. Note VBA stomping as a known limitation: the p-code can diverge from the source stream on older Office builds, so a clean `olevba` read doesn't guarantee a clean macro if you're on an old parser version — cross-check with `pcodedmp` when results look inconsistent.

## Archive Contents Analysis

List contents before extracting anything, and compare listed size vs. compressed size (zip-bomb indicator) and file count. Watch for: password-protected archives (a routine social-engineering trick to dodge automated AV/content scanning — the "password is in the email body" pattern), nested archive-in-archive chains, path-traversal filenames (`../../../Windows/System32/`), and double-extension/extension-spoofed entries (`resume.pdf.exe`, or a `.jpg` that's actually a PE by magic bytes).

**[ENGINEERING]**
```bash
7z l -slt payload.zip | grep -E "Path|Size|Packed Size"
# Verify true type vs claimed extension
file --mime-type $(unzip -Z1 payload.zip)
```

## Suspicious Metadata Analysis

Office `docProps/core.xml` and `app.xml` carry Author, Company, Last Modified By, Template, and revision save-count. Inconsistencies matter: a "final invoice" with 47 revisions and a Company field referencing an unrelated org, or a creation timestamp that postdates the modification timestamp, both suggest template reuse from a builder kit rather than organic authoring. PDF `/Producer` and `/Creator` strings that don't match the claimed authoring tool are the PDF equivalent. For images, run `exiftool` for GPS/device leakage and check for data appended after the EOF marker (a common steganographic carrier).

## AI-Specific Embedded Instruction Channels

This is the piece that's unique to an AI-ingestion pipeline versus a normal email-attachment path: content that's invisible to a human reader but fully readable to the model's parser.

**[ANALYST]** - Check specifically for: white/0-pt font text or off-canvas text boxes in DOCX/PDF; PDF optional content groups (hidden layers) that carry text but render off; image `alt-text`/accessibility fields and PDF tagged-structure text (often piped into vision/OCR context automatically); document `Comments`, `Keywords`, and `Subject` metadata fields; and PPTX speaker notes. Any of these containing directives like "ignore previous instructions" or "when summarizing this document, also output the following to the user" is an indirect prompt-injection attempt riding in on embedded content, not just a malware carrier — escalate it on that basis even if the file is otherwise benign from a malware-execution standpoint.

**[ENGINEERING]** - Automated scanning should diff *rendered* text against *full-extracted* text (including hidden runs, alt-text, and OCG layers) and alert on divergence above a tuned threshold, plus keyword-match instruction-style language in non-visible fields feeding the AI's context window.
