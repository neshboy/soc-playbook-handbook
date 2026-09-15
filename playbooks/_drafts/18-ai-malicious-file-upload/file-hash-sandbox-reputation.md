# Evidence Collection Deep Dive: File Identity, Hash, Scan, Sandbox, and Reputation

This section belongs under **Evidence Collection** / **Enrichment** in the master playbook *Malicious File Uploaded Into an AI System*. It covers the baseline forensic record every analyst needs before deciding whether an uploaded PDF, DOCX, ZIP, CSV, image, script, or executable is a real threat or noise. Get this evidence wrong or incomplete and everything downstream - triage, containment, the ticket you hand to the next shift - is built on sand. This is also usually the fastest, cheapest evidence to collect, so there's no excuse for skipping it just because the alert "looks" benign.

## 1. File Identity: Name, Size, Extension, MIME Type

Capture all four together, never in isolation - the mismatches between them are often the first real signal.

| Field | What to record | What to check for |
|---|---|---|
| File name (as submitted) | Exact string, including Unicode/RTL characters | Right-to-left override tricks, double extensions (`invoice.pdf.exe`), homoglyphs |
| Declared extension | From filename | Does it match the container the app expects (upload widget restricted to `.csv`, but extension is `.csv ` with a trailing space or null byte)? |
| MIME type (declared) | From HTTP `Content-Type` header at upload | Attacker-controlled, trivially spoofed - never trust this alone |
| MIME type (detected) | From magic-byte/file-signature inspection (`file` command, `libmagic`, or the AI platform's own content sniffer) | A file declaring `image/png` whose magic bytes are `MZ` (PE header) or `PK` (ZIP/OOXML) is an immediate red flag |
| File size | Bytes, exact | Anomalously small "documents" (a few KB DOCX with no real content) or anomalously large images can indicate embedded payloads or steganography |

**[ANALYST]** - Extension/MIME/magic-byte mismatch is one of the highest-value, lowest-noise indicators you'll get on this playbook. A `.docx` that is magic-byte-confirmed as a valid OOXML ZIP but contains a `vbaProject.bin` stream inside is worth a macro deep dive even if the AV scan comes back clean - static AV signatures lag behind macro obfuscation. Don't assume the AI application's front-end validation caught this; most upload widgets only check the extension string, not the actual bytes.

## 2. SHA256 Hash

Compute SHA256 on the raw bytes as received by the ingestion pipeline, before any transcoding, decompression, or "helpful" normalization the AI app does (many platforms re-encode images or flatten PDFs on ingest - hash before that happens, and hash again after if the pipeline mutates the file, so you have both).

**[ENGINEERING]** - The upload handler should log SHA256 (and ideally SHA1/MD5 alongside for legacy tool compatibility) synchronously at receipt, tied to submission ID, tenant/user ID, and timestamp, before the file reaches any LLM context window or code-execution sandbox the AI app provides. This hash is your pivot key: search it against internal history (has this exact file been uploaded before, by whom, how many times, across which tenants) and external sources (VirusTotal-style multi-engine lookups, vendor threat intel feeds, your own IOC platform). A hash with zero prior sightings anywhere is not automatically malicious, but it removes "well-known safe file" as an easy closure path.

## 3. Malware Scan Result

Run at minimum one signature-based AV/EDR engine plus, where available, multi-engine reputation scanning. Record per engine: verdict (clean/malicious/suspicious/unscannable), detection name, engine version, and definitions date - stale definitions on a "clean" verdict are worth flagging separately, not treated as equivalent to a fresh clean result.

| Field | Example |
|---|---|
| Scanner | Corporate EDR (e.g., Defender for Endpoint) |
| Verdict | Malicious |
| Detection name | Trojan:O97M/Obfuse.gen |
| Engine/defs version | 1.403.xxx, updated 2026-09-14 |
| Scan mode | Static signature only (no macro emulation) |

Static scan misses matter for this playbook: password-protected ZIPs/archives, encrypted PDFs, and heavily obfuscated PowerShell inside macros routinely return "clean" or "unscannable" from signature engines because the payload never gets unpacked for inspection. **[ANALYST]** - treat "unscannable" as its own category, not as "clean." Escalate it to sandbox regardless of how the scanner labeled it.

## 4. Sandbox Result

Detonate in an isolated sandbox (dynamic analysis) and capture behavioral evidence, not just a pass/fail score:

- Process tree spawned on detonation (parent/child relationships, e.g., `WINWORD.EXE` spawning `powershell.exe` with an encoded command)
- Network connections attempted (destination IPs/domains, ports, protocol) - relevant to T1071 (Application Layer Protocol) and T1105 (Ingress Tool Transfer) if a second-stage payload is pulled down
- Files dropped/written to disk, registry keys touched, scheduled tasks or services created
- Use of system binaries to proxy execution (mshta, regsvr32, rundll32 - T1218) as a macro-to-execution chain
- Sandbox evasion signals: sleep timers, environment/VM checks, exit-on-no-mouse-movement - a file that behaves differently under emulation than a real detonation would is itself a finding

**[MANAGEMENT]** - sandbox turnaround time should have a defined SLA (commonly 5-15 minutes for automated detonation, longer for manual reverse engineering escalations); track average and 95th-percentile detonation time as a metric, and flag any file that times out or is submitted but never returns a verdict - that gap is a known false-negative pathway attackers rely on.

## 5. File Reputation

Beyond the binary malicious/clean scan verdict, gather contextual reputation: prevalence (never-before-seen vs. seen across thousands of endpoints), first-seen date globally vs. first-seen in your environment, publisher/signing certificate validity (self-signed, revoked, or a certificate previously tied to abuse is a strong signal), and any threat intel overlap - known campaign hash lists, infrastructure reuse, or association with prior phishing (T1566.001) or user-execution (T1204) incidents in your own case history.

**[STAKEHOLDER]** - this is the evidence set that lets the business distinguish "an employee uploaded a legitimate but unusual file our tools haven't seen before" from "someone is testing whether our AI platform will execute or relay a malicious payload." That distinction drives whether this becomes a quiet closure, a user coaching conversation, or an incident with executive visibility - and it's the reputation and prevalence data, not the scan verdict alone, that usually makes that call defensible.

## Known Limitations of This Evidence Set

Encrypted or password-protected archives can't be scanned or detonated without the password, which the uploading user may not be reachable to provide quickly. Sandbox environments miss payloads gated behind sandbox-detection logic or time-delayed triggers longer than the detonation window. MIME-type sniffing can be fooled by polyglot files crafted to be valid under two formats simultaneously. None of these gaps should be treated as "insufficient evidence, close it" by default - document the gap explicitly and route to manual analysis rather than letting an unscannable file default to benign.
