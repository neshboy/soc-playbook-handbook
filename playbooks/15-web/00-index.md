# Web Security Playbooks

## What ties this category together

Every playbook in this folder deals with attacks that ride in over HTTP or HTTPS against something you expose on purpose - a web app, an API, an admin console, a login page. That's the common thread: the attacker doesn't need a foothold on your network first, they just need a URL. In ATT&CK terms almost everything here traces back to **T1190 - Exploit Public-Facing Application** as the eventual objective, frequently preceded by **T1595 - Active Scanning** while someone (or something automated) maps out what's running before deciding how to hit it.

The alerts in this category also share a volume problem the other categories mostly don't have. A domain controller doesn't get port-scanned by strangers in Brazil forty times a day. A public login page does. So detection logic here spends a lot of effort on separating background radiation - scanners, bots, researchers, misconfigured integrations hammering an endpoint - from something actually shaped like an attack chain. If you're coming from an identity or endpoint background, recalibrate your baseline: "weird" traffic hitting a public web app on a Tuesday afternoon is closer to normal than exceptional.

## Log sources and tooling that matter here

**[ENGINEERING]** - The playbooks in this folder assume you have, at minimum, access to:

- **WAF logs** (e.g., AWS WAF, Cloudflare, Azure Front Door/App Gateway, F5, ModSecurity) - your first and often best source, since a decent WAF has already done payload classification for you. Pull both allowed and blocked events; alerting only on blocks means you miss everything that got through.
- **Web/app server logs** - IIS (W3C format), Apache/Nginx access and error logs, or the application's own structured logging. Fields you'll reference constantly across this category: client IP, `X-Forwarded-For`/`X-Real-IP`, HTTP method, URI/query string, status code, user-agent, referer, response size, and time-to-first-byte for timing-based inference attempts.
- **Reverse proxy, load balancer, and CDN logs** - the true source IP frequently lives here, not at the origin. If you only have origin server logs, expect every request to appear to come from your LB or CDN edge node.
- **API gateway logs** - for anything fronted by Kong, Apigee, AWS API Gateway, Azure APIM - request/response pairs, auth token validation results, and rate-limit rejections.
- **Application/database audit logs** - needed to confirm impact for injection-class alerts (did a query actually execute, was data returned, was a table modified).
- **EDR/host telemetry on the web server itself** - for the playbooks where a successful exploit drops a process or file (web shells, RCE, malicious upload), the web log tells you the request happened; the host tells you what it did afterward.
- **Vulnerability scanner and pentest schedules** - not a log source, but you need the calendar. Authorized scanning that isn't cross-referenced looks identical to reconnaissance.

**[STAKEHOLDER]** - This is the category most directly tied to customer-facing risk: a confirmed SQL injection or authentication bypass on a production app can mean direct data exposure, regulatory notification obligations, and reputational fallout in a way an isolated internal endpoint alert usually doesn't. Prioritization and escalation thresholds for this folder should reflect that the "front door" is involved.

## Friction specific to this category

Web security investigations have their own particular flavor of pain. The biggest recurring one is source IP attribution - between CDNs, load balancers, and corporate proxies, the IP in your alert is frequently the edge device, not the attacker, and if `X-Forwarded-For` isn't being logged (or isn't trusted because it's client-settable) you're stuck. Encoding is the second headache: URL-encoding, double-encoding, Unicode tricks, and base64 wrapping around payloads all break naive string-match detections and make manual log review tedious - dont assume a clean-looking request is actually clean, decode it before ruling it out. WAFs also tend to log the *blocked* payload nicely but say very little about what happened to requests that were allowed through, which is exactly the traffic you need to review most closely. Add to that: staging/dev environments quietly not sending logs anywhere, vulnerability scans from an authorized third party lighting up ten playbooks at once, request bodies getting truncated at some arbitrary log size limit right before the interesting part, and multi-tenant SaaS platforms where "the attacker" turns out to be another customer's misconfigured integration hammering their own API key. Analyst needs to validate scanner-vs-attacker context before escalating - this is where a lot of web alerts either resolve as Benign Positive or Expected Activity rather than confirmed malicious, and that's a normal, correct outcome, not a failure to find something.

## Playbooks in this category

| # | Playbook | File |
|---|---|---|
| 1 | SQL Injection | `sql-injection.md` |
| 2 | XSS | `xss.md` |
| 3 | Command Injection | `command-injection.md` |
| 4 | Path Traversal | `path-traversal.md` |
| 5 | LFI (Local File Inclusion) | `lfi.md` |
| 6 | RFI (Remote File Inclusion) | `rfi.md` |
| 7 | Web Shell Detection | `web-shell-detection.md` |
| 8 | Credential Stuffing | `credential-stuffing.md` |
| 9 | Password Spraying (Web-Facing) | `password-spraying-web-facing.md` |
| 10 | Admin Panel Scanning | `admin-panel-scanning.md` |
| 11 | Malicious File Upload | `malicious-file-upload.md` |
| 12 | RCE (Remote Code Execution) | `rce.md` |
| 13 | API Abuse | `api-abuse.md` |
| 14 | Enumeration | `enumeration.md` |
| 15 | Authentication Bypass | `authentication-bypass.md` |
| 16 | Session Hijacking | `session-hijacking.md` |
| 17 | Bot Traffic / Web Scraping | `bot-traffic-web-scraping.md` |
| 18 | Suspicious User-Agent | `suspicious-user-agent.md` |
