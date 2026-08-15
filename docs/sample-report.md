# Penetration Test Report — http://localhost/dvwa

*Generated: 2026-08-15 21:11 · Scan ID: 67ba05d5-8cb2-43ce-b942-56431cd9da22*

## 1. Executive Summary

An automated assessment of `http://localhost/dvwa` identified **13 confirmed finding(s)** (1 critical, 3 high, 5 medium, 3 low, 1 informational). The most severe issues should be remediated first; details and remediation guidance follow.

## 2. Scope & Methodology

- **Target:** `http://localhost/dvwa`
- **Tools:** OWASP ZAP (active scan), Nmap (service discovery)
- **Analysis engine:** heuristic (n/a)
- **Mode:** sample data (mock)
- **Categories:** Recon, SQL Injection, Cross-Site Scripting, Broken Authentication, Security Misconfiguration

## 3. Findings Summary

| # | Category | Severity | Confidence | Endpoint |
|---|----------|----------|------------|----------|
| 1 | sqli | critical | high | `http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit` |
| 2 | sqli | high | medium | `http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit` |
| 3 | xss | high | medium | `http://localhost/dvwa/vulnerabilities/xss_r/?name=test` |
| 4 | xss | high | low | `http://localhost/dvwa/vulnerabilities/xss_s/` |
| 5 | auth | medium | medium | `http://localhost/dvwa/login.php` |
| 6 | misconfig | medium | high | `http://localhost/dvwa/` |
| 7 | misconfig | medium | high | `http://localhost/dvwa/` |
| 8 | misconfig | medium | medium | `http://localhost/dvwa/config/` |
| 9 | recon | medium | high | `localhost:3306` |
| 10 | auth | low | high | `http://localhost/dvwa/login.php` |
| 11 | misconfig | low | high | `http://localhost/dvwa/` |
| 12 | recon | low | high | `localhost:22` |
| 13 | recon | informational | high | `localhost:80` |

## 4. Detailed Findings

### 4.1 SQL Injection (Critical)

- **Category:** sqli
- **Endpoint:** `http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit`
- **Confidence:** high

**Description.** SQL injection may be possible. The application appears to build SQL queries with unsanitised user input in the 'id' parameter.

**Evidence.**

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
```

**Remediation.** Use parameterised queries / prepared statements and validate all input. Apply least-privilege DB accounts.

### 4.2 SQL Injection - Boolean Based (High)

- **Category:** sqli
- **Endpoint:** `http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit`
- **Confidence:** medium

**Description.** Blind boolean-based SQL injection appears possible on the 'id' parameter of the blind SQLi page.

**Evidence.**

```
Response length differs between true and false conditions
```

**Remediation.** Use parameterised queries and avoid returning differential responses based on query truthiness.

### 4.3 Cross Site Scripting (Reflected) (High)

- **Category:** xss
- **Endpoint:** `http://localhost/dvwa/vulnerabilities/xss_r/?name=test`
- **Confidence:** medium

**Description.** The 'name' parameter is reflected into the HTML response without output encoding, allowing reflected XSS.

**Evidence.**

```
<script>alert(1)</script>
```

**Remediation.** Contextually output-encode all user input and set a restrictive Content-Security-Policy.

### 4.4 Cross Site Scripting (Persistent) (High)

- **Category:** xss
- **Endpoint:** `http://localhost/dvwa/vulnerabilities/xss_s/`
- **Confidence:** low

**Description.** A stored XSS payload in the guestbook message field may be persisted and rendered to other users. Confidence is low pending manual confirmation.

**Evidence.**

```
Stored payload reflected on guestbook page
```

**Remediation.** Encode stored content on output and sanitise on input; deploy CSP.

### 4.5 Absence of Anti-CSRF Tokens (Medium)

- **Category:** auth
- **Endpoint:** `http://localhost/dvwa/login.php`
- **Confidence:** medium

**Description.** The login form does not include an anti-CSRF token, and no account lockout was observed after repeated failed logins.

**Evidence.**

```
<form action="login.php" method="post">
```

**Remediation.** Add per-request anti-CSRF tokens and implement account lockout / rate limiting on authentication.

### 4.6 Missing Security Header: X-Frame-Options (Medium)

- **Category:** misconfig
- **Endpoint:** `http://localhost/dvwa/`
- **Confidence:** high

**Description.** The X-Frame-Options header is not set, leaving pages vulnerable to clickjacking.

**Evidence.**

```
No X-Frame-Options header in response
```

**Remediation.** Set X-Frame-Options: DENY (or a restrictive frame-ancestors CSP directive).

### 4.7 Missing Security Header: Content-Security-Policy (Medium)

- **Category:** misconfig
- **Endpoint:** `http://localhost/dvwa/`
- **Confidence:** high

**Description.** No Content-Security-Policy is defined, weakening defence-in-depth against XSS and data injection.

**Evidence.**

```
No Content-Security-Policy header in response
```

**Remediation.** Define and enforce a restrictive Content-Security-Policy.

### 4.8 Directory Listing Enabled (Medium)

- **Category:** misconfig
- **Endpoint:** `http://localhost/dvwa/config/`
- **Confidence:** medium

**Description.** Directory browsing is enabled on /config, exposing file names and potential configuration artefacts.

**Evidence.**

```
Index of /dvwa/config
```

**Remediation.** Disable directory indexing (Options -Indexes) and restrict access to configuration directories.

### 4.9 Open port 3306/tcp - mysql (Medium)

- **Category:** recon
- **Endpoint:** `localhost:3306`
- **Confidence:** high

**Description.** MySQL 5.7.33 is exposed. If reachable from untrusted networks this significantly widens the attack surface.

**Evidence.**

```
3306/tcp open mysql MySQL 5.7.33
```

**Remediation.** Bind MySQL to localhost only and firewall port 3306 from untrusted networks.

### 4.10 Cookie No HttpOnly Flag (Low)

- **Category:** auth
- **Endpoint:** `http://localhost/dvwa/login.php`
- **Confidence:** high

**Description.** The session cookie PHPSESSID is set without the HttpOnly flag, exposing it to theft via client-side script.

**Evidence.**

```
Set-Cookie: PHPSESSID
```

**Remediation.** Set the HttpOnly and Secure flags on all session cookies.

### 4.11 Verbose Server Header (Low)

- **Category:** misconfig
- **Endpoint:** `http://localhost/dvwa/`
- **Confidence:** high

**Description.** The Server header discloses the exact web server and version, aiding targeted attacks.

**Evidence.**

```
Server: Apache/2.4.25 (Debian)
```

**Remediation.** Suppress or genericise the Server header (ServerTokens Prod).

### 4.12 Open port 22/tcp - ssh (Low)

- **Category:** recon
- **Endpoint:** `localhost:22`
- **Confidence:** high

**Description.** OpenSSH 7.4 is running. Older SSH versions may have known weaknesses.

**Evidence.**

```
22/tcp open ssh OpenSSH 7.4
```

**Remediation.** Restrict SSH access, use key-based auth, and keep OpenSSH updated.

### 4.13 Open port 80/tcp - http (Informational)

- **Category:** recon
- **Endpoint:** `localhost:80`
- **Confidence:** high

**Description.** HTTP service running Apache 2.4.25 (Debian). Hosts the DVWA practice application.

**Evidence.**

```
80/tcp open http Apache httpd 2.4.25 ((Debian))
```

**Remediation.** Keep the web server patched; this is the primary attack surface.

## 5. Recommendations

Prioritise remediation by severity (critical/high first). Adopt parameterised queries, contextual output encoding, secure cookie flags, anti-CSRF tokens, and a complete set of security response headers. Re-scan after fixes to confirm closure.

## Appendix A — Discarded (False Positives / Noise)

- `http://localhost/dvwa/` — Timestamp Disclosure: Discarded as low-confidence informational noise.
