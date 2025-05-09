## LegitURL  
> Like a **nutrition label for links** — LegitURL shows how secure and trustworthy a website really is, based on technical behavior, not reputation.  
> Because trust should be earned — not assumed.

LegitURL is a privacy-focused iOS app that helps both non-technical and technical users assess the **legitimacy of an unknown web link**.

It uses strict, transparent heuristics to compute a **Legitimacy Score**, based solely on how the site behaves:  
- Is the certificate valid?  
- Are the security headers correct?  
- Are there shady redirects, cookies, or inline scripts?

The app analyzes these signals **blindly**, meaning it doesn’t care if the domain is famous or obscure.  
It only cares if the site **demonstrates a commitment to security and quality in its web development practices** —  
or if the URL itself shows signs of deception, like **lookalike domains** or **scam patterns**.

## 1. Who is LegitURL for?

Most people can’t tell if a link is safe — especially when it’s shortened, disguised, or coming from an unknown source.  
Browsers rarely warn you unless a page is *blatantly* malicious.

**LegitURL gives you a second opinion before you click.**

Its primary audience is non-technical users who want to know:  
> *"Can I trust this link I just found in a message, an ad, or an email?"*

The app checks both:
- The **structure of the URL** (to detect scam tricks like `secure-paypal-login.com`)
- The **behavior of the website** (headers, cookies, redirects, TLS certificates, and more)

Originally, the goal was simple: follow a link and reveal its final destination.  
But as the project evolved, it became clear that proper analysis required deeper inspection.

As a result, LegitURL now also includes features that technical users might appreciate:  
- Full URL decomposition  
- HTTP header inspection  
- TLS certificate analysis  
- Cookie behavior  
- Content Security Policy (CSP) evaluation  
- Inline script extraction from the HTML body (after a single, minimal GET request)

All done **without exposing any user-identifying information**.

## 2. How Does It Work

Users can paste, type, or scan a QR code to input a URL.  
With a single tap, they receive a **Legitimacy Score**, displayed as:  
🟩 Green, 🟧 Orange, or 🟥 Red.

The app analyzes each URL in **two phases**:

1. **Offline inspection**  
   LegitURL dissects the full URL structure — including domain, subdomains, path, query parameters, and fragments.  
   It looks for scam patterns, encoded traps, brand impersonation, suspicious gibberish, and more.

2. **Online behavior analysis**  
   The app then performs a **minimal HTTP GET request**, stripped of query parameters and fragments, to the *core* URL.  
   It captures and inspects:
   - Response headers  
   - TLS certificate  
   - Cookies
   - HTML body (fully analyzed, first 1.2MB shown)  
   - Inline scripts (fully parsed, first 3072 bytes per script shown)

###  Redirect-aware, but not redirect-blind

If the link triggers redirects, **each destination is looped back into analysis** — just like a new URL.  
This allows LegitURL to detect:
- Tracking redirects
- Scam chains
- Downgrades in security
- Silent rewrites (even when no `Location` header is sent)

Every step is inspected independently — no assumptions, no shortcuts.

---

Users can also:

- Create custom watchlists (brands, keywords, domains) to monitor
- Explore a built-in glossary of web and security terms to better understand the findings

## 2.1 Valid Input

Only URLs using the **HTTP protocol over TLS (`https://`)** are analyzed — in line with Apple’s `URLSession` requirements.  
This means links using other protocols such as `ftp://`, `ssh://`, or `file://` are **not supported**.

If no scheme is specified, `https://` is automatically assumed.  
Non-secure (`http://`) links are considered unsafe by default and are **flagged immediately**, without performing any network request.

## 2.2 URL Components Analysis

LegitURL first inspects the structure of the link **before contacting any server**.  
It breaks the URL into parts — domain, subdomains, path, query parameters, and fragments — and checks for signs of scams, impersonation, or tracking.

### What is checked:
- **Brand impersonation** — like `secure-paypal-login.com`
- **Lookalike tricks** — mixed character sets (e.g., Cyrillic + Latin), or similar spelling
- **Scam keywords** — known phishing words or suspicious combinations
- **Encoded tricks** — hidden emails, UUIDs, or links inside query strings
- **Redirect patterns** — URLs hiding other URLs inside them

Every part of the URL — domain, path, query, and even fragment — is analyzed with appropriate weight:
- Domains and subdomains are the **most important**
- Path and fragment are scanned for context and intent
- Query values are decoded recursively using a custom system called **Lamai**

---

### Technical details:

- Domains are split using Apple’s `URLComponents` and the Mozilla PSL (Public Suffix List)
- IDNA (punycode) normalization is applied
- Hyphens and underscores might be split for tokenization
- Mixed-script detection flags suspicious combinations (e.g., Cyrillic+Latin)
- Brand lookalikes or gibberish detected using:
  - Levenshtein distance
  - 2-gram similarity
  - iOS dictionary (to detect real words)
  - Entropy fallback for gibberish detection 
- Path, Query and fragment values are parsed, decoded (Base64, URL-encoded, etc.), and inspected for:
  - Emails, IPs, UUIDs, nested URLs
  - Scam terms or gibberish

Decoded URLs are **re-analyzed recursively**, applying the same strict logic as the original.

---

## 2.3 Response Analysis

After inspecting the structure of the URL, LegitURL sends a **single, secure request** to see how the website behaves.

It checks:
- What kind of response the site gives
- Whether it tries to redirect you
- If its certificate and headers follow modern security practices
- And whether anything shady shows up in the page's code or cookies

The request is **strictly controlled**:
- No personal data is sent
- No session is stored
- No cookies, no autofill, no fingerprinting
- Just a clean snapshot of the server’s first impression

---

### Technical details

The GET request is made using a controlled configuration that avoids leaking any user data.  
LegitURL simulates a fresh, anonymous visit — **no cookies, no storage, no session reuse.**

<details>
<summary>Click to view request code (Swift)</summary>

```swift
// Create a URLRequest for the URL.
var request = URLRequest(url: url)
request.httpMethod = "GET" // Specify the HTTP method.
request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", forHTTPHeaderField: "User-Agent")
request.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
request.setValue("gzip, deflate, br", forHTTPHeaderField: "Accept-Encoding")
request.timeoutInterval = 10

// Configure a dedicated URLSession for this request.
let config = URLSessionConfiguration.default
config.requestCachePolicy = .reloadIgnoringLocalCacheData
config.httpCookieStorage = nil
config.urlCache = nil
config.httpShouldSetCookies = false
config.httpShouldUsePipelining = false
config.httpMaximumConnectionsPerHost = 1
config.timeoutIntervalForRequest = 10
config.timeoutIntervalForResource = 15
config.httpCookieAcceptPolicy = .never
```
</details>

- The request is:
  - Sent over HTTPS only  
  - Time-limited to **10 seconds**

- The response is parsed but **not followed**:
  - Redirects (`3xx`) are captured, not followed blindly
  - External vs. internal redirects are identified
  - Missing `Location` headers are flagged as **silent rewrites**

Captured content includes:

- **Headers** — inspected for security misconfigurations
- **TLS Certificate** — checked for:
  - CN / SAN matching
  - Expiration
  - Issuer / trustworthiness
- **HTML body** — fully analyzed, with a 1.2 MB display cap
- **Inline scripts** — extracted and scanned (first 3072 bytes per inline script shown)
- **Cookies** — fully parsed and scored by privacy and lifespan

If a redirect is detected, the destination is **looped back** into the same full analysis pipeline.

### TLS Certificate Analysis

Checks include:

- Domain listed in SAN
- Certificate validity (not expired)
- Valid CA chain
- Self-signed detection
- Certificate freshness (too short or too long)
- Flooded SAN list detection (common in DV cert abuse)

---

### Cookie Analysis

- Cookies set on non-`200` responses are considered suspicious  
- Attributes analyzed:
  - Value size and entropy
  - `SameSite`, `HttpOnly`, `Secure` presence

  > LegitURL does **not assume `SameSite=Lax`** when the attribute is missing.  
  While modern browsers may treat missing SameSite as `Lax` by default,  
  **LegitURL treats absence as a missing protection** for two reasons:
  - iOS does not reliably expose whether the header was explicitly set
  - Security should be **opt-in**, not assumed from browser defaults
  - Exportability / reusability across domains

- Cookies are flagged as:
  - **Tracking**
  - **Suspicious**
  - **Dangerous**

Cookies previously seen in the redirect chain are not penalized again, but tracked.  
Cookies set during `3xx` responses are penalized **more heavily**.

---

### HTML Body Analysis

Triggered only if response is `200` and content-type is `text/html`.

Checks include:

- Valid HTML structure (`<html>`, `<head>`, `<body>`)
- Malformed `<script>` tags
- Script-to-content ratio
- Density of inline and external script content ( nromalized to script per 1kB)
- Suspicious JavaScript patterns:
  - Setters like `eval()`, `atob()`
  - Accessors like `document.cookie`, `sessionStorage`, `WebAssembly`
  - Risky behavior pairings (e.g., `getElementById()` near `.submit()`)

Nonce values and external script URLs are stored for **CSP comparison**.  
Subresource Integrity (SRI) detection is supported (hashes are shown), but not yet validated due to the performance cost of asynchronous verification.  
Script SHA values are extracted and displayed but not cryptographically verified yet.

---

### Header Analysis

Checks include:

#### Content-Security-Policy (CSP)
- Missing CSP is heavily penalized
- Requires one of: `script-src`, `default-src`, or `require-trusted-types-for`
- Penalizes:
  - `unsafe-eval`
  - `unsafe-inline` 

- Only `script-src` and `default-src` directives' values are currently analyzed and penalized,  
but all directives are parsed to detect inconsistencies or suspicious entries.  
This ensures future directives aren’t silently ignored, even if they’re not yet scored.
- Compares CSP nonces with actual inline script nonces (mismatch is flagged)
- Flags unused or unrelated `script-src` entries

#### Other Security Headers
- `Strict-Transport-Security` (HSTS) presence and duration
- `Content-Type` declaration
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- Header leakage via `Server`, `X-Powered-By`, and similar fields

## 2.4 Output

### The app outputs a safety rating:

- 🟥 **Red = Unsafe**  
  Poor security, risky behavior, or suspicious patterns.  
  Doesn’t always mean scam — but if you don’t know the site, don’t waste your time.  
  **The server didn’t even try to protect users — or it relies on the browser to cover for its weaknesses.**

- 🟧 **Orange = Suspicious**  
  Mixed signals: some good, some weak.  
  Often caused by bad hygiene, lazy setup, or partial protection.  
  **Trusted brands may land here — they might lean on reputation instead of doing it right.  
  This doesn't necessarily mean the site is malicious, but it indicates potential security weaknesses or privacy-unfriendly practices you should be aware of.**

- 🟩 **Green = Safe**  
  Strong security signals: clean redirects, proper headers, trusted certificates.  
  **Not bulletproof — but a clear sign the site is doing things right.**

---

### Advanced users can view detailed breakdowns:

- URL components  
- All security findings and logs  
- Full HTTP headers  
- CSP policy  
- Cookies  
- Certificate info  
- HTML body (display cap: 1.2 MB)  
- Extracted inline JavaScript (display cap: 3072 bytes per script)

## 3. Scoring System

Every **redirect chain** is evaluated as a whole, with a base score of **100**.

The final rating reflects both individual issues and **patterns across the chain**.

### Examples of penalized signals:
- Scam word in subdomain  
- Watchlist brand in domain  
- High-entropy or obfuscated path  
- Dangerous JavaScript in body  
- Fresh DV certificate  
- Insecure or tracking cookies  
- Misconfigured headers

The impact of each signal depends on **where** and **how** it appears:

- `applepie.com` is treated differently than `secure-apple.com`  
- A cookie on a `200 OK` is not the same if set during a redirect

### Bit Flags & Scoring Logic

LegitURL uses **bit flags** to track signal types across the entire redirect chain.  
When certain combinations are detected, the score is **aggressively downgraded**, even if each signal alone wouldn’t be critical.

#### Examples of elevated-risk combinations:
- Scam keyword in subdomain + known brand in domain → **Critical**
- Fresh DV certificate + weak headers + malformed HTML → **Dangerous**
- URL 1: [ScamWord]  
- URL 2: [Brand + DV Cert]  
		→ Result: [Scam + Brand + DV] → CRITICAL

## 4. Core Detection & Heuristics

### Dependencies

- [ASN1Decoder](https://github.com/filom/ASN1Decoder)  
  Used to decode and parse TLS certificate structures (X.509), including CN, SANs, issuer, validity, and extensions.

- [PunycodeSwift](https://github.com/gumob/PunycodeSwift)  
  Used to convert Internationalized Domain Names (IDNs) to their ASCII-compatible encoding (ACE) for uniform comparison.

---

### Heuristic System

LegitURL does not rely on blacklists, allowlists, or pre-trained models.  
It uses a strict set of **deterministic heuristics** to detect scam patterns, weak security posture, and suspicious behaviors.

Signals are grouped and scored across five main areas:

1. **URL structure** (domain, subdomain, path, query, fragment)
2. **TLS certificate** (CN/SANs, CA chain, validity)
3. **HTTP headers** (CSP, HSTS, leak-prone headers)
4. **Cookies** (security attributes, tracking potential)
5. **HTML & JS body** (structure, script density, suspicious JS usage)

Each signal is converted into a penalty and sometimes a bit flag.  
Flags are accumulated per-URL and across the redirect chain to evaluate both local and global risks.

Some signals are **contextual** — meaning their impact depends on where and how they appear:

- A tracking cookie on a `3xx` response is penalized more than one on a `200`
- A scammy-looking subdomain is scored more harshly if the domain matches a known brand
- Some signals are marked as **INFO**, meaning they are potentially relevant but not inherently bad

#### Examples of INFO-only signals:
- Certificate is DV / OV / EV (informative, not penalized)
- Internal redirect to a different subdomain
- Small cookies (under 10 bytes) with low entropy

These INFO signals may indicate patterns that deserve attention or correlation —  
but they do not directly reduce the score unless part of a flagged combination.
### These signals are hidden by default in the warning view, so only true **penalized** signals are shown unless the user expands them.
---

## 5. Core Detection Features

LegitURL relies primarily on **Swift’s Foundation library**, with only two external dependencies:

- [PunycodeSwift](https://github.com/gumob/PunycodeSwift) — for converting internationalized domain names (IDNs) to ASCII
- [ASN1Decoder](https://github.com/filom/ASN1Decoder) — for decoding and parsing X.509 TLS certificates

---

### Internal Reference Lists

LegitURL includes several internal datasets to support heuristic detection:

- **Mozilla Public Suffix List (PSL)**  
  Stored in a local SQLite database, with two columns:
  - Raw TLD
  - Punycode TLD (for IDN matching)

- **Known Brands & Trusted Domains**  
  A small but growing list of brand names and their legitimate websites.  
  Used to detect impersonation attempts or domain mismatches.  
  Fully user-expandable from within the app.

- **Scam & Phishing Keywords**  
  A curated list of suspicious words and phrases often used in scams.  
  Includes generic terms like `account`, `secure-login`, `verify`, etc.  
  Fully user-expandable from within the app.

- **Suspicious JavaScript Functions & Accessors**  
  Used in body/script analysis to flag potentially risky behavior:
  - `eval()`, `Function()`, `setTimeout(..., "code")`
  - `atob()`, `btoa()`
  - `fetch()`, `navigator.sendBeacon()`
  - `document.write`, `document.cookie`, `sessionStorage`, etc.

---

### Matching & Scanning

- Most exact matches use `.contains` from Swift Foundation.
- For byte-level inspection, LegitURL uses **custom functions** that scan forwards from a byte offset, with logic to ignore tabs, spaces, and `\n` characters as needed.
- This is used in body parsing and JS inspection to locate and extract relevant tag content quickly.

---

### Typo Detection

All typo detection uses:
- **Levenshtein distance = 1**, backed by  
- **2-gram similarity fallback** (triggered when Levenshtein fails)

---

### Lamai — Recursive Decoder

Lamai is LegitURL’s custom recursive decoder. It attempts to make sense of encoded values found in:
- Query strings  
- Fragments  
- Cookie values  
- Redirect URLs

#### How it works:
- Tries base64 (with automatic padding if `%4 ≠ 0`)
- Attempts URL, percent, and Unicode decoding
- Follows each decoding path as far as it can go (max depth)
- Each decoding branch checks for:
  - Scam keywords
  - Brand impersonation
  - Nested values (UUID, IPs, emails, JSON blobs)
  - Structural patterns
- **Entropy is a last resort**, only evaluated when decoding fails.  
  It's powerful but risky — high entropy doesn’t guarantee encoding, and early checks can block meaningful paths.

---

### HTML Body Analysis

- Fast byte scanning detects `<html>`, `<head>`, `<body>`, and `<script>` tags
- Checks for:
  - Structural validity (proper opening/closing tags)
  - Script tag localisation classification (inline vs. external)
  - Suspicious JS patterns
  - HTML to JS ratio
- Performance:
  - `google.com` (~180KB): ~5ms  
  - `steampowered.com` (~780KB): ~20ms

---

### Cookie Analysis

- Uses a **32-bit mask** to represent cookie traits:
  - `HttpOnly` missing
  - `Secure` missing
  - Various value size
  - High entropy
  - Expiracy
  - SameSite policy
- Combines flags into higher-level heuristics:
  - Example: a 100-byte cookie with 365-day expiry and no `HttpOnly` → flagged as **tracking or malicious**
  - `SameSite=None` + no `Secure` or `HttpOnly` → flagged as **potentially dangerous**
- The system tries to balance **strictness with fairness**, acknowledging some cookies are marketing-related while others may be riskier.

  > LegitURL does **not assume `SameSite=Lax`** when the attribute is missing.  
  While modern browsers may treat missing SameSite as `Lax` by default

---

### TLS Certificate Analysis

- After decoding the X.509 certificate, LegitURL checks:
  - Chain validity (alongside URLSession’s built-in checks)
  - Expiration and issue date (detects **fresh certs** or overly long lifespans)
  - CA type: DV / OV / EV via OID policy extension
  - SAN (Subject Alternative Name) entries — wildcard, scope, and proper domain inclusion

**Note:** While it is possible to bypass URLSession to do full manual cert validation, this would likely lead to App Store rejection. LegitURL respects system level validation but performs its own analysis on top for **scoring and signal extraction**.

---

### HTTP Headers Analysis

LegitURL analyzes HTTP headers only on **200 OK responses**, ensuring the content being evaluated is directly served — not redirected.

#### Content-Security-Policy (CSP)

LegitURL focuses on detecting broken or misleading CSP configurations:

- Only `script-src` and `default-src` are penalized (for now)
- Using `nonce-` or `shaXXX-` with `'unsafe-inline'` → **nullifies the nonce**
- Combining `'self'` with `*` or `https:` → flagged as contradictory
- Compares actual inline script nonce values with the CSP nonce
- External script URLs are checked against what's allowed in the CSP
- Flags excessive or unused domains in `script-src` as suspicious

#### Other Security Headers

These headers are also inspected:

- `Strict-Transport-Security` (HSTS) — presence and max-age
- `X-Content-Type-Options` — should be `nosniff`
- `Referrer-Policy` — expected to be `strict-origin` or stronger
- `Server`, `X-Powered-By` — flagged if leaking unnecessary metadata

> Even trusted domains often misconfigure these. LegitURL applies consistent penalties to encourage real security — not just appearances.

## 6. Example Use Case

### Example 1: Brand Impersonation with Suspicious TLD

If the user has correctly added `bankoftrust.com` to their **watchlist**, the app will:

- Treat `bankoftrust.com` as a **trusted root domain**
- Skip domain-level penalty checks for it
- Still flag any **use of “bankoftrust”** in unrelated subdomains or domains

---

**Pasted URL: https://secure-login.trustedbank.com.userauth-check.info/session?token=xyz**

**URL Breakdown:**

- **Domain:** `userauth-check`
- **TLD:** `.info`
- **Subdomain:** `secure-login.trustedbank.com`
- **Path:** `/session`
- **Query:** `token=xyz`

---

### Offline Analysis:

| Component      | Observation | Signal Type | Action |
|----------------|-------------|-------------|--------|
| **Domain**     | `userauth` not in dictionary | Weak signal | No penalty |
| **TLD**        | `.info` has poor reputation | Moderate signal | -20 penalty |
| **Subdomain**  | Contains scam/phishing terms + brand impersonation (`trustedbank.com`) | Critical combo | Heavy penalty |
| **Path**       | `session` resembles API endpoint (expects value) | Contextual weak signal | -10 penalty |
| **Query**      | Passed to Lamai, no relevant signals found | — | No penalty |

---

### Conclusion:

- Subdomain + `.info` TLD + API-style path forms a **high-risk pattern**
- Offline logic recognizes this combo and applies a **critical penalty**
- Total score drops to **0/100**
- **Online check is skipped** — it's already flagged as too risky

---

### Verdict:

> This URL impersonates a known brand using a deceptive subdomain, a suspicious TLD, and a query path that mimics login flow.  
> **Final Score: 0/100 — flagged as DANGEROUS**

### Example 2: Redirect Chain with Tracking Cookies and Suspicious Scripts

Let’s say a user encounters a shortened link in a promoted X.com post:  
**Pasted URL: bit.ly/mihoyanagi**

---

**Initial URL Breakdown:**

- **Domain:** `bit`
- **TLD:** `.ly`
- **Path:** `/mihoyanagi`

---

### Offline Analysis:

| Component | Observation | Signal Type | Action |
|-----------|-------------|-------------|--------|
| **Path**  | Not recognized by dictionary | None | No penalty |  
| **Redirect** | 301 → domain changes | Weak signal | -10 |

**→ Score remains 100**

---

### Online Analysis Begins

**Request sent with real iOS User-Agent and clean headers**

---

#### Redirect 1: `https://jolyvip.com/mihoyanagi`

| Component | Observation | Signal Type | Action |
|-----------|-------------|-------------|--------|
| **Path**  | Not recognized by dictionary | None | No penalty |
| **Redirect**     | 302 → domain changes again | Weak signal | -10 | 
| **TLS**          | 4 days old | Moderate signal | -10 |
| **Cookie 1**     | 10 bytes, no flags, 31-day lifespan, `SameSite=Lax` | Weak | - |
| **Cookie 2**     | 213 bytes, no flags, `SameSite=Lax` | Moderate | -15 |

---

#### Final URL: `https://coingrok.io`

| Component        | Observation | Signal Type | Action |
|------------------|-------------|-------------|--------|
| **HTML Body**       | 74% inline JavaScript, script density 1.282 | Suspicious | -25 |
| **CSP**             | Missing | -50 |
| **X-Powered-By**    | `Next.js` backend leaked | Weak signal | -5 |
| **Server Header**   | `cloudflare` | Informational | No penalty |

---

### Verdict:

> This link leads through a **redirect chain with cookie abuse, shady TLDs, tracking attempts, and excessive inline scripts**.  
> Final domain leaks stack metadata and hosts CSP violations.  
> **Final Score: 0/100 — flagged as DANGEROUS**

### Example 3: Cloaked Scam Infrastructure via Shared TLS Certificate

Let’s consider the following link:  
**https://www.man-entreprise.com/vrp/ayxxxxxxx/yyyy**  
*(Query parameters have been altered to avoid exposing personal data.)*

---

**Initial URL Breakdown:**

- **Domain:** `man-entreprise`
- **TLD:** `.com`
- **Path:** `/vrp/ayxxxxxxx/yyyy`

---

### Offline Analysis:

| Component | Observation | Signal Type | Action |
|-----------|-------------|-------------|--------|
| **Domain** | Clean | — | No penalty |
| **Path**   | Not recognized, not suspicious | — | No penalty |

**→ Score remains 100**

---

### Online Analysis Begins

**Request sent with real iOS User-Agent and clean headers**

---

#### Redirect 1: `https://ed.manageo.biz/clt-su/SFR/formulaire16_2tps.jsp?...`

| Component       | Observation | Signal Type | Action |
|-----------------|-------------|-------------|--------|
| **Redirect**    | 302 to `.biz` domain | Moderate | -10 |
| **TLD**         | `.biz` — poor reputation | Moderate | -15 |
| **Query string**| Malformed, some keys empty, odd characters | Suspicious | -15 |
| **TLS**         | DV cert (Let's Encrypt), ~10 days old | Informational | No penalty yet |

---

#### TLS Certificate (from `man-entreprise.com`)

| Attribute         | Value |
|------------------|-------|
| **Type**         | DV (Domain Validation) |
| **Issuer**       | Let's Encrypt |
| **Age**          | 10 days |
| **SAN Entries**  | 76 fully-qualified domains, unrelated | 🚨 High-risk |
| **Wildcard**     | None |

→ 🚨 Strong signal of **cloaking infrastructure via shared certificate**

---

#### Final URL: `https://ed.manageo.biz`

| Component         | Observation | Signal Type | Action |
|-------------------|-------------|-------------|--------|
| **Response**      | 200 OK | — | — |
| **Cookie**        | `JSESSIONID` missing `Secure` flag | Weak | -10 |
| **Script origin** | Undetectable or malformed | Suspicious | -15 |
| **Script density**| 1.325 scripts per 1000 bytes | Abnormally high | -15 |
| **TLS**           | DV cert, Let's Encrypt, 25 unrelated SANs | Infra signal | -30 |

---

### Verdict:

> This link leads to a **suspicious redirect chain** starting from a clean domain that shares a **Let's Encrypt DV certificate** with 76 unrelated sites.  
> It lands on a `.biz` domain serving **cloaked or obfuscated JavaScript**, with **leaked personal data** and malformed query patterns.  
> The final destination shares a similarly structured certificate — indicating **shared scam infrastructure** at scale.

**Final Score: 0/100 — flagged as CRITICAL**

### Example 4: Major Brands, Minor Effort

These sites are globally recognized — but when analyzed blindly, as if they were unknown, their setups fall short.

| Site               | Score   | Key Issues |
|--------------------|---------|------------|
| `www.google.com`   | 0/100   | CSP is report-only with `unsafe-eval` and `unsafe-inline` (even with a nonce); sets tracking cookies |
| `m.youtube.com`    | 44/100  | Sets tracking cookies; 92% of HTML is JavaScript; missing `</body>` tag; no `Referrer-Policy` |
| `facebook.com`     | 6/100   | Sets 3 large, secure cookies; 96% of HTML is JavaScript; uses `unsafe-eval`; cookies are modified by JS despite being inaccessible via `document.cookie` |
| `amazon.com`       | 15/100  | Uses `document.write()` inline; no CSP at all |

> These aren’t scams — but if you didn’t already trust them, **nothing in their technical behavior would earn your trust.**

###  Example 5: Major Brand good effort, or close.

### Example 5: Major Brands That Try — Or Almost Do

Some high-profile sites make a visible effort to secure users — and it shows.

| Site                                | Score   | Notes |
|-------------------------------------|---------|-------|
| `stripe.com`                        | 99/100  | Strong CSP, secure headers, minimal leakage — but one cookie is JS-accessible |
| 🇫🇷`immatriculation.ants.gouv.fr`🇫🇷    | 96/100  | Excellent headers; heavy page (3MB); CSP allows 5 script sources, but only 1 is used |
| `apple.com`                         | 60/100  | CSP includes `unsafe-inline` and `unsafe-eval`; weak `Referrer-Policy` |

> Stripe clearly wants to appear trustworthy — and backs it up with real protections.  
> The French government site is surprisingly solid.  
> Apple… may have just forgotten about their headers.


