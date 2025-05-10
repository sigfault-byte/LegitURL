> **This is a WIP.**  
> LegitURL works — and it's strict, by choice.  
> But a lot is still being added, tuned, or cleaned up.  
> It’s already useful, but not finished.

## LegitURL  
> Like a **nutrition label for links**  
> Scan a URL to see its 🟩 🟧 🟥 Legitimacy based on **technical behavior**, not reputation.  
> Because trust should be earned — not assumed.

- [1. Who is LegitURL for?](#1-who-is-legiturl-for)
- [2. How Does It Work](#2-how-does-it-work)
- [3. Scoring System](#3-scoring-system)
- [4. Core Detection & Heuristics](#4-core-detection--heuristics)
- [5. Core Detection Features](#5-code-detection-features)
- [6. Example Use Case](#6-example-use-case)
- [7. The Philosophy Behind LegitURL](#7-the-philosophy-behind-legiturl)
- [8. Why LegitURL Exists](#8-why-legiturl-exists)
- [9. Contact & License](#9-contact--license)


**LegitURL is a privacy-focused iOS app** that helps you:  
- **Spot scams** (e.g., `secure-paypal-login.com`)  
- **Avoid trackers** (shady redirects, invasive cookies)  
- **Inspect security** (TLS certs, headers, scripts)  

It uses strict, transparent heuristics to compute a **Legitimacy Score**, based entirely on how the site behaves.

LegitURL analyzes all signals **blindly** — it doesn’t care if the domain is famous or obscure.  
It only cares whether the site **demonstrates a commitment to security and quality**,  
or whether the URL shows signs of deception, like **lookalike domains** or **scam indicators**.

## 1. Who is LegitURL for?

Most people can’t tell if a link is safe — especially when it’s shortened, disguised, or came from an unknown source.  
Browsers rarely warn you unless a page is *blatantly* malicious.

**LegitURL gives you a second opinion before you click.**

Its core audience is anyone who asks:  
> *"Can I trust this link I just found in a message, an ad, or an email?"*

**Ideal for:**  
- Casual users who want a fast safety check  
- Privacy-conscious users avoiding trackers  
- Developers inspecting headers, CSP, and TLS

LegitURL checks both:  
- The **structure of the URL** (to catch scams like `secure-paypal-login.com`)  
- The **behavior of the site** (headers, cookies, redirects, TLS certs, and more)

The original idea was simple: follow a link and show where it leads.  
But that wasn’t enough — real analysis required deeper inspection.

So the app grew into something more technical, now offering:  
- Full URL decomposition  
- HTTP header inspection  
- TLS certificate analysis  
- Cookie behavior scoring  
- Content-Security-Policy (CSP) evaluation  
- Inline script extraction (from a single, minimal GET request)

All done **without exposing any user-identifying information**.

## 2. How Does It Work

Users can paste, type, or scan a QR code to input a URL.  
With a single tap, they receive a **Legitimacy Score**, displayed as:  
🟩 Green, 🟧 Orange, or 🟥 Red.

The app analyzes each URL in **two phases**:

---

### 1. Offline Inspection

LegitURL dissects the full URL structure — including domain, subdomains, path, query parameters, and fragment.  
It checks for:

- Scam patterns
- Encoded traps
- Brand impersonation
- Gibberish / non-dictionary terms
- Suspicious or misleading formatting

---

### 2. Online Behavior Analysis

LegitURL performs a **minimal HTTP GET request** to the *core* URL  
(query parameters and fragments are stripped first).

It captures and analyzes:

- Response headers  
- TLS certificate  
- Cookies  
- HTML body (fully parsed; display capped at 1.2MB)  
- Inline scripts (fully parsed; 3072-byte display cap per script)

If the link triggers redirects, **each destination is looped back through the same analysis** — treated like a new URL.  
This allows LegitURL to detect:

- Tracking redirects  
- Scam chains  
- Downgrades in security  
- Silent server-side rewrites (even when no `Location` header is sent)

→ **No assumptions. No shortcuts. Every step is independently verified.**

---

### Bonus Features

- Create custom **watchlists** for domains, keywords, or brands  
- Browse a built-in **glossary** to understand headers, TLS concepts, and security terms

## 2.1 Valid Input

Only URLs using the **HTTP protocol over TLS (`https://`)** are analyzed — in line with Apple’s `URLSession` requirements.  
Links using other protocols such as `ftp://`, `ssh://`, or `file://` are **not supported**.

If no scheme is specified, `https://` is automatically assumed.  
Non-secure (`http://`) links are considered unsafe by default and are **immediately flagged**, with **no network request performed**.

## 2.2 URL Components Analysis

LegitURL inspects the full structure of a URL **before contacting any server**.  
If a critical signal is found during offline checks, no network request is made at all.

The URL is broken into parts — domain, subdomains, path, query parameters, and fragments — and each is checked for signs of:

- Scam behavior
- Brand impersonation
- Obfuscation
- Tracking infrastructure

---

### What is checked:

- **Brand impersonation** — e.g., `secure-paypal-login.com`
- **Lookalike tricks** — mixed character sets (e.g., Cyrillic + Latin), or visually similar spelling
- **Scam keywords** — known phishing terms or suspicious word combinations
- **Encoded tricks** — hidden emails, UUIDs, or URLs inside query strings
- **Redirect patterns** — embedded or nested URLs passed as parameters

Each part is scored with appropriate weight:

- **Domains and subdomains** carry the most importance
- **Path and fragment** provide behavioral context
- **Query values** are decoded recursively using a custom system called **Lamai**

---

### Technical details:

- Domains are parsed using Apple’s `URLComponents` and the Mozilla Public Suffix List (PSL)
- IDNA (Punycode) normalization ensures proper handling of internationalized domains
- Hyphens and underscores are optionally tokenized for deeper analysis
- Mixed-script detection flags character set combos (e.g., Cyrillic + Latin)

**Brand spoofing and gibberish detection** uses:  
- Levenshtein distance (typo-based similarity)  
- 2-gram similarity (pattern-based matching)  
- iOS dictionary lookups to identify real words  
- Entropy fallback to catch random or machine-generated strings  

**Path, query, and fragment values** are:  
- Decoded (Base64, percent-encoded, Unicode, etc.)  
- Inspected for known structures and patterns:  
  - Email addresses, IPs, UUIDs, nested URLs  
  - Scam terms or obfuscated tokens  

Decoded values — especially URLs — are **recursively re-analyzed** with the same strict logic as the original input.

## 2.3 Response Analysis

After inspecting the URL structure, LegitURL sends a **single, secure request** to see how the server behaves.

It checks:
- What kind of response the site returns
- Whether it tries to redirect you
- Whether its certificate and headers follow modern security practices
- And whether anything shady shows up in the page's code or cookies

The request is **strictly controlled**:
- No personal data is sent
- No session is stored
- No cookies, no autofill, no fingerprinting
- Just a clean snapshot of the server’s first impression

---

### Technical Details

The GET request is made using a sandboxed configuration that avoids leaking any user data.  
LegitURL simulates a fresh, anonymous visit — **no cookies, no storage, no session reuse**.

<details>
<summary>Click to view request code (Swift)</summary>

```swift
// Create a URLRequest for the URL.
var request = URLRequest(url: url)
request.httpMethod = "GET"
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
  - Sent over **HTTPS only**, to URLs stripped of their query parameters and fragments  
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
- Density of inline and external script content ( normalized to script per 1kB)
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

### Dependencies

- [ASN1Decoder](https://github.com/filom/ASN1Decoder)  
  Used to decode and parse TLS certificate structures (X.509), including CN, SANs, issuer, validity, and extensions.

- [PunycodeSwift](https://github.com/gumob/PunycodeSwift)  
  Used to convert Internationalized Domain Names (IDNs) to their ASCII-compatible encoding (ACE) for uniform comparison.

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

### HTML and Script Analysis (Byte-Level Parsing)

- **Document boundaries** are pre-scanned in the first and last 500 bytes:
  - If `<html>` is missing → **critical penalty**, document marked as non-HTML (no further parsing)
  - If `</html>` is missing → **moderate penalty**, fallback end is set to end of the document

- All `<` positions are scanned to locate tags:
  - If followed by `/`, checks for closing `</head>`, `</body>`, `</script>`
  - Otherwise, checks for opening `<head>`, `<body>`, or `<script>` in the next few bytes

- **Inside `<head>`**:
  - Searches for `<meta http-equiv="Content-Security-Policy">`

- **Inside `<script>`**:
  - Attempts to locate the closing `</script>` within the first 3072 bytes
  - Extracts:
    - `nonce` value
    - `integrity` attribute (SRI)

- Scripts are sorted by context and origin:
  - For `<script src=...>`: scans for `=` followed by quoted values
  - Determines source origin (e.g., `'self'`, external URL, protocol-relative, data URI)

- **Inline script content is concatenated into a “JavaScript Soup”**, then scanned:
  - Searches for all `(` and `.` byte positions
  - At each candidate:
    - Check previous 1–3 bytes for common JS accessors or function names
    - Apply filters to skip junk matches

- Matches are compared against a list of **risky JS functions** (e.g., `eval`, `atob`, `btoa`, `document.write`)
- Detects suspicious **combinations** like:
  - `document.getElementById()` followed by `.submit()`
  - `atob()` followed by `JSON.parse()`

---

### Cookie Scoring Engine (Byte + Flag-Based Heuristics)

- iOS flattens headers via `URLSession`, merging duplicate `Set-Cookie` keys
- Cookies are parsed using `HTTPCookie` and then **encoded as bit flags**:
  - Missing `HttpOnly`
  - Missing `Secure`
  - Expiry > 30 days
  - Size thresholds
  - Entropy levels
  - Set on a non 200
  - `SameSite` policy state  

  
  > A missing SamesitePolicy is **not** defaulted to `lax`
  

- Flag combinations are mapped to penalty levels:
  - Small cookie (<10 bytes) with low entropy → **ignored**
  - Session cookies without `HttpOnly` → **capped penalty** (CSRF risk)
  - Large cookie (>100 bytes) with high entropy → **often flagged as dangerous**

> Cookie logic is still evolving.  
> It’s tricky to balance RGPD logic — where a banner asks for consent, but cookies are already set — versus short-lived session cookies and long-lived marketing junk.
> In theory, no cookie should be set at all — LegitURL simulates a clean, anonymous GET with no query parameters.

---

### TLS Certificate Analysis

LegitURL performs manual analysis of the site's TLS certificate, after decoding the raw X.509 structure.

Checks include:

- **Chain validity**
  - Verified alongside `URLSession`’s built-in trust checks  
  - Many sites rely on the browser to complete missing intermediate chains — LegitURL flags this as a signal of **incomplete or lazy TLS setup**
- **Expiration and issue date**
  - Flags **newly issued certificates** (e.g., <7 days old)  
  - Flags **overly long durations** (>13 months)
- **CA Type**
  - Extracted via OID from policy extension  
  - Supports detection of DV, OV, and EV certs
- **Subject Alternative Name (SAN) entries**
  - Checks for:
    - Wildcard usage
    - Scope (subdomain vs unrelated FQDNs)
    - Legitimate coverage of the target domain

> While LegitURL could bypass `URLSession` to run fully manual certificate validation, doing so may lead to App Store rejection.  
> Instead, it uses system-level trust — and builds **scoring logic** on top of it.
> Some servers only serve the leaf certificate, relying on browsers to auto-complete the trust chain using cached intermediates.

> Unfortunately, when Apple’s secure TLS enforcement is enabled, URLSession doesn’t distinguish between:  
	•	Missing certificate  
	•	Incomplete chain (leaf only)  
	•	Invalid or untrusted certificate  

> This means LegitURL can’t always tell why the TLS validation failed — only that it did.
> If the handshake fails under strict, system-default rules, it’s treated as a critical signal.

---

### SAN Pattern Analysis — Detecting Cloaked Scam Infrastructure

In particular, LegitURL inspects the SAN field for **abnormal domain spread**:

> A certificate issued by Let's Encrypt with **many individual FQDNs** (e.g., 10–100 entries), no wildcards, and a short lifespan is a strong signal of **malicious infrastructure** designed for evasion.

---

#### Why It Matters

- **Legit orgs use wildcards**
  - E.g., `*.example.com` for `api.`, `login.`, `cdn.`, etc.
  - It’s efficient, maintainable, and works with internal subdomains

- **Let’s Encrypt wildcards require DNS-01**
  - Scammers avoid this because it requires control of DNS
  - They use HTTP-01 for quick provisioning on throwaway servers

- **Dozens of FQDNs on a single cert?**
  - No real business does this — but it’s perfect for:
    - Phishing kits
    - Redirect chains
    - Scam landing pages
    - Disposable botnet mailers

- **Unrelated domains = intentional obfuscation**
  - A SAN list filled with random, loosely related, or totally unrelated domains is a red flag
  - It’s often part of a **scamkit cloaking network**

- **Risk is compounded**
  - When combined with shady TLDs (`.biz`, `.click`), obfuscated JS, bad CSP, and tracking cookies —  
    → **It’s no longer coincidence. It’s infrastructure.**

> Counterexample:
> steampowered.com uses a Let’s Encrypt DV certificate with 48 SANs and no wildcard — a pattern that would normally raise red flags.

> However, the domain redirects to store.steampowered.com, which presents an EV certificate with only 2 SANs — scoped and trustworthy.

> In this case, LegitURL waives the penalty for the original certificate, recognizing the redirect to a more secure, verified endpoint.

---

### Conclusion

This TLS behavior deviates from best practices and reveals intent:  
> Not to serve users securely — but to **cloak an entire ecosystem of scam domains** behind a single certificate.

### HTTP Headers Analysis

LegitURL analyzes HTTP headers **only on `200 OK` responses**, ensuring the content being evaluated is *directly served* — not redirected.

#### Content-Security-Policy (CSP)

- Searches for either `Content-Security-Policy` or `Content-Security-Policy-Report-Only`
  - If the former is missing, a **heavy penalty** is applied  
  - If only the `Report-Only` version is found, it's used for analysis (but still penalized)

- Ensures the header ends with a semicolon (`;`)
  - If not, appends one

- Splits the header into directives using `;` as a separator

- If `script-src` is missing:
  - Falls back to `default-src`
  - If both are missing, checks for `require-trusted-types-for 'script'`
  - If **none** of these are found, the policy is considered **incomplete**, and the same penalty as a missing CSP is applied

- Maps combinations and directive values to **bitflags** for scoring

- Compares:
  - Extracted inline script `nonce` values
  - External script origins  

  against allowed sources in the CSP header

> Most modern threats don’t need to breach the server, they exploit what runs in the browser.
> A strict CSP won’t stop every attack, but it does shrink the client-side attack surface.


#### Other Security Headers

These headers are also inspected:

- `Strict-Transport-Security` (HSTS) — presence and max-age
- `X-Content-Type-Options` — should be `nosniff`
- `Referrer-Policy` — expected to be `strict-origin` or stronger
- `Server`, `X-Powered-By` — flagged if leaking unnecessary metadata

> Even trusted domains often misconfigure these. 

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

**→ Score 90**

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
| **CSP**             | Missing | |-50 |
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

> These aren’t scams — but if we didn’t already trust them, **nothing in their technical behavior would give trust signal.**

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


## 7. The Philosophy Behind LegitURL

LegitURL humbly tries to show what browsers are silently correcting for us.  

In the early days of the web, **browsers had** to be forgiving. If they weren’t, developers would’ve given up, overwhelmed by how strict the platform could be. But, decades later, that leniency remains, and it’s now hiding problems instead of solving them.  

Browsers have become **the compilers of the internet**,  except they don’t crash with a segfault. They just keep rendering. They try to “fix” our mistakes: silently rewriting malformed HTML, guessing character encodings, injecting missing tags, and even executing scripts with poor CSP setups. The HTTP headers? **They’re like compiler flags**,  but most websites either forget them or misuse them entirely.  

While this may have made sense 25 years ago, today it’s less defensible. Many of the websites that get away with bad setups aren’t abandoned; **they’re actively making money**. Their excuse is often “legacy stack” or “it’s too much work.” But if the site is still live and bringing value, there’s no excuse not to invest in proper engineering.  

The rise of bloated frontend frameworks didn’t help. Teams now download a dozen packages — some they don’t understand — and ship bloated builds full of eval(), random cookies, third-party scripts, and lazy security decisions.  

Eventually, **even browsers had enough**. Around 2020, they began enforcing defaults, like treating missing SameSite attributes as Lax. They promoted Content-Security-Policy, not as a silver bullet, but as a way to shrink the attack surface. It won’t sanitize inputs or block DDoS traffic. But it protects the browser — and by extension, the user — from being forced to make bad assumptions.  

**Browsers are blamed for being slow or memory-hungry. But think about it: they’re not just rendering websites. They’re debugging them in real time**.  

LegitURL exists to highlight this. Not to punish, but to give users visibility into what’s really going on behind the scenes. The web isn’t just wide — it’s wild. And even the biggest, most trusted sites often rely on bad hygiene while demanding that junior devs invert binary trees in COBOL to get hired.  

## 8. Why LegitURL Exists

A few months ago, a relative fell victim to a phishing scam. The bank refused to reimburse them, claiming they couldn’t prove the user was at fault—yet offered no evidence of robust security on their own platform. The phishing link, now offline, was insidious: it hid the real bank’s website in the URL fragment, a trick invisible to most users.  

This experience hit hard. I wanted to build a tool to empower non-technical users to see where a link really leads—highlighting the true domain, TLD, and any red flags like deceptive fragments.  
LegitURL started as a simple way to catch scams, but the deeper I dug, the clearer it became: **the web is riddled with issues far beyond phishing**.  

Too many websites skip basic security practices. Redirects often mask tracking or deception,  technical behavior rarely matches a site’s reputation, leaving users vulnerable. LegitURL evolved to expose these flaws, analyzing URLs with strict, transparent heuristics to reveal what browsers silently forgive.
I also wanted a fast, offline-capable app to replicate the manual checks I’d do for a URL—because having that power at your fingertips is practical and empowering. LegitURL exists to give users a second opinion, protect their privacy, and push for a safer, more accountable web.


## 9. Contact & License

LegitURL is released under the **GNU AGPLv3 license**.

You’re free to use, study, and improve the code — even in commercial projects —  
**but any derivative work, especially one used over a network (e.g. as a web service),  
must also be made public under the same license.**

This protects users and ensures the project remains open and honest.

> See [LICENSE](LICENSE) for full terms.

For questions, feedback, or if you want to collaborate, contact:  
iskndre@protonmail.me