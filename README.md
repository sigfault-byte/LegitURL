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

  
  > Note: LegitURL does **not assume `SameSite=Lax`** when the attribute is missing.  
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

- Only `script-src` and `default-src` values are currently analyzed and penalized,  
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
  **They didn’t even try to protect you, or they rely on the browser to cover for them.**

- 🟧 **Orange = Suspicious**  
  Mixed signals: some good, some weak.  
  Often caused by bad hygiene, lazy setup, or partial protection.  
  **Trusted brands may land here — they lean on reputation instead of doing it right.**

- 🟩 **Green = Safe**  
  Strong security signals: clean redirects, proper headers, trusted certificates.  
  **Not bulletproof — but a clear sign the site is doing things right.**

---

### Advanced users can view detailed breakdowns:

- URL Components  
- All the security findings / logs  
- Full HTTP headers  
- CSP policy  
- Cookies  
- Certificate info  
- HTML body (max 1.2 MB)  
- Extracted JS (up to 3072 bytes per script)

## 3. Scoring System

Every URL starts with a baseline score of **100**.
Penalties reduce this score based on detected signals:

Examples:
- Scam word in subdomain
- Watchlist brand in domain
- High-entropy obfuscated path
- Dangerous JS in body
- Fresh DV certificate
- Insecure or tracking cookie
- Misconfigured headers

Scores vary based on where and how the signals are found:
- `applepie.com` is weighted differently than `secure-apple.com`

The app uses bit flags to track signal types across redirect chains.  
Combos are elevated:
- Scam subdomain + brand domain → critical flag
- Fresh DV cert + weak headers + malformed HTML → dangerous

## 4. Core Detection & Heuristics

Dependencies:

- [ASN1Decoder](https://github.com/filom/ASN1Decoder)
  - Used to decode and parse the TLS certificates 
- [PunycodeSwift](https://github.com/gumob/PunycodeSwift)
  - USed for converting internationalized domain name (IDNs) to their ASCII representation.

