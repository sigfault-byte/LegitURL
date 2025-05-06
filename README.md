## LegitURL
> A privacy-focused iOS app to assess URL legitimacy through strict heuristics and clear analysis

> If you want users to trust you, you need to demonstrate a commitment to security and quality in your web development practices.

LegitURL is an iOS app designed to analyze URLs and help users — both non-technical and technical — assess the legitimacy of a web link.

Its goal is to apply strict heuristics to compute a *Legitimacy Score* based on the information and patterns it can detect, by blindly analysing various signals.

## 1. Who is LegitURL for?

The app’s primary audience is non-technical users. Its main purpose is to help them quickly determine whether a link is suspicious.

The original idea behind the app was simply to follow a link to its final destination and reveal it, showing users exactly where the link would take them.

However, during development, it became clear that achieving this properly required deeper technical analysis. As a result, LegitURL now also offers features that technical users may appreciate: it clearly displays URL components, HTTP headers, TLS certificates, cookies, and extracted scripts from the HTML body after performing a single, minimal HTTP request to the server, without exposing any user-identifying information.

## 2. How Does It Work

Users paste a link, press a button, and receive a safety score assessment, displayed using three possible colors: green, orange, or red.

The app analyzes a URL in two phases:

1. It first checks the URL components offline.
2. Then, it performs a minimal HTTP GET request to the core URL (without query parameters) to inspect the response headers, TLS certificate, cookies, and HTML body.

Additionally, users can populate their own watchlists of domains, brands, or keywords they wish to monitor.

The app also includes a built-in glossary of various web and security-related terms to help users better understand the analysis results.

## 2.1 Input

Only secure (https) links are analyzed, in accordance with Apple’s URLSession guidelines. If no scheme is specified, `http://` is automatically prefixed.

Non-secure (http) links are considered unsafe by default and are flagged without further analysis.

## 2.2 URL Components Analysis

The URL is first broken down using Apple’s `URLComponents` and Mozilla’s Public Suffix List (PSL) to correctly identify the domain, subdomains, and top-level domain (TLD).

Checks include:
- Underscores (`_`) in subdomains are removed.

- Hyphens (`-`) in domains or subdomains are used to split parts for deeper analysis.

- The domain is converted to IDNA (Internationalized Domain Name in Applications).

- Brand impersonation attempts are detected using both default and user-provided brand lists.

- Script composition is analyzed:
  - Mixed Latin, Cyrillic, or Greek is flagged as suspicious.
  - Entire non-ASCII domains are checked against TLD consistency.
- Scam words, phishing keywords, and brand lookalikes are detected using:
  - Levenshtein distance
  - 2-gram similarity
  - The iOS dictionary (with entropy fallback)

The path is split on `/` and analyzed using the same logic.

Findings in query and fragment components are treated as lower-signal than those in domains or subdomains.

If the query and fragment are well-formed (i.e., no unusual `?#` or `#?` patterns):
- They are parsed into key-value arrays.
- If the fragment resembles a query string, the same logic is applied.
- Otherwise, the fragment is analyzed like a path, with additional checks:
  - UUIDs
  - Nested URLs
  - Emails
  - Redirect patterns
  - Suspicious JavaScript markers

Query keys and values are sent into a custom recursive decoder called **Lamai**, which attempts Base64, Unicode, URL encoding, and percent decoding.

Lamai evaluates each decoding branch up to depth 5 and analyzes leaf nodes for:
- Email addresses
- IPs
- URLs
- UUIDs
- Scam terms
- Entropy fallback if no result

Discovered URLs (from decoding or raw content) are recursively analyzed.

## 2.3 Response Analysis

The app performs a GET request to the core URL. Timeout is set to 10 seconds.

It does not follow redirects, but captures:
- Headers
- HTML body
- TLS certificate

Redirect status codes (3xx) are inspected to see whether:
- The domain changes (external redirect)
- The path changes (internal redirect)

### TLS Certificate Analysis

Checks include:
- Domain listed in SAN
- Certificate validity (not expired)
- Chain validity
- Self-signed detection
- Certificate freshness (too short or too long)
- Flooded SAN list detection (especially for DV certs)

### Cookie Analysis

If response ≠ 200, cookies are considered suspicious.

Cookie attributes analyzed:
- Value size
- Value entropy
- `SameSite`, `HttpOnly`, `Secure`
- Exportability / reusability across chains

Cookies are flagged as:
- Tracking
- Suspicious
- Dangerous

Previously seen cookies across redirects are not penalized again but tracked. Cookies set on 3xx responses are penalized more heavily.

### HTML Body Analysis

Triggered only if response is 200 and content-type is `text/html`.

Checks include:
- Valid HTML structure (`<html>`, `<head>`, `<body>`)
- Malformed `<script>` tags
- Ratio of script size to HTML content
- Density of script content (inline and external)
- Suspicious JS patterns:
  - Setter functions: `eval()`, `atob()`, etc.
  - Accessors: `document.cookie`, `sessionStorage`, `WebAssembly`
  - Suspicious pairings (e.g., `getElementById()` near `.submit()`)

Nonce values and external script URLs are stored for CSP comparison.
SRI and inline hash validation not yet implemented.

### Header Analysis

Checks include:

- Presence of `Content-Security-Policy` (CSP)
  - Missing CSP is heavily penalized
  - Requires at least one of: `script-src`, `default-src`, or `require-trusted-types-for`
  - Penalizes `unsafe-eval` always, `unsafe-inline` conditionally
  - Only `script-src` and `default-src` values currently penalized
  - Compares CSP nonce with detected inline script nonces (mismatch flagged, no penalty yet)
  - Flags unused CSP URLs or external script mismatches

- HSTS (`Strict-Transport-Security`) presence and duration
- Content-Type declaration
- `X-Content-Type-Options: nosniff`
- Referrer policy
- Header leakage (e.g., `Server`, `X-Powered-By`)

## 2.4 Output

The app outputs a safety rating:

- 🟥 Red = Dangerous

- 🟧 Orange = Suspicious

- 🟩 Green = Safe


Advanced users can view detailed breakdowns:

- URL Components
- Full HTTP headers
- CSP policy
- Cookies 
- Certificate info
- HTML body (max 1.2MB)
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

