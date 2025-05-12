> **This is a WIP.**  
> LegitURL works — and it's strict, by choice.  
> But a lot is still being added, tuned, or cleaned up.  
> It’s already useful, but not finished.

## LegitURL  
> Like a **nutrition label for links**  
> Scan a URL to see its 🟩 🟧 🟥 Legitimacy based on **technical behavior**, not reputation.  
> Because trust should be earned — not assumed.

- [1. Who is LegitURL for?](#1-who-is-legiturl-for)
- [2. How it works](#2-how-it-works)
- [3. Scoring system](#3-scoring-system)
- [4. Core detection & heuristics](#4-core-detection--heuristics)
- [5. Core detection features](#5-code-detection-features)
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
- Privacy-conscious users 
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

## 2. How it works

Users can paste, type, or scan a QR code to input a URL.  
With a single tap, they receive a **Legitimacy Score**, displayed as:  
🟩 Green, 🟧 Orange, or 🟥 Red.

The app analyzes each URL in **two phases**:

---

### 1. Offline inspection

LegitURL dissects the full URL structure — including domain, subdomains, path, query parameters, fragment and flags:

- Brand impersonation (e.g. secure-paypal-login.com)
- Scam keywords and look-alike tricks
- Encoded or nested URLs/UUIDs
- High-entropy or non-dictionnary tokens
- Suspicious punctuation or mixed‑script formatting

---

### 2. Online behavior analysis


A **single sandboxed HTTPS GET** is sent to the *core* URL  
(query parameters and fragments are removed).

Captured signals:

- **Response headers**
- **TLS certificate**
- **Cookies** (parsed & scored)
- **HTML body** – fully parsed; *UI display* capped at 1.2 MB
- **Inline scripts** – fully parsed; *UI display* capped at 3 KB per block

If the request triggers redirects, **every hop re‑enters phase 1**, enabling detection of:

- Tracking or affiliate chains
- Phishing “hop‑by‑hop” scams
- Security downgrades
- Silent server‑side rewrites (no `Location` header)

> No assumptions, no shortcuts — every step is verified on‑device with **zero user data leaked**.

---


### Bonus tools

- **Custom watchlists** for domains, keywords, or brands  
- A built‑in **glossary** of headers, TLS, and security terms

---

## 2.1 Valid input

Only URLs that use **HTTPS (`https://`)** are analysed, mirroring Apple’s `URLSession` policy.  
Schemes such as `ftp://`, `ssh://`, or `file://` are **not supported**.

If the scheme is omitted, LegitURL **assumes `https://`**.  
Plain‑HTTP (`http://`) links are considered unsafe and are **flagged without any network request**.

---

## 2.2 URL‑components analysis  

LegitURL inspects a link **locally, before any network traffic**.  
If a *critical* offline signal is found, the online phase is skipped.

The URL is split into five parts: **domain, subdomains, path, query, fragment** and each part is scanned for:

- Brand impersonation
- Scam patterns
- Obfuscation techniques
- Embedded tracking infrastructure

### Checks per component  

| Signal type | Examples |
|-------------|----------|
| **Brand impersonation** | `secure-paypal-login.com` |
| **Look‑alike tricks** | Mixed scripts (Cyrillic + Latin), homoglyphs |
| **Scam keywords** | `account‑verify`, `login‑secure`, etc. |
| **Encoded artefacts** | Hidden e‑mails, UUIDs, nested URLs |

**Weighting**

- **Domains & subdomains** carry the highest weight.  
- **Path & fragment** add behavioural context.  
- **Query values** are decoded *recursively* by a custom decoder.

---

### Technical details

- Domains are parsed with Apple’s **`URLComponents`** plus the **Mozilla Public Suffix List (PSL)**.  
- **IDNA (Punycode) normalisation** ensures internationalised domains resolve to ASCII for comparison.  
- Hyphens (`-`) and underscores (`_`) are optionally **tokenised** to expose embedded words.  
- **Mixed‑script detection** flags character‑set blends (e.g. Cyrillic + Latin).

**Brand‑spoofing & high‑entropy detection**

- **Levenshtein distance = 1** for typo‑based similarity.  
- **2‑gram similarity** as a fallback pattern match.  
- **iOS dictionary look‑ups** to confirm real‑word tokens.  
- **Shannon‑entropy fallback** catches random or machine‑generated strings.

**Path, query, and fragment analysis**

1. **Decode recursively** — Base64, percent‑encode, Unicode escapes, etc.  
2. **Scan for structures**  
   - Email addresses, IPs, UUIDs, nested URLs  
   - Scam phrases, obfuscated tokens  
3. Any decoded value that looks like a URL is **fed back into the full offline inspection** (max depth 5).

> **Note:** Only the first decoding branch that produces a *meaningful* token continues; high‑entropy leaves are pruned early to avoid depth bombs. 

## 2.3 Response analysis

After the offline pass, LegitURL fires **one sandboxed HTTPS GET** to the *core* URL  
(query and fragment were already stripped).

### What is captured

- **Status code** – maps 2xx/3xx/4xx/5xx into heuristic buckets  
- **Redirect target** – `Location` header *and* silent server‑side rewrites  
- **TLS certificate chain** – CN/SAN match, validity dates, issuer, age  
- **Response headers** – CSP, HSTS, Referrer‑Policy, leakage fields, etc.  
- **Cookies** – every `Set‑Cookie` parsed and flagged by the cookie engine  
- **Body & inline scripts** – script are fully tokenised (UI display capped)

### Probe constraints (privacy guarantees)

| Guardrail | Purpose |
|-----------|---------|
| **Ephemeral `URLSession`** | No cookies or local storage sent |
| **Default iOS User‑Agent, no extra headers** | Mimics a real browser while avoiding fingerprint noise |
| **Single connection, 10 s timeout** | Prevents long‑poll DoS; no session reuse |
| **No personal identifiers** | Nothing user‑specific leaves the device |

> Result: a reproducible “first‑impression” snapshot of the server’s behaviour, captured without leaking user data or following unbounded redirect chains.

---

### Technical Details

LegitURL makes one **sandboxed HTTPS GET** that mimics a first‑time visit:

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

#### Request parameters

- **HTTPS‑only** — query‑string & fragment removed  
- **10 s timeout** — protects against slow‑loris / hung hosts

#### Redirect handling

- **3xx codes captured, not auto‑followed**  
- **External vs internal hops** recorded for scoring  
- **Missing `Location` header** → flagged as a *silent rewrite*

#### Captured artefacts  →  analysis layer

| Artefact | Used for … |
|----------|------------|
| **Response headers** | CSP, HSTS, leakage, redirect classification |
| **TLS certificate** | CN / SAN match, age, issuer, chain completeness |
| **`Set‑Cookie` headers** | Cookie engine – size, entropy, SameSite, Secure |
| **HTML body** <br>*full parse&nbsp;· UI shows 1.2 MB* | Tag balance, script density, malformed markup |
| **Inline scripts** <br>*full parse&nbsp;· UI shows 3 KB* | JS risk patterns, nonce/hash extraction |

If a redirect is detected, the **destination URL re‑enters phase 1** and runs through the entire offline → online cycle again (depth‑ and timeout‑guarded).

### TLS certificate analysis

| Check | Why it matters |
|-------|----------------|
| **Site domain in SAN list** | Confirms the certificate actually covers the requested host. |
| **Validity window** | Flags *expired* certs and *over‑long* (> 13 months) or *ultra‑short* (< 7 days) DV lifetimes. |
| **Complete, trusted CA chain** | Detects missing intermediates or untrusted roots. |
| **Self‑signed leaf** | Outside dev/test, almost always signals risk. |
| **Freshness heuristic** | Newly issued DV certs (< 7 days) are common in throw‑away phishing infra. |
| **Flooded SAN list** | 25 + unrelated FQDNs without wildcards → pattern typical of large‑scale DV abuse. |

*Notes:*  
* EV/OV/DV **type is recorded but not penalised by itself**; DV only becomes a factor when combined with other weak signals (e.g., fresh issue + flooded SAN).  
* Wildcards (`*.example.com`) are **not** counted toward the “flooded” threshold; legitimate orgs often use a single wildcard for sub‑properties.  
* If URLSession’s strict validation fails, LegitURL treats the handshake failure as **critical**, regardless of the specific CA reason Apple reports.

---

### Cookie analysis

| Rule | Rationale |
|------|-----------|
| **Set on non‑200 response → suspect** | Legit sites rarely set state before final content is served. |
| **Attribute audit** | Each `Set‑Cookie` is parsed for:<br>• size & Shannon entropy<br>• `Secure`, `HttpOnly`, `SameSite` flags |
| **SameSite≠assumed** | LegitURL **does not default missing `SameSite` to `Lax`**:<br>1. iOS API can’t tell if it was omitted.<br>2. Security should be explicit, not browser‑inferred. |
| **Redirect‑phase cookies** | Cookies issued during any `3xx` hop incur a higher penalty than those on the final `200`. |

*Implementation notes*  
* Duplicate cookies encountered later in the redirect chain are **recorded but not penalised again** (prevents score inflation).  

---

### HTML body analysis

*Triggered only when the server returns **200 OK** with `Content‑Type: text/html`.*

| Check | Purpose |
|-------|---------|
| **Document skeleton** – `<html>`, `<head>`, `<body>` present | Flags broken or deliberately obfuscated markup |
| **Malformed `<script>` tags** | Detects truncated / malformed scripts |
| **Script‑to‑content ratio** | High JS density often correlates with cloaking or ad‑tech |
| **Inline + external script density** (per 1 kB) | Normalises page size differences |
| **Suspicious JS patterns** | • *Setters*: `eval`, `Function`, `atob`<br>• *Accessors*: `document.cookie`, `sessionStorage`, `WebAssembly`<br>• *Risky pairings*: `getElementById` + `.submit()` etc. |

Additional data captured for cross‑checks:

| Stored for… | Used in… |
|-------------|---------|
| **Inline script `nonce` values** | CSP nonce‑matching |
| **External script URLs** | CSP `script‑src` origin matching |
| **`integrity="sha…"` hashes** | SRI presence (shown; not yet verified) |
| **Extracted SHA‑256 of inline blocks** | Future SRI self‑check roadmap |

> **Note** – SRI hashes and script SHA‑256 values are **displayed to the user** but *not* cryptographically verified yet; asynchronous hashing is on the roadmap.

All body parsing runs on‑device; only the first **1.2 MB** of HTML and **3 KB** per inline script are rendered in the UI, but the full content is tokenised for heuristics.

---

### Header analysis

#### Content‑Security‑Policy (CSP)

| Rule | Impact |
|------|--------|
| **CSP header missing** | Heavy penalty, no client‑side code guard in place |
| Must include **`script-src`, `default-src`, or `require-trusted-types-for`** | Without one of these, script execution is effectively unrestricted |
| **`unsafe-eval`** present | High‑risk: enables runtime code generation |
| **`unsafe-inline`** present *and* no `'strict-dynamic'` + nonce/hash | High‑risk: allows arbitrary inline scripts |
| **Nonce mismatch** between header and inline `<script>` | Indicates policy is ineffective or stale |
| **Unused / unrelated `script-src` origins** | Signals overly broad allow‑list; flagged as weak hygiene |

*Implementation notes*

* Only the values of **`script-src`** and **`default-src`** are scored today.  
  All other directives are still parsed so future rules won’t miss them.  
* If `'strict-dynamic'` is present **and** every inline block carries a valid nonce/hash, the penalty for `'unsafe-inline'` is *downgraded* (legacy‑browser shim).

---

#### Other security headers checked

| Header | What LegitURL looks for |
|--------|-------------------------|
| **`Strict-Transport-Security`** | Presence, `max-age` ≥ 1 year, `includeSubDomains` |
| **`Content-Type`** | Correct MIME for returned body |
| **`X-Content-Type-Options`** | Must be `nosniff` |
| **`Referrer-Policy`** | At least `strict-origin` or stricter |
| **`Server`, `X-Powered-By`, …** | Excessive stack leakage results in minor penalty |

Headers are evaluated only on **200 OK** responses; redirects are assessed separately in the redirect‑handling logic.

## 2.4 Output

### Traffic‑light verdict

| Colour | Meaning | When to worry |
|--------|---------|---------------|
| 🟥 **Red – Unsafe** | Multiple critical findings (weak TLS, missing CSP, scam keywords, etc.). | Treat as hostile unless you fully trust the sender. |
| 🟧 **Orange – Suspicious** | Mixed signals: decent setup but notable hygiene gaps (e.g., tracking cookies on redirects, `unsafe-inline`). | Acceptable for known brands; be cautious with unknown sites. |
| 🟩 **Green – Safe** | Strong security posture: clean redirects, correct headers, trusted cert. | Still not bullet‑proof, but shows clear effort to protect users. |

*Red does **not** always equal confirmed phishing; it means the site relies on browser leniency or omits basic protections.*

---

### Detailed breakdown (advanced view)

| Data pane | What you get |
|-----------|--------------|
| **URL components** | Parsed domain, subdomain, path, query, fragment |
| **Findings & logs** | Full list of heuristics and penalties |
| **HTTP headers** | Raw + annotated view |
| **CSP policy** | Directive table |
| **Cookies** | Flag level, attributes, entropy |
| **Certificate** | CN/SAN list, issuer, validity, chain notes |
| **HTML body** | First 1.2 MB |
| **Inline JS** | First 3 KB per block, risk highlights, can be copy |

## 3. Scoring system

Each **redirect chain** starts at **100 points**.  
Penalties are applied per URL *and* for patterns that emerge across hops  

### Individual penalty examples

| Signal | Typical hit |
|--------|-------------|
| Scam keyword in subdomain | −20 |
| Watch‑list brand misuse in subdomain | −25 |
| High‑entropy / obfuscated path | −10 |
| Dangerous JavaScript pattern | -30 |
| Fresh DV certificate (< 7 d) | −10 |
| Tracking cookie on 3xx | −15 |
| CSP missing or no `script-src`, `defautl-src` or `require-trusted-type` | −50 |

*Weights are versioned and will evolve.*

#### Context matters

| Same signal, different context | Result |
|--------------------------------|--------|
| `applepie.com` vs `secure-apple.com` | Only the second triggers **brand‑spoof** penalty. |
| Cookie on **200 OK** | Mild warning. |
| Same cookie set on **302 redirect** | Higher penalty (tracking during redirect). |

---

### Bit‑flag engine

LegitURL tags every finding with a **bit flag** (`DOMAIN_SCAM_OR_PHISHING`, `TLS_IS_FRESH`, `HEADERS_CSP_MALFORMED`, …).  
Combinations drop the score faster than individual hits—catching situations where separate “yellow” signals combine into a clear red flag.

| Example combo | Flags raised | Resulting severity |
|---------------|-------------|--------------------|
| Scam keyword in subdomain **+** watch‑list brand in domain | `SCAM_WORD`&nbsp;∧&nbsp;`BRAND_HIJACK` | **Critical** |
| Fresh DV cert **+** weak headers **+** malformed HTML | `FRESH_DV` ∧ `WEAK_HDR` ∧ `HTML_MALFORM` | **Dangerous** |
| Hop 1: `[ScamWord]` → Hop 2: `[Brand + DV]` | Chain flags propagate; overall score marked | **Critical** |

> **Why bit flags?** They give deterministic, explainable downgrades and allow new heuristics to slot in without rewriting the whole weight table.

## 4. Core detection & heuristics

### Heuristic system

LegitURL relies on **deterministic rules**, not black‑/allow‑lists or ML models.  
Signals are grouped into five layers:

| Layer | What is examined |
|-------|------------------|
| **1. URL structure** | Domain, subdomain, path, query, fragment |
| **2. TLS certificate** | CN/SAN, chain validity, age, issuer |
| **3. HTTP headers** | CSP, HSTS, leakage, referrer, MIME |
| **4. Cookies** | Size, entropy, attributes, redirect phase |
| **5. HTML & JS body** | Tag structure, script density, risky API use |

Each finding maps to **(a) a point penalty** and, if relevant, **(b) a bit flag**.  
Flags accumulate per URL *and* across the redirect chain, catching compound risks.

#### Context‑aware scoring

| Scenario | Weighting difference |
|----------|---------------------|
| Tracking cookie on **3xx** vs **200** | Higher penalty on 3xx (redirect tracking). |
| Scam‑style subdomain on unrelated domain vs. brand domain | Heavier hit if host contains a known brand. |

### INFO‑only signals

Some findings are logged for context but **do not deduct points** unless combined with other flags.

| INFO signal | Why it’s informative |
|-------------|----------------------|
| Certificate type (DV / OV / EV) | Neutral alone; useful in combos (e.g., *fresh DV + weak headers*). |
| Internal redirect to sibling subdomain | Benign on its own; may pair with cookie issues. |
| Tiny cookies (< 10 B, low entropy) | Often harmless session IDs. |

INFO entries are **hidden by default** in the warning panel; users can expand to view them when needed.

---

## 5. Core detection features

LegitURL is built almost entirely on **Swift Foundation**.  
Only two third‑party libraries are used:

| Dependency | Purpose |
|------------|---------|
| **[ASN1Decoder](https://github.com/filom/ASN1Decoder)** | Decodes X.509 certificates (CN, SAN, issuer, extensions). |
| **[PunycodeSwift](https://github.com/gumob/PunycodeSwift)** | Converts IDNs to ASCII (ACE) for uniform comparisons. |

---

### Internal reference lists

| Dataset | Stored as | Used for | User‑editable |
|---------|-----------|----------|---------------|
| **Mozilla Public Suffix List** | SQLite (raw TLD, punycode TLD) | Domain parsing & mixed‑script checks | — |
| **Known brands & legit domains** | JSON | Brand‑spoof detection | ✅ |
| **Scam / phishing keywords** | JSON | Subdomain & path heuristics | ✅ |
| **Suspicious JS APIs** | Swift array | Inline‑script risk scan | — |

---

### Matching & scanning strategy

* **String matches** — plain `.contains` for speed.  
* **Byte‑level scans** — custom forward scanner that skips whitespace and `\n`; used to pluck tags and JS tokens without full AST.  
* Both approaches prioritise **O(n)** passes to keep on‑device analysis fast.

> **Note** – Reference lists load at startup and can be updated in‑app without shipping a new binary.

---

### Typo detection

| Stage | Algorithm |
|-------|-----------|
| **Primary** | **Levenshtein distance = 1** (single insertion / deletion / swap). |
| **Fallback** | **2‑gram similarity** when Levenshtein fails but string length is ≥ 4. |

This two‑step avoids expensive distance calculations on obviously different strings while still catching more subtle swaps.

---

### Lamai – recursive decoder

Lamai unpacks encoded values found in **path / query / fragment strings**.

#### Decode pipeline

1. **Base64** (auto‑pad when `len % 4 ≠ 0`).  
2. **URL / percent / Unicode escapes**.  
3. Follow each successful decode as a new branch (max depth 5).  
4. At each node, run heuristic checks:  
   * Scam keywords & brand spoof  
   * UUID, IP, e‑mail, nested URL patterns  
   * Structural JSON or query blobs  
5. If a branch yields no match and depth limit nears, evaluate **Shannon entropy** to decide whether to keep exploring.

> **Entropy is last‑resort** – high entropy alone doesn’t prove encoding; early pruning avoids chasing random blobs.

Branches that reveal a valid URL are fed back into the **offline inspection** pipeline, ensuring nested phishing links are scored just like top‑level targets.

---

### HTML & script analysis (byte‑level)

1. **Boundary scan**  
   *First ± 500 bytes* of body are checked:  
   
   | Condition | Action | Penalty |  
   |-----------|--------|---------|  
   | `<html>` tag missing | Mark as non‑HTML; skip deeper parsing | **Critical** |  
   | `</html>` tag missing | Fallback end = body length | **Moderate** |  

2. **Tag discovery** – scan every `<` byte  

   | Byte + look‑ahead | Meaning |
   |-------------------|---------|
   | `<` `/` … | Closing tags `</head>`, `</body>`, `</script>` |
   | `<head>` / `<body>` / `<script>` | Opening tags |

3. **Head checks**  
   *Inside `<head>`* search for `<meta http-equiv="Content-Security-Policy">`.

4. **Script block processing**  
   *Inside each `<script>`* (first **3 KB**):  
   
   | Extracted | Purpose |
   |-----------|---------|
   | `nonce=` value | CSP nonce‑match |
   | `integrity=` (SRI) | Presence logged (hash not yet verified) |

5. **Script origin classification**  
   *For `<script src="…">`* determine origin: `'self'`, external URL, protocol‑relative, `data:` URI, etc.

6. **JavaScript‑soup scan**  
   *Inline scripts are concatenated, then scanned byte‑wise:*  
   
   - Locate every `(` and `.` byte.  
   - Look back 1–3 bytes to spot common accessors / functions.  
   - Skip junk via lightweight filters (whitespace, digits).

7. **Risk pattern matching**  
   Inline tokens are compared to the **risky‑JS list** (`eval`, `atob`, `btoa`, `document.write`, …).  
   Logic also flags **pairings**, e.g.:  


   | Sequence | Flag |  
   |----------|------|  
   | `document.getElementById` → `.submit()` | Suspicious form auto‑submit |  
   | `atob()` → `JSON.parse()` | Decoded blob executed |


All parsing runs on‑device; although only the first **1.2 MB** of HTML and **3 KB** per inline block are shown in the UI, the *entire* body is tokenised for heuristics.

---

### Cookie scoring engine (byte + flag)

LegitURL receives cookies flattened by **`URLSession`**.  
Each `HTTPCookie` is distilled into a **bit‑flag bundle**:

| Flag            | Condition |
|-----------------|-----------|
| `httpOnly`      | `HttpOnly` present |
| `secure`        | `Secure` present |
| `persistent`    | Expires > 30 days |
| `smallValue` / `largeValue` | < 16 B / > 64 B |
| `highEntropyValue` | Shannon > 3.5 bits/char |
| `setOnRedirect` | Cookie issued on 3xx/4xx/5xx |
| `sameSiteNone`  | `SameSite=None` |
| `sameSiteMissing` | Attribute absent **(not defaulted to `Lax`)** |

> **Why `SameSite` missing as a weakness**  
> iOS **URLSession** flattens duplicate _Set‑Cookie_ headers into one field.  
> Modern browsers (Chrome ≥ 80, Safari ≥ 14, Firefox ≥ 96) *assume* `SameSite=Lax` if the attribute is missing. LegitURL does **not** mirror that assumption because:  
> 1. Mobile tracking kits still rely on no‑`SameSite` to enable cross‑site POST redirects.  
> 2. Security should be explicit; silent defaults hide developer intent.  
> 3. The flattening makes reliable detection harder — erring on caution is safer.  


Flag → penalty mapping

| Flags raised | Outcome |
|--------------|---------|
| `smallValue ` & low entropy | **Ignored** – likely benign session ID |
| `httpOnly` only | **Capped** – CSRF risk but common |
| `largeValue ` + `highEntropyValue ` | **Tracking** – probable blob |
| Any flag on a **3xx** hop | Penalty adds a moderate penalty – redirect tracking |

> LegitURL simulates a clean, first‑visit GET: no query params, no existing cookies.  
> That means *any* cookie set before consent (RGPD banners) is visible.  
> Balancing hygiene vs. legal grey‑zones is ongoing; weights may evolve.

---

### TLS certificate analysis

LegitURL decodes the raw X.509 and layers its own heuristics **on top of `URLSession`’s system trust**.

| Check | What we look for | Why it matters |
|-------|-----------------|----------------|
| **Chain validity** | All intermediates present in the handshake. | Sites that rely on the browser’s cached intermediates signal **lazy or incomplete TLS**. |
| **Issue / expiry dates** | *New* < 7 days, *Long* > 13 months. | Fresh DV certs & very long lifetimes often correlate with disposable infra. |
| **CA type** (DV / OV / EV) | Parsed from policy OID. | Informational flag; used in combos (e.g., *fresh DV + weak headers*). Bonus for EV or OV |
| **SAN list** | • Wildcard vs. many FQDNs<br>• Coverage of target host. | 25 + unrelated SANs without wildcards ⇒ common pattern in large‑scale DV abuse. |

> **Why not bypass `URLSession`?**  
> A fully custom verifier could read handshake errors in detail, but shipping that risks **App Store rejection**. LegitURL therefore accepts system trust and scores on top of it.

#### System‑trust limitations

Apple’s secure‑TLS layer does **not** expose whether a failure is due to:

* Missing leaf cert  
* Incomplete chain  
* Untrusted root

LegitURL only knows the handshake failed; such failures are treated as **critical** regardless of root cause.

---

### SAN‑pattern analysis – spotting cloaked infrastructure

LegitURL examines the **Subject Alternative Name (SAN)** list for signals that a certificate is protecting more than just a normal “set of sub‑sites.”

#### Red‑flag pattern

> **Many (10 – 100) unrelated FQDNs**, no wildcard entries, and a certificate age < 30 days — especially when the issuer is Let’s Encrypt — strongly suggests throw‑away scam infra.

| Why this pattern is rare on legitimate sites |
|----------------------------------------------|
| **Wildcards are cheaper to maintain** — orgs usually issue `*.example.com` and call it a day. |
| **Let’s Encrypt wildcards require DNS‑01** — attackers prefer HTTP‑01 because they don’t own DNS. |
| **Dozens of disparate FQDNs** make no operational sense for normal businesses but are perfect for phishing kits, redirect chains, and disposable botnet mailers. |

A SAN list packed with unrelated domains is therefore scored as **“Cloaked Infra”**.  
When combined with weak headers, shady TLDs (`.biz`, `.click`), or obfuscated JavaScript, the overall risk escalates quickly.

#### Counter‑example: Steam

* `steampowered.com` → 48 SAN entries, Let’s Encrypt DV, no wildcard.  
* Immediate redirect to `store.steampowered.com` → EV cert, only 2 SANs.

Because the chain lands on a **stronger, scoped EV certificate**, LegitURL waives the penalty for the first hop — context overrules the raw SAN count.

---

### HTTP header analysis

LegitURL inspects headers **only on `200 OK`**, so the findings reflect the page that is actually rendered.

#### Content‑Security‑Policy (CSP)

| Step | Test | Action |
|------|------|--------|
| **Presence** | `Content‑Security‑Policy` header missing | **Heavy penalty** |
| | Only `…Report‑Only` present | Analyse but apply smaller penalty |
| **Parsing** | Header must end in `;` | Append if missing |
| | Split into directives by `;` | Build directive map |
| **Mandatory directive** | No `script-src` → fall back to `default-src` → if both missing, check `require-trusted-types-for 'script'` | If none found → treat as **incomplete CSP** (same penalty as missing) |
| **Bit‑flags** | Map directive/value combos to flags (`UNSAFE_INLINE`, `UNSAFE_EVAL`, `STRICT_DYNAMIC`, etc.) | Feed flags into scorer |
| **Nonce / origin match** | Compare inline‑script nonces + external script origins to `script-src` allow‑list | Mismatch → penalty |

> A strict CSP can’t stop every attack, but it **shrinks the client‑side attack surface** that modern threats exploit.

---

#### Other security headers

| Header | What we check | Expectation / Penalty |
|--------|---------------|-----------------------|
| `Strict-Transport-Security` | Presence + `max-age` | ≥ 31536000 s and `includeSubDomains` |
| `X-Content-Type-Options` | Value | Must be `nosniff` |
| `Referrer-Policy` | Value | `strict-origin` or stricter |
| `Server` / `X-Powered-By` | Version leakage (`apache/2.4`, `php/8.2`) | **INFO** if header present but no version,<br>**Suspicious** if version string leaks |

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

### Example 4: Popular sites that score poorly when judged blind

These sites are globally recognized — but when analyzed blindly, as if they were unknown, their setups fall short.

| Site               | **Score** | Key issues |
|--------------------|---------:|------------|
| www.google.com     | **29/100** | CSP is *report‑only* (`unsafe-eval`); sets tracking cookies |
| m.youtube.com      | **44/100** | 92 % of HTML is JS; tracking cookies; missing `</body>`; no `Referrer-Policy` |
| facebook.com       | **6/100** | 96 % JS; three large cookies modified by JS; `unsafe-eval` present |
| amazon.com         | **15/100** | Inline `document.write()`; CSP header missing |

> These aren’t scams — but if we didn’t already trust them, **nothing in their technical behavior would give trust signal.**  
> This shows hygiene gaps, not proven scams.

### Example 5: Popular sites that score good

Some high-profile sites make a visible effort to secure users — and it shows.

| Site                                | Score   | Notes |
|-------------------------------------|---------|-------|
| stripe.com                        | **99/100**  | Strong CSP, secure headers, minimal leakage — but one cookie is JS-accessible |
| immatriculation.ants.gouv.fr    | **96/100**  | Strong CSP; secure headers, heavy page (3MB); CSP allows 5 script sources, but only 1 is used |
| apple.com                         | **60/100**  | CSP includes `unsafe-inline` and `unsafe-eval`; weak `Referrer-Policy` |

> Stripe clearly wants to appear trustworthy — and backs it up with real protections.  
> The French government site is solid.  
> CSP still allows unsafe-inline/unsafe-eval; referrer policy is lax.


## 7. Why LegitURL exists

Web browsers were designed to be forgiving.  
For decades that resilience, auto‑closing tags, guessing encodings, running scripts despite weak policies—helped the Web grow. Today the same leniency often masks structural problems instead of surfacing them.

Browsers now play the role of **just‑in‑time compiler and debugger**: silently fixing malformed HTML, defaulting security headers, and tolerating unsafe client‑side code. As a result, many production sites operate with minimal security hygiene yet still “work,” so the underlying weaknesses remain invisible to users.

Around 2020 major engines started tightening defaults—e.g., treating missing `SameSite` as `Lax`, encouraging Content‑Security‑Policy—not to break sites, but to reduce attack surface. Even so, a modern page can set tracking cookies during redirects, embed third‑party scripts, or rely on permissive CSP directives and still render without warning.

**LegitURL’s goal is visibility, not punishment.**  
By evaluating a link’s behaviour without reputation bias, it shows where a site relies on browser forgiveness and where it follows best practices. The web is vast; trusted brands and unknown domains alike can fall short. LegitURL gives users and developers a concise, transparent view of those gaps—so they can decide whether “it works” is good enough.  


## 9. Contact & License

LegitURL is released under the **GNU AGPLv3 license**.

You’re free to use, study, and improve the code — even in commercial projects —  
**but any derivative work, especially one used over a network (e.g. as a web service),  
must also be made public under the same license.**

This protects users and ensures the project remains open and honest.

> See [LICENSE](LICENSE) for full terms.

