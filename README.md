# LegitURL

> **A nutrition label for links** — on-device scanner that scores any URL in ≈2 s using 100 + deterministic heuristics.

[![Release](https://img.shields.io/badge/release-1.1.6-blue.svg)](#)
[![iOS](https://img.shields.io/badge/iOS-18%2B-brightgreen.svg)](#)
[![App Store](https://img.shields.io/badge/download-App%20Store-blue)](https://apps.apple.com/fr/app/legiturl/id6745583794)
[![License](https://img.shields.io/badge/license-AGPL--v3-green)](LICENSE)

<div align="center">
  <img src="AppPreview/LegitURL_demo.gif" width="500" alt="Quick 8-second demo: paste link → score → examples"/>
</div>

---

## Why you might care

* **Instant verdict** - assigns 🟩/🟧/🟥 locally in ≈2 s, no cloud calls.  
* **App-sec focus** - flags silent redirects, CSP issues, shady certs, and tracking cookies.  
* **Explainable heuristics** - every finding follows a traceable rule, no black-box logic.  
* **Privacy by design** - single HTTPS fetch to the target, zero third-party traffic.

---

## Score legend

| Score | Meaning |
|-------|---------|
| 🟥 **Red — Unsafe** | Multiple high-risk signals (weak TLS, missing CSP, scam keywords …). |
| 🟧 **Orange — Suspicious** | Mixed hygiene; often fine for major brands, caution for unknown sites. |
| 🟩 **Green — Safe** | Clean redirects, solid headers, trusted cert, no heavy tracking. |

---

## Quick start

| | |
|---|---|
| **End-users** | [App Store](https://apps.apple.com/fr/app/legiturl/id6745583794) |
| **Developers** | Open `LegitURL.xcodeproj` in Xcode and run. |

---

## Screenshots

| | |
|---|---|
| **Signals & Logs** | <img src="AppPreview/signals_details.PNG" alt="Signals and logs view showing coloured findings" width="400"> |
| **Inline script findings** | <img src="AppPreview/script_details.PNG" alt="Inline script detail with extracted snippet of risky functions" width="400"> |

<details>
<summary>More screenshots</summary>

| | |
|---|---|
| **Cookie view** | <img src="AppPreview/cookies_details.PNG" alt="Cookie detail with bit-flag severity pyramid" width="45%"> |
| **CSP directives** | <img src="AppPreview/csp_details.PNG" alt="Content-Security-Policy directive list" width="45%"> |
| **HTML report export** | <img src="AppPreview/html_report.PNG" alt="Preview of generated HTML security report" width="45%"> |
| **LLM JSON export** | <img src="AppPreview/LLM_json_export.PNG" alt="Screen showing compact JSON export for LLMs" width="45%"> |

</details>

---

## How does it work

1. **Offline parsing** – look-alikes, encodings, scam words, entropy tests.  
2. **Sandboxed HTTPS fetch** – reads cert, headers, cookies, HTML, inline JS.  
3. **Deterministic scoring** – bit-flags + weighted penalties → single score.

Full spec and details examples lives in [`TECHNICAL_OVERVIEW.md`](TECHNICAL_OVERVIEW.md).

---

## Roadmap

### Completed
- [x] Cookie bit-flag pyramid
- [x] CSP / header correlation

### In progress
- [ ] Correlate CSP SHA to inline  
- [ ] HTML `<meta refresh>` detection  
- [ ] Subresource-Integrity (SRI) hash checks  
- [ ] Consolidated CSP generator
- [ ] Implement OpenSSL probe to retrieve certificate chain and reason for failed TLS handshake

## License

GNU  Affero GPL v3 – see [`LICENSE`](LICENSE) for details. Issues welcome.
