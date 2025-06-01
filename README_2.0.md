# LegitURL

> **A nutrition label for links** — on-device scanner that scores any URL in ≈2 s using 100 + deterministic heuristics.

[![Release](https://img.shields.io/badge/release-1.1.0-blue.svg)](#)
[![iOS](https://img.shields.io/badge/iOS-18%2B-brightgreen.svg)](#)
[![App Store](https://img.shields.io/badge/download-App%20Store-blue)](https://apps.apple.com/fr/app/legiturl/id6745583794)
[![License](https://img.shields.io/badge/license-AGPL--v3-green)](#)

<div align="center">
  <img src="AppPreview/LegitURL_demo.gif" height="650" alt="LegitURL demo"/>
</div>

---

## Why you might care

* **Instant verdict** - assigns 🟩/🟧/🟥 locally in ≈2 s, no cloud calls.  
* **App-sec focus** - flags silent redirects, CSP issues, shady certs, and tracking cookies.  
* **Explainable heuristics** - every finding follows a traceable rule, no black-box logic.  
* **Privacy by design** - single HTTPS fetch to the target, zero third-party traffic.

---

## Quick start

| | |
|---|---|
| **End-users** | [App Store](https://apps.apple.com/fr/app/legiturl/id6745583794) |
| **Developers** | Open `LegitURL.xcodeproj` in Xcode and click to run. |

---

## Score legend

| Score | Meaning |
|-------|---------|
| 🟥 **Red — Unsafe** | Multiple high-risk signals (weak TLS, missing CSP, scam keywords …). |
| 🟧 **Orange — Suspicious** | Mixed hygiene; often fine for major brands, caution for unknown sites. |
| 🟩 **Green — Safe** | Clean redirects, solid headers, trusted cert, no obvious tracking. |

---

## Feature tour

<details>
<summary>Click for screenshots</summary>

| | |
|---|---|
| Home → Analysis | ![](AppPreview/2_home-analysis-view.png) |
| Logs → URL detail | ![](AppPreview/3_logs-view.png) |
| Cookies · CSP | ![](AppPreview/5_cookie-detail-view.png) |
| TLS · Scripts | ![](AppPreview/7_tls-details-view.png) |
| Glossary | ![](AppPreview/9_glossary-view.png) |

</details>

---

## Under the hood

1. **Offline parsing** – look-alikes, encodings, scam words, entropy tests.  
2. **Sandboxed HTTPS fetch** – reads cert, headers, cookies, HTML, inline JS.  
3. **Deterministic scoring** – bit-flags + weighted penalties → single score.

Full spec lives in [`TECHNICAL_OVERVIEW.md`](TECHNICAL_OVERVIEW.md).

---

## License

GNU  Affero GPL v3 – see [`LICENSE`](LICENSE) for details. Issues welcome.
