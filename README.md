# LegitURL

> **A security nutrition label for links** — a fully on-device URL scanner that performs over 100 deterministic checks in ≈2 seconds.

[![Release](https://img.shields.io/badge/release-1.1.6-blue.svg)](#)
[![iOS](https://img.shields.io/badge/iOS-18%2B-brightgreen.svg)](#)
[![App Store](https://img.shields.io/badge/download-App%20Store-blue)](https://apps.apple.com/fr/app/legiturl/id6745583794)
[![License](https://img.shields.io/badge/license-AGPL--v3-green)](LICENSE)

<div align="center">
  <img src="AppPreview/LegitURL_demo.gif" width="500" alt="Quick 8-second demo: paste link → score → security findings"/>
</div>

---

# Overview

**LegitURL** is a lightweight mobile app that analyzes the trustworthiness of any URL using a transparent, heuristic-driven approach. All scans are conducted locally and completed in ~2 seconds. No cloud analysis, no data leaks. just fast, explainable results.

See the [examples](https://github.com/sigfault-byte/LegitURL/blob/main/Examples/README.md) for sanitized case studies of real-world phishing links, complete with PDF exports, structured JSON, and LLM reasoning outputs.

### Key features:
- **Instant risk scoring** – assigns 🟩/🟧/🟥 based on 100+ deterministic checks  
- **Security-focused** – detects silent redirects, CSP misconfigurations, suspicious TLS certificates, and tracking behavior  
- **Explainable results** – every finding is traceable to a rule; no black-box logic  
- **Privacy-first design** – a single HTTPS request, no third-party traffic, zero analytics  
- **Exportable reports** – generate PDFs or LLM-ready JSON for external review  

---

## Media Coverage

### *Cyberdefense Magazine* (July 2025)
> **"LegitURL offers a unique approach to link analysis — blending pedagogy and precision in a tool designed for everyone."**

<details><summary>Excerpt from the article</summary>

> [...]  
> But **encryption** is not **authentication**.  
> Rendering is not endorsement.  
> Even seemingly benign links can conceal redirect chains, cloaked infrastructure, or misconfigured policies — all while wearing the lock like a badge.  
> I often tell non-technical users to imagine a website as a shop, and their browser as a **guide** or **bodyguard**.  
> That guide will help them get inside, translate unknown languages, and smooth over bumps in the experience.  
> But how many of us would willingly enter a **shop** with **crumbling walls, broken stairs, sticky notes slapped on our chest**, and **strangers watching our every move**, while the bodyguard just smiles and quietly patches the walls?  
> [...]  

</details>

> [Read the full article](https://www.cyberdefensemagazine.com/newsletters/july-2025/mobile/) page 258.

---

### *ZATAZ Cybersecurity News*

**LegitURL was also featured on [ZATAZ](https://www.zataz.com/legiturl-lapp-qui-note-vos-liens-en-2-secondes/)**, in an article by [Damien Bancal](https://damienbancal.fr), highlighting the tool's unique approach to phishing and scam link detection.

---

## Scoring System

| Score | Description |
|-------|-------------|
| 🟥 **High risk** | Multiple critical signals: expired/mismatched certs, missing CSP, scam patterns, cloaking, etc. |
| 🟧 **Moderate risk** | Mixed or partial protection. Often seen with major brands but warrants caution. |
| 🟩 **Low risk** | Clean redirect flow, strong TLS, proper headers, no tracking or obfuscation detected. |

---

## Getting Started

| | |
|---|---|
| **End-users** | Download via the [App Store](https://apps.apple.com/fr/app/legiturl/id6745583794) |
| **Developers** | Open `LegitURL.xcodeproj` in Xcode and build directly. |

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

## How it works

1. **Offline static parsing**  
   Detects homograph attacks, encoded words, scam phrases, entropy anomalies, and more.

2. **Sandboxed HTTPS fetch**  
   Retrieves headers, HTML body, TLS certificate, cookies, and inline JavaScript.

3. **Deterministic scoring engine**  
   Findings set bit-flags → weighted penalties → a single final score with full traceability.

See [`TECHNICAL_OVERVIEW.md`](TECHNICAL_OVERVIEW.md) for detailed logic and implementation

---

## Roadmap

### Completed
- [x] Cookie bit-flag pyramid
- [x] CSP / header correlation
- [x] HTML `<meta refresh>` detection

### In progress
- [ ] Correlate CSP SHA to inline 
- [ ] Subresource-Integrity (SRI) hash checks  
- [ ] Consolidated CSP generator
- [ ] Implement OpenSSL probe to retrieve certificate chain and reason for failed TLS handshake

## License

GNU  Affero GPL v3 – see [`LICENSE`](LICENSE) for details. Issues welcome.
