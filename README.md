> **Work‑in‑progress.**  
> It works today and gets sharper every week with new heuristics and polish.

## LegitURL
> Like a **nutrition label for links**  
> Scan any URL and get a 🟩 🟧 🟥 verdict based on **technical behaviour**.  
> Because trust should be *earned*, not assumed.

**Paste, type, or scan** a link → tap **Check**.

| Score | Findings | Meaning |
|-------|----------|---------|
| 🟥 **Red – Unsafe** | Multiple issues (weak TLS, missing CSP, scam keywords…). | Treat as hostile unless you already trust the sender. |
| 🟧 **Orange – Suspicious** | Mixed signals: solid parts but hygiene gaps (tracking cookies on redirects, `unsafe-inline`, …). | Usually fine for major brands; be cautious with unknown sites. |
| 🟩 **Green – Safe** | Clean redirects, correct headers, trusted cert. | Not bullet‑proof, but shows clear effort. |

After scanning you can inspect:

* Parsed URL components  
* All findings
* Full HTTP headers & CSP directive view  
* Cookies summary  
* HTML body (up to 1.2 MB)  
* Each `<script>` block (up to 3 KB)



---

### How it works
1. **Offline** – parse the link (look‑alikes, encodings, scam words).  
2. **Online** – one sandboxed HTTPS request reads headers, certificate, cookies, inline JS.

**All processing is local.**  
The only network traffic is **one direct HTTPS request to the link itself.**  
**No cloud, no tracking, no third-party services. Ever.**

---

- [1 · Who is LegitURL for?](#1-who-is-legiturl-for)  
- [2 · Quick start](#2-quick-start)

## 1. Who is LegitURL for?
Anyone thinking *“Should I trust this link?”*  
Ideal for casual users, privacy enthusiasts, and developers inspecting headers / CSP / TLS / JavaScript.

## 2. Quick start
[Join the TestFlight beta](https://…) or clone and build with Xcode.

---

**Dig deeper:** see [`TECHNICAL.md`](TECHNICAL.md)