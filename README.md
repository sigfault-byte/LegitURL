> **Work‑in‑progress.**  
> LegitURL already works — and it’s strict on purpose — but new heuristics and UI polish are landing every week.

## LegitURL
> Like a **nutrition label for links**  
> Scan any URL and get a 🟩 🟧 🟥 verdict based on **technical behaviour**, not brand reputation.  
> Because trust should be *earned* — not assumed.

- [1 · Who is LegitURL for?](#1-who-is-legiturl-for)
- [2 · Quick start](#2-quick-start)

LegitURL is a privacy‑focused iOS app that helps you  
• **Spot scams** (`secure-paypal-login.com`)  
• **Avoid trackers** (shady redirects, invasive cookies)  
• **Inspect security** (TLS certs, headers, scripts)

---

### How it works
1. Offline: parse the link (lookalikes, encodings, scam words).  
2. Online: one sandboxed HTTPS request reads headers, certificate, cookies, and inline JS  
**no personal data leaves your phone, all the analysis are offline.**

---

## 1. Who is LegitURL for?
Anyone wondering *“Can I trust this link I just found?”*  
Ideal for: casual users, privacy enthusiasts, devs inspecting headers/CSP/TLS/Javascript.

---

## 2. Quick start
[Join the TestFlight beta](https://…) — or clone and build in Xcode.

---

🛠 **Need the deep‑dive?** See [`TECHNICAL.md`](TECHNICAL.md).
