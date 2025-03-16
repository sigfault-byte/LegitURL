//
//  SuspiciousKeyWords.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
struct SuspiciousKeywords {
    // ✅ Common Phishing Words (For subdomain/path checks)
    static let phishingWords: Set<String> = [
        "login", "secure", "verify", "account", "support",
        "banking", "free", "win", "winner", "update",
        "reset", "confirm", "activate", "deactivate", "access",
        "validate", "approval", "auth", "security", "alert",
        "locked", "warning", "urgent", "message", "identity",
        "suspended", "recover", "recovery", "resetpassword",
        "protection", "unusual", "danger", "check", "fraud"
    ]

    // ✅ Scam-Related Terms
    static let scamTerms: Set<String> = [
        "giftcard", "giveaway", "claim", "unlock", "money",
        "bitcoin", "crypto", "lottery", "reward", "prize",
        "jackpot", "wiretransfer", "cash", "payout",
        "invest", "trading", "forex", "doubleyourmoney",
        "nft", "mining", "betting", "casino", "binaryoptions",
        "instantpayout", "loan", "loanapproval", "fastcash",
        "donate", "donation", "charity", "supportfund"
    ]

    // ✅ Redirect & JavaScript Exploitation Keywords
    static let redirectAndJSExploitationKeywords: Set<String> = [
        "redirect", "redir", "next", "window.location", "location.href",
        "location.replace", "location.assign", "navigate", "open(",
        "self.location", "parent.location", "document.cookie",
        "document.write", "eval(", "setTimeout", "setInterval",
        "onerror=", "onload=", "alert(", "confirm(", "prompt(",
        "innerHTML", "outerHTML", "execCommand", "createElement(",
        "appendChild(", "insertAdjacentHTML", "addEventListener", "<script>",
        "setAttribute", "document.domain", "window.name",
        "history.pushState", "history.replaceState", "track", "utm_", "clk", "rd", "ref", "out", "next", "dest"
    ]

    // ✅ Form Hijacking & Credential Theft
    static let phishingAndFormHijacking: Set<String> = [
        "input", "password", "username", "creditcard",
        "formaction", "fetch(", "XMLHttpRequest", "sessionStorage",
        "localStorage", "navigator.sendBeacon", "send(", "trackUser",
        "document.forms", "document.submit", "credentials",
        "autocomplete", "hiddeninput", "invisibleform",
        "value","secret", "keylogger", "recordkeys", "grabber",
        "stealer", "phish", "hidden"
    ]

    // ✅ Obfuscation & Encoding Tricks
    static let obfuscationAndEncodingTricks: Set<String> = [
        "btoa(", "atob(", "encodeURIComponent(", "decodeURIComponent(",
        "escape(", "unescape(", "fromCharCode(", "String.fromCharCode",
        "charCodeAt(", "replace(/", "match(/", "split(", "join(",
        "rot13", "hex_encode", "base64_encode", "base64_decode",
        "urlencode", "urldecode", "xor", "aes_encrypt", "des_encrypt",
        "md5", "sha1", "sha256", "crc32", "hmac", "ciphertext",
        "pkcs7", "pbkdf2", "bcrypt", "scrypt", "jwt="
    ]
    
    static let trackingAndMonitoring: Set<String> = [
        "ga(", "fbq(", "ym(", "insightly(", "mixpanel(", "amplitude(",
        "keen(", "matomo(", "clickid", "hotjar(", "clarity(", "snowplow(",
        "segment(", "fullstory(", "luckyorange(", "heap(", "adroll(",
        "pixel.fire", "doubleclick.net", "googletagmanager(", "gtm(",
        "google-analytics.com", "facebook.com/tr", "fbclid", "utm_",
        "trk", "trkId", "trkRef", "trackEvent", "trackPageview",
        "trackConversion", "visitorId", "sessionId", "userId",
        "datadome", "akamai-mpulse", "cloudflare_insights", "newrelic(",
        "optimizely(", "braze(", "webtrends(", "quantcast(", "pardot("
    ]
}

