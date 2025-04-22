//
//  SuspiciousKeyWords.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//

struct SuspiciousKeywords {
    // ✅ Common Phishing Words (For subdomain/path checks)
    static let phishingWords: Set<String> = [
        "login", "verify", "account", "secure", "support", "update", "reset", "confirm"
    ]

    // ✅ Scam-Related Terms
    static let scamTerms: Set<String> = [
        "giftcard", "giveaway", "money", "crypto", "reward", "prize", "claim", "jackpot"
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
    
    static let dangerousExtensions: Set<String> = ["exe", "sh", "bat", "dll", "apk", "msi", "scr"]
}
