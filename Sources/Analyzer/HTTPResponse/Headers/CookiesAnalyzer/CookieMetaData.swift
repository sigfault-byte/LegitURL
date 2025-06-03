//  CookieMetaData.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/04/2025.
//

import Foundation
//Not used, its either too echaustive or too restrictive, maybe let users add their own cookie key watchlist????
let trackingKeywords = Set(["sessionid", "sid", "sess", "jsessionid", "phpsessid", "utm_", "fbp", "_ga", "_gid", "_gcl_au", "_gat", "ajs_user_id", "cluid", "visitor_id", "trackid", "tracker", "campaign", "click_id", "__utm", "__hssc", "__hstc", "__cf_bm", "ads", "ad_id", "affiliate_id", "pixel_id"])

typealias CookieSeverity = SecurityWarning.SeverityLevel


struct CookieMetadata: Hashable{
    let name: String
    let value: String
    let domain: String
    let path: String
    let expire: Date?
    let sameSite: String // "Lax", "Strict", or "None"
    let secure: Bool
    let httpOnly: Bool
    let comment: String?
    let commentURL: URL?
    let version: Int
    let portList: [NSNumber]?
}

func populateCookieMetadata(_ cookie: HTTPCookie) -> CookieMetadata {
    let rawDomain = cookie.domain
    let normalizedDomain = (rawDomain == ".^filecookies^" || rawDomain.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) ? nil : rawDomain
    return CookieMetadata(
        name: cookie.name,
        value: cookie.value,
        domain: normalizedDomain ?? "",
        path: cookie.path,
        expire: cookie.expiresDate,
        sameSite: cookie.sameSitePolicy?.rawValue ?? "none",
        secure: cookie.isSecure,
        httpOnly: cookie.isHTTPOnly,
        comment: cookie.comment,
        commentURL: cookie.commentURL,
        version: cookie.version,
        portList: cookie.portList
    )
}

func parseCookies(from headers: [String], for url: String) -> [CookieMetadata] {
    guard let urlObject = URL(string: url) else {
        #if DEBUG
        print("Invalid URL format: \(url)")
        #endif
        return []
    }

    var allCookies: [CookieMetadata] = []

    for cookieString in headers {
        let singleHeader = ["Set-Cookie": cookieString]
        let parsed = HTTPCookie.cookies(withResponseHeaderFields: singleHeader, for: urlObject)
        allCookies.append(contentsOf: parsed.map { populateCookieMetadata($0) })
    }

    return allCookies
}

struct CookieFlagBits: OptionSet, Hashable {
    let rawValue: UInt32

    // Size (0–2)
    static let smallValue            = CookieFlagBits(rawValue: 1 << 0)   // 1
    static let mediumValue           = CookieFlagBits(rawValue: 1 << 1)   // 2
    static let largeValue            = CookieFlagBits(rawValue: 1 << 2)   // 4

    // Lifespan (3–6)
    static let session               = CookieFlagBits(rawValue: 1 << 3)   // 8
    static let expired               = CookieFlagBits(rawValue: 1 << 4)   // 16
    static let shortLivedPersistent  = CookieFlagBits(rawValue: 1 << 5)   // 32
    static let persistent            = CookieFlagBits(rawValue: 1 << 6)   // 64

    // Access Control (7–9)
    static let samesiteLax           = CookieFlagBits(rawValue: 1 << 7)   // 128
    static let samesiteStrict        = CookieFlagBits(rawValue: 1 << 8)   // 256
    static let sameSiteNone          = CookieFlagBits(rawValue: 1 << 9)   // 512

    // Security Attributes (10–11)
    static let secure                = CookieFlagBits(rawValue: 1 << 10)  // 1 024
    static let httpOnly              = CookieFlagBits(rawValue: 1 << 11)  // 2 048

    // Context (12–13)
    static let setOnRedirect         = CookieFlagBits(rawValue: 1 << 12)  // 4 096
    static let reusedAcrossRedirect  = CookieFlagBits(rawValue: 1 << 13)  // 8 192

    // Content Signature (14)
    static let highEntropyValue      = CookieFlagBits(rawValue: 1 << 14)  // 16 384
    static let pathOverlyBroad       = CookieFlagBits(rawValue: 1 << 15)  // 32 768
    static let domainOverlyBroad     = CookieFlagBits(rawValue: 1 << 16)  // 65 536
    static let wayTooLarge           = CookieFlagBits(rawValue: 1 << 17)  // 131 072
    static let verySmall             = CookieFlagBits(rawValue: 1 << 18)
        
}


struct CookieAnalysisResult: Identifiable, Hashable {
    let id = UUID()
    var cookie: CookieMetadata
    let severity: CookieSeverity
    let flags: CookieFlagBits
    let entropy: Float?
}

extension CookieFlagBits {
    func descriptiveReasons(entropyScore: Float? = nil) -> (machine: [String], human: [String]) {
        var human: [String] = []
        var machine: [String] = []

        if contains(.reusedAcrossRedirect) {
            return (["reused_across_redirect"], ["Same Cookie reused across redirects"])
        }
        
        if contains(.verySmall) {
            return (["very_small"], ["Very small value (≤8 bytes)"])
        }
        
        if contains(.smallValue) {
            machine.append("small_value")
            human.append("Small value (≤16 bytes)")
        }
        if contains(.mediumValue) {
            machine.append("medium_value")
            human.append("Medium value (16–64 bytes)")
        }
        if contains(.largeValue) && contains(.persistent) {
            machine.append("large_persistent_value")
            human.append("Fingerprint-style tracking (large persistent value too big to be random)")
        } else if contains(.largeValue) {
            machine.append("large_value")
            human.append("Large value (>64 bytes) — too big to be random")
        }
        if contains(.wayTooLarge) {
            machine.append("way_too_large")
            human.append("The value is more than 100bytes")
        }

        if contains(.expired) {
            machine.append("expired_cookie")
            human.append("Expired cookie")
        }
        if contains(.shortLivedPersistent) && contains(.persistent) {
            machine.append("conflicting_lifespan")
            human.append("Conflicting lifespan — both short-lived and persistent set (likely misconfiguration or cloaking)")
        } else if contains(.shortLivedPersistent) {
            machine.append("short_lived_persistent")
            human.append("Short-lived persistent cookie — mimics session but persists (likely tracking)")
        } else if contains(.persistent) {
            machine.append("persistent_cookie")
            human.append("Persistent cookie")
        }

        if contains(.samesiteLax) {
            machine.append("samesite_lax")
            human.append("SameSite=Lax, correclty set")
        }
        if contains(.sameSiteNone) {
            machine.append("samesite_none")
            human.append("SameSite=None — could be unset. Browsers default to Lax, but it should be declare explicitly.")
        }

        if contains(.secure) == false {
            machine.append("secure_missing")
            human.append("Secure flag missing (can be sent over HTTP)")
        }
        if contains(.httpOnly) == false {
            machine.append("httponly_missing")
            human.append("HttpOnly flag missing (accessible by JavaScript)")
        }

        if contains(.setOnRedirect) {
            machine.append("set_on_redirect")
            human.append("Cookie was set during redirect")
        }

        if contains(.highEntropyValue) {
            machine.append("high_entropy_value")
            if let score = entropyScore {
                human.append("High-entropy value (H ≈ \(String(format: "%.2f", score)))")
            } else {
                human.append("High-entropy value")
            }
        }

        if contains(.pathOverlyBroad) {
            machine.append("path_overly_broad")
            human.append("Path is overly broad (applies site-wide)")
        }
        if contains(.domainOverlyBroad) {
            machine.append("domain_overly_broad")
            human.append("Domain is overly broad (shared with subdomains and site-wide)")
        }

        return (machine, human)
    }
}
