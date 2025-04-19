//  CookieMetaData.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//

import Foundation
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
    return CookieMetadata(
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        expire: cookie.expiresDate,
        sameSite: cookie.sameSitePolicy?.rawValue ?? "Lax",
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
        print("Invalid URL format: \(url)")
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
    let rawValue: UInt16

    // Size (0–2)
    static let smallValue           = CookieFlagBits(rawValue: 1 << 0)   // 1
    static let mediumValue          = CookieFlagBits(rawValue: 1 << 1)   // 2
    static let largeValue           = CookieFlagBits(rawValue: 1 << 2)   // 4

    // Lifespan (3–6)
    static let session              = CookieFlagBits(rawValue: 1 << 3)   // 8
    static let expired              = CookieFlagBits(rawValue: 1 << 4)   // 16
    static let shortLivedPersistent = CookieFlagBits(rawValue: 1 << 5)   // 32
    static let persistent           = CookieFlagBits(rawValue: 1 << 6)   // 64

    // Access Control (7–9)
    static let samesiteLax          = CookieFlagBits(rawValue: 1 << 7)   // 128
    static let samesiteStrict       = CookieFlagBits(rawValue: 1 << 8)   // 256
    static let sameSiteNone         = CookieFlagBits(rawValue: 1 << 9)   // 512

    // Security Attributes (10–11)
    static let secure               = CookieFlagBits(rawValue: 1 << 10)  // 1024
    static let httpOnly             = CookieFlagBits(rawValue: 1 << 11)  // 2048

    // Context (12–13)
    static let setOnRedirect        = CookieFlagBits(rawValue: 1 << 12)  // 4096
    static let reusedAcrossRedirect = CookieFlagBits(rawValue: 1 << 13)  // 8192

    // Content Signature (14)
    static let highEntropyValue     = CookieFlagBits(rawValue: 1 << 14)  // 16384
}


struct CookieAnalysisResult: Identifiable, Hashable {
    let id = UUID()
    let cookie: CookieMetadata
    let severity: CookieSeverity
    let flags: CookieFlagBits
    let entropy: Float?
}

extension CookieFlagBits {
    func descriptiveReasons(entropyScore: Float? = nil) -> [String] {
        var reasons: [String] = []

        if contains(.highEntropyValue) {
            if let score = entropyScore {
                reasons.append("High-entropy value (H ≈ \(String(format: "%.2f", score)))")
            } else {
                reasons.append("High-entropy value")
            }
        }

        if contains(.smallValue)            { reasons.append("Small value (≤16 bytes)") }
        if contains(.mediumValue)           { reasons.append("Medium value (17–64 bytes)") }
        if contains(.largeValue)            { reasons.append("Large value (>64 bytes)") }

        if contains(.session)               { reasons.append("Session cookie") }
        if contains(.expired)               { reasons.append("Expired cookie") }
        if contains(.shortLivedPersistent)  { reasons.append("Short-lived persistent cookie") }
        if contains(.persistent)            { reasons.append("Persistent cookie") }

        if contains(.samesiteLax)           { reasons.append("SameSite=Lax") }
        if contains(.samesiteStrict)        { reasons.append("SameSite=Strict") }
        if contains(.sameSiteNone)          { reasons.append("SameSite=None") }

        if contains(.secure) == false       { reasons.append("Secure flag missing (can be sent over HTTP)") }
        if contains(.httpOnly) == false     { reasons.append("HttpOnly flag missing (accessible by JavaScript)") }

        if contains(.setOnRedirect)         { reasons.append("Cookie was set during redirect") }
        if contains(.reusedAcrossRedirect)  { reasons.append("Cookie reused across redirect chain") }

        return reasons
    }
}
