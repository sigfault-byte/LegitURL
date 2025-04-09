import Foundation
//Path and Domain Analysis: While the primary risks are often associated with the value and flags, analyzing the path and domain could provide additional context. For example, a cookie with a broad domain set on a specific path might be worth noting.
func analyzeCookie(_ cookie: CookieMetadata, httpResponseCode: Int) -> CookieAnalysisResult {
    var flags: [String] = []
    var severity: CookieSeverity = .info

    let valueSize = cookie.value.utf8.count
    let (isHighEntropyValue, entropyScore) = LegitURLTools.isHighEntropy(cookie.value, 4.0)
    if isHighEntropyValue {
        flags.append("High-entropy value (H ≈ \(String(format: "%.2f", entropyScore ?? 0))) — suspicious randomness")
    }

    if valueSize >= 64 {
        flags.append("Value size ≥64 bytes — large opaque identifier or encoded blob")
    } else if valueSize >= 32 {
        flags.append("Value size ≥32 bytes — possible UUID, HMAC, or token")
    } else if valueSize >= 16 {
        flags.append("Value size ≥16 bytes — could represent a UUID or short hash")
    }

    // Detect fingerprint-like cookies: large value with very short expiry
    if valueSize >= 100 && (cookie.expire?.timeIntervalSinceNow ?? 0) < 3600 {
        flags.append("Large fingerprint-style cookie with short expiry — possible device profiling")
    }

    if let expiry = cookie.expire {
        let duration = expiry.timeIntervalSinceNow
        if duration <= 0 {
            flags.append("Expired cookie")
        } else if duration > 86400 {
            flags.append("Persistent cookie ( more than 24h)")
        } else if !cookie.value.isEmpty {
            flags.append("Short-lived persistent cookie")
        }
    } else {
        flags.append("Session cookie")
    }
    
    if valueSize > 64 && cookie.secure == false {
        flags.append("Large tracking value without Secure — possible misconfiguration or malicious use")
    }
    
    if cookie.sameSite.lowercased() == "none" {
        flags.append("SameSite=None (cross-site access)")
    }

    if cookie.secure == false {
        if cookie.sameSite.lowercased() == "none" {
            flags.append("Secure flag missing on SameSite=None cookie (critical misconfiguration)")
        } else {
            flags.append("Secure flag missing (insecure transmission possible)")
        }
    }

    if cookie.httpOnly == false {
        flags.append("HttpOnly flag missing — may expose cookie to JavaScript access")
    }
    
    if valueSize <= 10 && cookie.expire == nil && cookie.sameSite.lowercased() != "none" && cookie.secure != false {
        flags.append("Tiny sessionless cookie (\(valueSize)bytes) — likely benign (preference/flag)")
    }

    // Analyze value length in bytes and entropy for randomness
//TODO double check    Missing secure flag on same site = none is red flag! +  httpOnly SHOULD alway be there -> yellow / orange flag!!!
    let valueSeverity = isHighEntropyValue ? 2 : valueSize >= 32 ? 1 : valueSize >= 16 ? 1 : 0
    let isPersistent = cookie.expire != nil
    let isCrossSite = cookie.sameSite.lowercased() == "none"
    let isSecure = cookie.secure
    let isExpired = cookie.expire?.timeIntervalSinceNow ?? 1 <= 0
    let isBenignTiny = flags.contains("Tiny sessionless cookie — likely benign (preference/flag)")

    // Priority-based severity assignment
    if httpResponseCode != 200 {
        flags.append("Cookie set on non-200 response")
        severity = .dangerous
    } else if isBenignTiny {
        severity = .info
    } else if isExpired {
        severity = .info
    } else if valueSeverity >= 2 && isPersistent && isCrossSite {
        severity = .dangerous
    } else if valueSeverity >= 1 && (isPersistent || isCrossSite || isSecure) {
        severity = .tracking
    } else if valueSeverity > 0 || isCrossSite || (isSecure == false && !isCrossSite) {
        severity = .suspicious
    } else {
        severity = .info
    }

    return CookieAnalysisResult(cookie: cookie, severity: severity, flags: flags)
}

struct CookieAnalysisResult: Identifiable, Hashable {
    let id = UUID()
    let cookie: CookieMetadata
    let severity: CookieSeverity
    let flags: [String]
}
