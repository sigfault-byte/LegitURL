func analyzeCookie(_ cookie: CookieMetadata, httpResponseCode: Int, seenCookie: Set<String>) -> CookieAnalysisResult {
    if seenCookie.contains(cookie.name) {
        return CookieAnalysisResult(
            cookie: cookie,
            severity: .info,
            flags: CookieFlagBits.reusedAcrossRedirect,
            entropy: nil
        )
    }
    
    var severity: CookieSeverity = .info
    var bitFlags: CookieFlagBits = []

    let valueSize = cookie.value.utf8.count
    let (isHighEntropyValue, entropyScore) = LegitURLTools.isHighEntropy(cookie.value, 4.4)
    if isHighEntropyValue {
        bitFlags.insert(.highEntropyValue)
        
    }
    if valueSize <= 16 {
        bitFlags.insert(.smallValue)
    } else if valueSize <= 31 {
        bitFlags.insert(.mediumValue)
    }

    if valueSize >= 32 {
        bitFlags.insert(.largeValue)
    }

    // TODO (v2.0): Investigate use of expired cookies in redirect chains
    // - If cookie is expired AND value is long/high-entropy → may be fingerprinting cleanup
    // - If expired on non-200 response → possibly used in cloaking logic
    // - For now, expired cookies are flagged as `.info` only
//    print("🔍 Cookie: \(cookie.name) expires in \(cookie.expire) seconds")
    if let expiry = cookie.expire {
        let duration = expiry.timeIntervalSinceNow
        if duration <= 0 {
            bitFlags.insert(.expired)
        } else if duration > 86400 {
            bitFlags.insert(.persistent)
        } else if !cookie.value.isEmpty {
            bitFlags.insert(.shortLivedPersistent)
        }
    } else {
        bitFlags.insert(.session)
    }

    if cookie.sameSite.lowercased() == "none" {
        bitFlags.insert(.sameSiteNone)
    }

    if cookie.secure == true {
        bitFlags.insert(.secure)
    }

    if cookie.httpOnly == true {
        bitFlags.insert(.httpOnly)
    }

    

    let isCrossSite = cookie.sameSite.lowercased() == "none"
    let isSecure = cookie.secure

    if httpResponseCode != 200 {
        bitFlags.insert(.setOnRedirect)
        severity = .suspicious
    } else if bitFlags.contains([.highEntropyValue, .persistent, .sameSiteNone]) {
        severity = .dangerous
    } else if bitFlags.contains(.smallValue) {
        severity = .info
    } else if bitFlags.contains(.expired) {
        severity = .info
    } else if bitFlags.contains([.highEntropyValue, .persistent]) || bitFlags.contains([.highEntropyValue, .sameSiteNone]) || bitFlags.contains([.persistent, .sameSiteNone]) {
        severity = .tracking
    } else if bitFlags.contains(.highEntropyValue) || isCrossSite || (isSecure == false && !isCrossSite) {
        severity = .suspicious
    } else {
        severity = .info
    }

    return CookieAnalysisResult(cookie: cookie, severity: severity, flags: bitFlags, entropy: entropyScore)
}
