func analyzeCookie(_ cookie: CookieMetadata, httpResponseCode: Int, seenCookie: Set<String>) -> CookieAnalysisResult {
    if seenCookie.contains(cookie.name) {
        return CookieAnalysisResult(
            cookie: cookie,
            severity: .info,
            flags: CookieFlagBits.reusedAccrossRedirect,
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

    if valueSize >= 64 {
        bitFlags.insert(.largeValue)
    }

    if valueSize >= 100 && (cookie.expire?.timeIntervalSinceNow ?? 0) < 3600 {
        bitFlags.insert(.fingerprintStyle)
    }

    if let expiry = cookie.expire {
        let duration = expiry.timeIntervalSinceNow
        if duration <= 0 {
            bitFlags.insert(.expired)
        } else if duration > 86400 {
            bitFlags.insert(.persistent)
        } else if !cookie.value.isEmpty {
            bitFlags.insert(.shortLivedPersistent)
        }
    }

    if valueSize > 64 && cookie.secure == false {
        bitFlags.insert(.secureMissing)
    }

    if cookie.sameSite.lowercased() == "none" {
        bitFlags.insert(.samesiteNone)
    }

    if cookie.secure == false {
        bitFlags.insert(.secureMissing)
    }

    if cookie.httpOnly == false {
        bitFlags.insert(.httpOnlyMissing)
    }

    if valueSize <= 12 {
        bitFlags.insert(.smallCookie)
    }

    let isCrossSite = cookie.sameSite.lowercased() == "none"
    let isSecure = cookie.secure

    if httpResponseCode != 200 {
        bitFlags.insert(.cookieOnRedirect)
        severity = .dangerous
    } else if bitFlags.contains([.highEntropyValue, .persistent, .samesiteNone]) {
        severity = .dangerous
    } else if bitFlags.contains(.benignTiny) {
        severity = .info
    } else if bitFlags.contains(.expired) {
        severity = .info
    } else if bitFlags.contains([.highEntropyValue, .persistent]) || bitFlags.contains([.highEntropyValue, .samesiteNone]) || bitFlags.contains([.persistent, .samesiteNone]) {
        severity = .tracking
    } else if bitFlags.contains(.highEntropyValue) || isCrossSite || (isSecure == false && !isCrossSite) {
        severity = .suspicious
    } else {
        severity = .info
    }

    return CookieAnalysisResult(cookie: cookie, severity: severity, flags: bitFlags, entropy: entropyScore)
}
