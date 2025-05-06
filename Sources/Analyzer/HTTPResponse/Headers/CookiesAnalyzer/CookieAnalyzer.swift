// DOMAIN STRUCTURE
//┌─────────────────────────────┐
//│         example.com         │
//└────────────┬────────────────┘
//             │
//   ┌─────────┴────────────┐
//   │                      │
//www.example.com     api.example.com
//   │                      │
//login.example.com   shop.example.com
//
//
// COOKIE DOMAIN SCOPE
//Set-Cookie: Domain=example.com
//→ Sent only to: example.com
//
//Set-Cookie: Domain=.example.com
//→ Sent to: example.com, www.example.com, api.example.com, etc.
//
//Set-Cookie: Domain=sub.example.com
//→ Sent only to: sub.example.com
//
// Wildcards like *.example.com are NOT allowed
// But Set-Cookie: Path=/ → cookie is sent to all paths on the same domain (site-wide scope)
// Not shared across domains or subdomains unless Domain=.example.com is explicitly set
//PATH STRUCTURE UNDER example.com
///
//├── index.html
//├── account/
//│   ├── login/
//│   └── settings/
//└── shop/
//    ├── cart/
//    └── checkout/
//
//COOKIE PATH SCOPE
//Request URL: https[:]//example.com/account/login
//
//1. No Path attribute →
//   → Cookie Path = /account/
//   → Sent to: /account/, /account/login/, /account/settings/
//   → Not sent to /shop/ or /
//
//2. Path=/
//   → Sent to ALL paths under domain (site-wide)
//
//3. Path=/account/
//   → Sent only to: /account/, /account/login/, etc.
//
//Cookie Path = Directory of the request URI if unspecified

func analyzeCookie(_ cookie: CookieMetadata, httpResponseCode: Int, seenCookie: Set<String>, host: String) -> CookieAnalysisResult {
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
    let (isHighEntropyValue, entropyScore) = CommonTools.isHighEntropy(cookie.value, 4.7)
    if isHighEntropyValue {
        bitFlags.insert(.highEntropyValue)
        
    }
    if valueSize < 8 {
        bitFlags.insert(.verySmall)
    }
    
    switch valueSize {
    case 0...16:
        bitFlags.insert(.smallValue)
    case 17...64:
        bitFlags.insert(.mediumValue)
    default:
        bitFlags.insert(.largeValue)
    }
    
    if valueSize > 100 && isHighEntropyValue { bitFlags.insert(.wayTooLarge) }
    
    // TODO (v2.0): Investigate use of expired cookies in redirect chains
    // - If cookie is expired AND value is long/high-entropy → may be fingerprinting cleanup
    // - If expired on non-200 response → possibly used in cloaking logic
    // - For now, expired cookies are flagged as `.info` only
//    print("Cookie: \(cookie.name) expires in \(cookie.expire) seconds")
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
    } else if cookie.sameSite.lowercased() == "lax" {
        bitFlags.insert(.samesiteLax)
    } else if cookie.sameSite.lowercased() == "strict" {
        bitFlags.insert(.samesiteStrict)
    }

    if cookie.secure == true {
        bitFlags.insert(.secure)
    }

    if cookie.httpOnly == true {
        bitFlags.insert(.httpOnly)
    }

    let domainParts = cookie.domain.components(separatedBy: ".").filter { !$0.isEmpty }
    let isDomainBroad = cookie.domain.hasPrefix(".") && domainParts.count >= 2
    let isPathBroad = cookie.path == "/"
    if isPathBroad {
        bitFlags.insert(.pathOverlyBroad)
    }
    

    if isDomainBroad && isPathBroad {
        bitFlags.insert(.domainOverlyBroad)
    }

    let isCrossSite = cookie.sameSite.lowercased() == "none"
    let isSecure = cookie.secure

    // Severity determination logic:
    // - Any cookie accessible to JS and longer than 16B is considered tracking
    // - High-entropy, persistent, and wide-scope cookies escalate to tracking or dangerous
    // - Small/expired cookies are low-risk and informational
    // - Redirect-set cookies are suspicious by design
    if httpResponseCode != 200 {
        bitFlags.insert(.setOnRedirect)
        severity = .suspicious
    }else if valueSize > 100 && (cookie.httpOnly == false || cookie.secure == false ){
        severity = .dangerous
    }else if !cookie.httpOnly && valueSize > 16 && isHighEntropyValue {
        severity = .tracking
    } else if bitFlags.contains([.highEntropyValue, .persistent, .sameSiteNone]) {
        severity = .dangerous
    } else if bitFlags.contains(.smallValue) {
        severity = .info
    } else if bitFlags.contains(.expired) && cookie.httpOnly == true {
        severity = .info
    }else if bitFlags.contains(.expired) && isHighEntropyValue && cookie.httpOnly == false {
        severity = .suspicious
    }else if bitFlags.contains([.highEntropyValue, .persistent]) || bitFlags.contains([.highEntropyValue, .sameSiteNone]) || bitFlags.contains([.persistent, .sameSiteNone]) {
        severity = .tracking
    } else if bitFlags.contains(.highEntropyValue) || isCrossSite || (isSecure == false && !isCrossSite) {
        severity = .suspicious
    } else {
        severity = .info
    }

    return CookieAnalysisResult(cookie: cookie, severity: severity, flags: bitFlags, entropy: entropyScore)
}
