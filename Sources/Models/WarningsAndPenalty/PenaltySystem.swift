import Foundation

struct PenaltySystem {
    public enum Penalty {
        // CRITICAL ISSUES
        static let critical                            = -100
        
        // HOST-RELATED PENALTIES
        static let highEntropyDomain                   = -30
        static let exactBrandImpersonation             = -25
        static let phishingWordsInHost                 = -20
        static let scamWordsInHost                     = -20
        static let tooManyHyphensInDomain              = -20
        static let userInfoInHost                      = -20
        static let subdomainUnderscore                 = -20
        static let brandImpersonation                  = -15
        static let brandLookaLike                      = -10
        static let underScoreInSubdomain               = -10
        static let highEntropySubDomain                = -10
        static let domainNonASCII                      = -10
        
        // REDIRECTION & OBFUSCATION
        //        static let hiddenRedirectFragment              = -40
        static let hiddenRedirectQuery                 = -30
        //        static let phpRedirect                         = -25
        //        static let suspiciousRedirect                  = -10
        
        // PATH-RELATED PENALTIES
        static let executableInPath                    = -20
        static let pathHasExecutable                   = -10
        static let pathIsEndpointLike                  = -10
        static let highEntropyPathComponent            = -10
        static let scamWordsInPath                     = -10
        static let phishingWordsInPath                 = -10
        static let suspiciousPathSegment               = -10
        static let containBrandInPath                  = -5
        static let brandLookaLikeInPath                = -5
        
        // QUERIES & fragment ... Need granularity see lamai todo
        static let malformedQueryPair                  = -40
        static let highEntropyQuery                    = -10
        static let queryKeyForbiddenCharacters         = -20
        static let valueForbiddenCharacters            = -20
        static let scamWordsInQuery                    = -20
        static let phishingWordsInQuery                = -20
        static let IpAddressInQuery                    = -20
        static let emailInQuery                        = -20
        static let exactBrandInQuery                   = -15
        static let keyIsHighEntropy                    = -15
        static let queryContainsBrand                  = -10
        static let brandLookAlikeInQuery               = -10
        static let uuidInQuery                         = -10
        static let jsonInQuery                         = -10
        static let emptyQuery                          = -5
        
        // Fragment
        static let forbiddenChar                       = -20
        static let malformedFragmentPair               = -20
        static let malformedFragment                   = -15
        
        //JAVASCRIPT & SECURITY ISSUES
        static let javascriptXSS                       = -30
        
        static let deepObfuscation                     = -20
        static let suspiciousPattern                   = -15
        static let base64Url                           = -10
        
        
        
        /////////////////////ONLINE ///////////////////////////////////////////
        ///Body
        static let scriptIs80Percent                   = -30
        static let extHttpScriptSrc                    = -40
        static let jsEvalInBody                        = -30
        static let badJSCallInline                     = -30
        static let jsFingerPrinting                    = -30
        static let hotdogWaterDev                      = -30
        static let unusualScritSrcFormat               = -30
        static let atobJSONparserCombo                 = -25
        static let metaRefreshInBody                   = -25
        static let scriptMalformed                     = -20
        static let scriptIsMoreThan512                 = -20
        static let scriptUnknownOrigin                 = -20
        static let jsWindowsRedirect                   = -20
        static let jsWebAssembly                       = -20
        static let extScriptSrc                        = -20
        static let highScriptDensity20                 = -20
        static let scriptDataURI                       = -20
        static let scriptIs70Percent                   = -10
        static let jsCookieAccess                      = -10
        static let smallHTMLless896                    = -10
        static let highScriptDensity                   = -10
        static let sameDomainCookie                    = -10
        static let jsStorageAccess                     = -10
        static let jsSetItemAccess                     = -10
        static let mediumScritpDensity                 = -5
        static let scriptIs5070Percent                 = -5
        static let smallhtmllessthan1408               = -5
        
        //InlineSpecific & JS penalty
        static let hightPenaltyForInlineJS             = -30
        static let jsSetEditCookie                     = -20
        static let mediumPenaltyForInlineJS            = -15
        static let lowPenaltyForInlineJS               = -5
        static let jsReadsCookie                       = -5
        
        ///Cookie////
        static let cookiesOnNon200                     = -20
        static let moreThan64BofCookie                 = -15
        static let moreThan16BofCookie                 = -5
        ///TLS///
        static let tksWeakKey                          = -20
        static let reusedTLS1FDQN                      = -20
        static let unknownVL                           = -10
        static let hotDogwaterCN                       = -10
        static let tlsWillExpireSoon                   = -10
        static let tlsIsNew7days                       = -10
        static let tlsShortLifespan                    = -10
        static let tlsIsNew30days                      = -5
        
        //RESPONSE HEADER ISSUE
        static let blockedByFirewall                   = -100
        static let serverError                         = -100
        static let missConfiguredOrScam                = -20
        static let hidden200Redirect                   = -20
        static let suspiciousStatusCode                = -15
        
        
        
        // Redirect
        static let silentRedirect                     = -20
        static let malformedRedirect                  = -20
        static let redirectToDifferentTLD             = -20
        static let redirectRelative                   = -20
        static let redirectToDifferentDomain          = -10
        
        // INFORMATIVE (No penalty)
        static let informational                       = 0
    }
    
    // ✅ Suspicious TLDs and their penalties
    static let suspiciousTLDs: [String: Int] = [
        ".tk":          -20,
        ".ml":          -20,
        ".ga":          -20,
        ".cf":          -20,
        ".gq":          -20,
        ".top":         -20,
        ".xyz":         -20,
        ".ru":          -20,
        ".cn":          -20,
        ".cc":          -20,
        ".pw":          -20,
        ".biz":         -20,
        ".ws":          -20,
        ".info":        -20,
        ".review":      -20,
        ".loan":        -20,
        ".download":    -20,
        ".trade":       -20,
        ".party":       -20,
        ".click":       -20,
        ".country":     -20,
        ".kim":         -20,
        ".men":         -20,
        ".date":        -20,
        ".gdn":         -20,
        ".stream":      -20,
        ".cam":         -20,
        ".cricket":     -20,
        ".space":       -20,
        ".fun":         -20,
        ".site":        -20,
        ".best":        -20,
        ".world":       -20,
        ".shop":        -20,
        ".gifts":       -20,
        ".beauty":      -20,
        ".zip":         -20,
        ".mov":         -20,
        ".live":        -20
    ]
    static func penaltyForCookieBitFlags(_ flags: CookieFlagBits) -> Int {
        // MARK: - Cookie Scoring Pyramid Initial logic
        //
        // Group 1 — BENIGN (Score: 0)
        // - Expired token:
        //     .expired + .httpOnly, without .highEntropyValue → harmless cleanup
        // - Secure session ID:
        //     .session + .smallValue + .secure + .httpOnly
        // - Short-lived token:
        //     .shortLivedPersistent + .smallValue + .secure + .httpOnly
        // - SameSite strict/lax with low entropy → conservative setup
        //
        // Group 2 — TRACKING (Score: -5 to -10)
        // - Secure persistent tracking:
        //     .persistent + .highEntropyValue + .secure + .httpOnly
        // - Clean medium cookie:
        //     .mediumValue + .secure + .httpOnly
        // - Redirect reuse:
        //     .reusedAcrossRedirect + .smallValue
        // - 3rd party tracking with protection:
        //     .sameSiteNone + .secure + .httpOnly
        //
        // Group 3 — SUSPICIOUS (Score: -10 to -15)
        // - Leaky persistent tracking:
        //     .persistent + .highEntropyValue + (missing .httpOnly || missing .secure)
        // - Fingerprint-style token:
        //     .shortLivedPersistent + .largeValue + .highEntropyValue + missing .httpOnly
        // - Redirect behavior:
        //     .setOnRedirect + .reusedAcrossRedirect
        // - Inconsistent session:
        //     .session + .largeValue
        // - SameSite=None + missing Secure flag
        //
        // Group 4 — DANGEROUS (Score: -15 to -20)
        // - Full fingerprint blob:
        //     .largeValue + .shortLivedPersistent + .highEntropyValue + missing .httpOnly
        // - Cross-redirect ID recycling:
        //     .persistent + .reusedAcrossRedirect + .highEntropyValue
        // - Cloaked redirect injection:
        //     .setOnRedirect + .highEntropyValue
        // - Conflicting lifespan indicators:
        //     .persistent + .shortLivedPersistent → malformed config, possibly intentional abuse
        var penalty = 0
        let fullSecured = flags.contains([.httpOnly, .secure])
        let fingerPrintStyle = flags.contains([. largeValue, .persistent])
        let isSameSiteNone = flags.contains(.sameSiteNone)
        
        // Group 1: Harmless, bad practice not dangerous,  reused on redirect
        if flags.contains([.expired, .httpOnly]) {
            return 0
        }
        if flags.contains(.reusedAcrossRedirect) && !flags.contains(.setOnRedirect) {
            return 0
        }
        
        // Suspicious misuse: session + SameSite=None
        if flags.contains(.session) && flags.contains(.sameSiteNone) {
            return -10  // Indicates tracking intent with fake session scope
        }

        // Invalid combo: SameSite=None without Secure
        if flags.contains(.sameSiteNone) && !flags.contains(.secure) {
            return -15  // Rejected by modern browsers but still a strong red flag
        }
        
        // Conflicting lifespan — possibly intentional cloaking
        if flags.contains([.persistent, .shortLivedPersistent]) {
            return -15
        }
        
        if flags.contains(.setOnRedirect) && flags.contains(.reusedAcrossRedirect) {
            if flags.contains(.highEntropyValue) {
                return -15  // Likely fingerprint injected mid-redirect
            } else {
                return -10  // Behavioral tracking across hops
            }
        }
        
        // Group 1: Benign cookie combinations
        if flags.contains(.smallValue) && fullSecured {
            return 0
        }
        
        // Group 2: Suspicious secure tracker potential
        if flags.contains(.mediumValue) && flags.contains(.session) {
            if fullSecured {
                return -2
            } else if !flags.contains(.secure) && flags.contains(.httpOnly) {
                return -4
            } else if flags.contains(.secure) && !flags.contains(.httpOnly) {
                return -6
            } else {
                return -7
            }
        }
        
        if flags.contains(.largeValue) && flags.contains(.session) {
            if fullSecured {
                return -3
            } else if flags.contains(.httpOnly) && !flags.contains(.secure) {
                return -5
            } else if flags.contains(.secure) && !flags.contains(.httpOnly) {
                return -6
            } else {
                return -8
            }
        }
        
        if fingerPrintStyle {
            if fullSecured && !isSameSiteNone {
                return -5
            } else if fullSecured && isSameSiteNone {
                return -7
            } else if flags.contains(.httpOnly) && !flags.contains(.secure) {
                return -8
            } else if flags.contains(.secure) && !flags.contains(.httpOnly) {
                return isSameSiteNone ? -10 : -8
            } else {
                return -15
            }
        }
        
        if flags.contains(.setOnRedirect) && flags.contains(.reusedAcrossRedirect) {
            if flags.contains(.highEntropyValue) {
                return -15  // Likely fingerprint injected mid-redirect
            } else {
                return -10  // Behavioral tracking across hops
            }
        }

        
        // MARK: - Atomic signal-based accumulation
        
        // Exposure
        if !flags.contains(.httpOnly)            { penalty += -5 } // More dangerous: JS can access
        if !flags.contains(.secure)              { penalty += -2 } // Less dangerous, more like different kind of dangerous : sent over HTTP
        if flags.contains(.domainOverlyBroad)    { penalty += -2 }
        if flags.contains(.pathOverlyBroad)      { penalty += -2 }
        
        // Payload intent
        if flags.contains(.persistent)           { penalty += -2 }
        if flags.contains(.shortLivedPersistent) { penalty += -1 }
        if flags.contains(.highEntropyValue)     { penalty += -3 }
        if flags.contains(.largeValue)           { penalty += -5 }
        
        // Configuration quirks
        if flags.contains(.sameSiteNone)         { penalty += -5 }
//        if flags.contains(.expired)              { penalty += -1 }
        if flags.contains(.setOnRedirect)        { penalty += -2}
        
        return max(penalty, -100)
    }
    
    static func getPenaltyAndSeverity(name: String) -> (penalty: Int, severity: SecurityWarning.SeverityLevel) {
        switch name {
        case "eval", "window[\"eval\"]":
            return (PenaltySystem.Penalty.critical, .critical)
        case "atob", "btoa", "fetch", "xmlhttprequest", "window.open", "document.write":
            return (PenaltySystem.Penalty.hightPenaltyForInlineJS, .dangerous)
        case "location.href":
            return (PenaltySystem.Penalty.hightPenaltyForInlineJS, .dangerous)
        case "location.replace", "location.assign", "getElementById":
            return (PenaltySystem.Penalty.mediumPenaltyForInlineJS, .suspicious)
        case "innerhtml", "outerhtml", "unescape", "escape":
            return (PenaltySystem.Penalty.mediumPenaltyForInlineJS, .suspicious)
        case "console.log":
            return (PenaltySystem.Penalty.lowPenaltyForInlineJS, .info)
        case "cookie":
            return (PenaltySystem.Penalty.jsCookieAccess, .dangerous)
        case "localStorage":
            return (PenaltySystem.Penalty.jsStorageAccess, .suspicious)
        case "setItem":
            return (PenaltySystem.Penalty.jsSetItemAccess, .suspicious)
        case "WebAssembly":
            return (PenaltySystem.Penalty.jsWebAssembly, .dangerous)
        default:
            return (-10, .suspicious)
        }
    }
    
    
}
