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
        static let pathHasExecutable                   = -20
        static let pathIsEndpointLike                  = -10
        static let highEntropyPathComponent            = -10
        static let scamWordsInPath                     = -10
        static let phishingWordsInPath                 = -10
        static let suspiciousPathSegment               = -10
        static let containBrandInPath                  = -5
        static let brandLookaLikeInPath                = -5
        
        // QUERIES & fragment ... Need granularity see lamai todo
        static let malformedQueryPair                  = -40
        static let highEntropyQuery                    = -15
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
        
        //InlineSpecific JS penalty
        static let hightPenaltyForInlineJS            = -30
        static let mediumPenaltyForInlineJS           = -15
        static let lowPenaltyForInlineJS              = -5
        
        ///Cookie////
        static let cookiesOnNon200                     = -20
        static let moreThan64BofCookie                 = -15
        static let moreThan16BofCookie                 = -5
        ///TLS///
        static let tksWeakKey                          = -20
        static let unknownVL                           = -10
        static let hotDogwaterCN                       = -10
        static let tlsWillExpireSoon                   = -10
        static let tlsIsNew                            = -10
        static let tlsShortLifespan                    = -10
        
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
        var penalty = 0
        if flags.contains(.cookieOnRedirect) {
            penalty -= 5
        }
        if flags.contains(.samesiteNone)         { penalty += -15 }
        
//         full exposure -> terrible cookie, critical score
        if flags.contains([.samesiteNone, .secureMissing, .httpOnlyMissing]) {
            return Penalty.critical
        }
//        if already seen, no penalty again
        if flags.contains(.reusedAccrossRedirect) {
            return 0
        }
        
        // cleaning cookie, whatever the size if httponly is set, the cookie is harmless.
        if flags.contains(.expired) && !flags.contains(.httpOnlyMissing) {
            return penalty
        }
        
        // Secure session cookie with any size not a fingerprint
        if flags.contains(.sessionCookie )
            && !flags.contains(.fingerprintStyle)
            && !flags.contains(.httpOnlyMissing)
            && !flags.contains(.secureMissing) {
            return penalty
        }
        
        if flags.contains([.shortLivedPersistent]) && !flags.contains([.httpOnlyMissing, .secureMissing])  {
            penalty -= 5
            return penalty
        }
        
        // Harmless but bad practice
        if flags.contains(.smallCookie) && (flags.contains(.httpOnlyMissing) || !flags.contains(.secureMissing)) {
            if flags.contains(.persistent) {
                penalty -= 5
            }
            penalty -= 5
            return penalty
        }
        
        //// Possibly CSRF-style token, intentionally readable by JS
        if flags.contains(.mediumCookie)
           && flags.contains(.persistent)
           && !flags.contains(.secureMissing)
           && flags.contains(.httpOnlyMissing)
           && !flags.contains(.highEntropyValue) {
            penalty -= 5
            return penalty
        }
        
        //        legit secure tracking
        if flags.contains(.persistent) && flags.contains(.highEntropyValue) && !flags.contains(.httpOnlyMissing) && !flags.contains(.secureMissing){
            penalty = -5
            return penalty
        }
        
//        leaky persistent trackcing
        if flags.contains(.persistent) && flags.contains(.highEntropyValue) && flags.contains(.httpOnlyMissing){
            penalty -= 20
            return penalty
        }
        
        if flags.contains(.shortLivedPersistent) && flags.contains(.httpOnlyMissing) && flags.contains(.secureMissing){
            penalty -= 15
            return penalty
        }
    
        if flags.contains([.largeValue, .persistent]) {
            if flags.contains([.httpOnlyMissing, . secureMissing]) {
                penalty -= 10
            }
            penalty -= 5
            return penalty
        }
        
//        Secure Heavy tracking fingerprint
        if flags.contains(.fingerprintStyle) && !flags.contains(.httpOnlyMissing) && !flags.contains(.secureMissing){
            penalty -= 15
            return penalty
        }
        
        if flags.contains(.fingerprintStyle) && !flags.contains(.httpOnlyMissing) && flags.contains(.secureMissing){
            penalty -= 20
            return penalty
        }
        
        if flags.contains(.fingerprintStyle) && flags.contains(.httpOnlyMissing) {
            penalty -= 25
            return penalty
        }
        
        if flags.contains(.secureMissing)        { penalty += -15 }
        if flags.contains(.httpOnlyMissing)      { penalty += -15 }
        if flags.contains(.largeValue)           { penalty += -10 }
        if flags.contains(.highEntropyValue)     { penalty += -5 }
        if flags.contains(.persistent)           { penalty += -5 }
        if flags.contains(.shortLivedPersistent) { penalty += -5 }

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
