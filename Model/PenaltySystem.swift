struct PenaltySystem {
    public enum Penalty {
       // 🔴 CRITICAL ISSUES
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
        static let pathIsEndpointLike                  = -15
        static let highEntropyPathComponent            = -10
        static let scamWordsInPath                     = -10
        static let phishingWordsInPath                 = -10
        static let suspiciousPathSegment               = -10
        static let exactBrandInPath                    = -5
        static let containBrandInPath                  = -5
        
        // QUERIES & fragment ... Need granularity see lamai todo
        static let malformedQueryPair                  = -40
        static let highEntropyQuery                    = -30
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
        static let jsEvalInBody                        = -30
        static let jsFingerPrinting                    = -30
        static let hotdogWaterDev                      = -30
        static let metaRefreshInBody                   = -25
        static let jsWindowsRedirect                   = -20
        static let scriptIs50Percent                   = -20
        static let scriptIs30Percent                   = -10
        static let extScriptSrc                        = -10
        ///Cookie////
        static let cookiesOnNon200                     = -20
        static let moreThan16BofCookie                 = -15
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
}
extension PenaltySystem {
    static func penaltyForCookieFlags(_ flags: [String]) -> Int {
        var penalty = 0

        for flag in flags {
            if flag.contains("Secure flag missing on SameSite=None") {
                penalty += 40
            } else if flag.contains("High-entropy value") {
                penalty += 20
            } else if flag.contains("Large fingerprint-style") {
                penalty += 25
            } else if flag.contains("Persistent cookie") {
                penalty += 10
            } else if flag.contains("cross-site access") {
                penalty += 10
            } else if flag.contains("Secure flag missing") {
                penalty += 15
            } else if flag.contains("opaque identifier") || flag.contains("UUID") {
                penalty += 10
            }
//                else if flag.contains("Tiny sessionless cookie") {
//                penalty -= 10 // 🟢 possible bonus
//            }
        }

        return min(max(penalty, -100), 100) // Clamp to avoid score abuse
    }
}
