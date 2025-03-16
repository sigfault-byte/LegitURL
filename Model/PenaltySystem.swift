struct PenaltySystem {
    public enum Penalty {
       // 🔴 CRITICAL ISSUES
        static let critical                            = -100

       // 🌍 HOST-RELATED PENALTIES
        static let unrecognizedTLD                     = -70
        static let hostIsIpAddress                     = -50
        static let homoGraphAttack                     = -50
        static let malformedURL                        = -50
        static let passwordInHost                      = -30
        static let unusualPort                         = -30
        static let phishingWordsInHost                 = -20
        static let scamWordsInHost                     = -20
        static let tooManyHyphensInDomain              = -20
        static let suspiciousTLD                       = -20
        static let shortSubdomain                      = -10
        static let tooManySubdomain                    = -15
        static let hostNonASCII                        = -10
        static let domainNonASCII                      = -10

       // 🔀 REDIRECTION & OBFUSCATION
        static let hiddenRedirectFragment              = -40
        static let hiddenRedirectQuery                 = -30
        static let phpRedirect                         = -25
        static let suspiciousRedirect                  = -10

       // 🛤 PATH-RELATED PENALTIES
        static let highEntropyPathComponent            = -10
        static let scamWordsInPath                     = -10
        static let phishingWordsInPath                 = -5
        static let suspiciousPathSegment               = -5

       // ❓ QUERY-RELATED PENALTIES
        static let urlInQueryValue                     = -20
        static let urlInQueryKey                       = -20
        static let trackingMonitoring                  = -20
        static let malformedQuery                      = -20
        static let phishingWordsInKey                  = -15
        static let phishingWordsInValue                = -15
        static let scammingWordsInKey                  = -15
        static let scammingWordsInValue                = -15
        static let jsRedirectInKey                     = -15
        static let jsRedirectInValue                   = -15
        static let malformedQueryPair                  = -20
        static let fragementLikeQuery                  = -20
        static let malformedFragment                   = -10
        static let hiddenKeyValue                      = -15
        static let queryNotRFCCompliant                = -10
        static let emptyQueryString                    = -5
        static let emptyFragment                       = -5
        static let highEntropyKeyOrValue               = -5
        static let longQuery                           = -5

       // 🔧 JAVASCRIPT & SECURITY ISSUES
        static let javascriptXSS                       = -30
        static let deepObfuscation                     = -20
        static let suspiciousPattern                   = -15
        static let base64Url                           = -10

       // 🆗 INFORMATIVE (No penalty)
        static let informational                       = 0
       }
    
    // ✅ Suspicious TLDs and their penalties
    static let suspiciousTLDs: [String: Int] = [
        ".tk": -20, ".ml": -20, ".ga": -20, ".cf": -20, ".gq": -20,
        ".top": -20, ".xyz": -20, ".ru": -20, ".cn": -20, ".cc": -20,
        ".pw": -20, ".biz": -20, ".ws": -20, ".info": -20, ".review": -20,
        ".loan": -20, ".download": -20, ".trade": -20, ".party": -20,
        ".click": -20, ".country": -20, ".kim": -20, ".men": -20, ".date": -20,
        ".gdn": -20, ".stream": -20, ".cam": -20, ".cricket": -20, ".space": -20,
        ".fun": -20, ".site": -20, ".best": -20, ".world": -20, ".shop": -20,
        ".gifts": -20, ".beauty": -20, ".zip": -20, ".mov": -20, ".live": -20
    ]
}
