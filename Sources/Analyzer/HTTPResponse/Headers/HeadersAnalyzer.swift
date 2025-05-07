//
//  HeadersAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 20/03/2025.
//
struct HeadersAnalyzer {
    static func analyze(responseHeaders: [String: String], urlOrigin: String, responseCode: Int) -> [SecurityWarning] {
        //        Only evaluate 200 code response, other repsponse need a different logic.
        //        particulary the 302 found common in scam and compromised CRM used as proxies
        guard responseCode == 200 else {
            return []
        }
        
        var warnings: [SecurityWarning] = []
        
        //hsts
        warnings.append(contentsOf: HeadersUtils.checkStrictTransportSecurity(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        // content type & content type otptions
        warnings.append(contentsOf: HeadersUtils.checkContentTypeOption(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        // content len, missing real content value to cross check
        warnings.append(contentsOf: HeadersUtils.checkContentLength(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        // cache control -> tricky part that d benefit from an exhaustive list of the cache control keys of known CDNs
//        TODO: cache Control
        //referer-policy
        warnings.append(contentsOf: HeadersUtils.checkReferrerPolicy(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        
        warnings.append(contentsOf: HeadersUtils.checkServerLeak(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        
        return warnings
    }
    
   
    
    
}

//    // ✅ **Function to check cookie security flags**
//    private static func checkCookieSecurityFlags(responseHeaders: [String: String], urlInfo: inout URLInfo) {
//        if let cookies = responseHeaders["Set-Cookie"] {
//            let cookieValues = cookies.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
//            if !cookieValues.contains("Secure") || !cookieValues.contains("HttpOnly") {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "⚠️ Cookie is missing Secure or HttpOnly flag: \(cookies). This could allow session hijacking.",
//                    severity: .suspicious
//                ))
//            }
//
//            // ✅ Check entropy of cookie value to detect randomness
//            let (isHighEntropy, entropyValue) = LegitURLTools.isHighEntropy(cookies)
//            if isHighEntropy {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "⚠️ High entropy detected in Set-Cookie value (Entropy: \(String(format: "%.2f", entropyValue ?? 0))). This could indicate a session token or tracking ID.",
//                    severity: .suspicious
//                ))
//            }
//        }
//    }
//
//    // ✅ **Function to detect server misconfigurations**
//    private static func detectServerMisconfigurations(responseHeaders: [String: String], urlInfo: inout URLInfo) {
//        if let serverHeader = responseHeaders["Server"] {
//            let outdatedIndicators = ["Apache/2.2", "PHP/5.3", "IIS/6.0"] // Example outdated versions
//            for indicator in outdatedIndicators {
//                if serverHeader.contains(indicator) {
//                    urlInfo.warnings.append(SecurityWarning(
//                        message: "🚨 Outdated server detected: \(serverHeader). This could be vulnerable to known exploits.",
//                        severity: .dangerous
//                    ))
//                }
//            }
//        }
//
//        // ✅ Check for verbose headers leaking too much info
//        let verboseHeaders = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
//        for verboseHeader in verboseHeaders {
//            if let value = responseHeaders[verboseHeader] {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "⚠️ Verbose server information exposed in \(verboseHeader): \(value).",
//                    severity: .suspicious
//                ))
//            }
//        }
//
//        // ✅ Check for potential Content-Type mismatches
//        if let contentType = responseHeaders["Content-Type"] {
//            let disallowedTypes = ["text/html", "application/javascript"]
//            if disallowedTypes.contains(contentType), responseHeaders["Content-Disposition"]?.contains("attachment") == true {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "🚨 Content-Disposition set to 'attachment' for \(contentType). This could be an attempt to force a malicious download.",
//                    severity: .critical
//                ))
//            }
//        }
//    }
//    //}
//
//    These headers enhance security and should be present:
//        •    "strict-transport-security" (HSTS)
//        •    "content-security-policy" (CSP)
//        •    "x-frame-options" (Prevents clickjacking)
//        •    "x-content-type-options" (Prevents MIME-type sniffing)
//        •    "referrer-policy" (Controls referrer leakage)
//        •    "permissions-policy" (Restricts browser features)
//        •    "cross-origin-embedder-policy"
//        •    "cross-origin-opener-policy"
//        •    "cross-origin-resource-policy"
//        •    "origin-agent-cluster"
//
//    If any of these are missing, we flag it!
//
//    ⸻
//
//    Tracking & Potential Privacy Risks
//
//    These headers indicate tracking, session behavior, or analytics:
//        •    "set-cookie" (Session persistence)
//        •    "etag" (Can be abused for tracking)
//        •    "permissions-policy" (Can also be abused)
//        •    "report-to" / "nel" (Network error logging, could track user failures)
//
//    If found, we log them, but they aren’t automatically bad.
//
//    ⸻
//
//    Server Exposure (Bad)
//
//    These headers expose information about the web server:
//        •    "server" (Should be hidden)
//        •    "x-powered-by" (Tells us the backend tech)
//        •    "x-aspnet-version"
//        •    "x-aspnetmvc-version"
//        •    "x-generator" (CMS like WordPress, Drupal)
//        •    "x-drupal-cache" (Drupal-specific)
//        •    "x-backend-server" (Exposes infrastructure)
//
//    If found, we penalize based on content.
//        •    Apache/Nginx? Minor penalty (-5)
//        •    Exposed framework (Express, Django, etc.)? Major penalty (-15)
//        •    PaaS hosting (Vercel, Firebase, etc.)? Moderate penalty (-10)
