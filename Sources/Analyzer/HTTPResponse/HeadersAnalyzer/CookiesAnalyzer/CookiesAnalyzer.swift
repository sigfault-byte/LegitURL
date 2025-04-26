//
//  CookiesAnalyzer.swift
//  URLChecker
//
//  Created by Chief Hakka on 06/04/2025.
//
// The point is trying to see how the cookies are used.
// Response header http code is important, a fullblown cookie fest on anything other than a 200 is sus
//    0–200 bytes: fine
//    200–500: mild warning
//    500–1000: suspicious
//    1000–2000+: tracking overload
//  SameSite=None without Secure -> dangerous
//  SameSite=None + cross-domain cookie name -> tracking fest
//  Long expiry dates (Expires or Max-Age) -> persistent tracking / finger printing
//  How to differentiate scam tactics from "legitimate" tracking for ads and marketting? Looks like they have the same markers...
//  -> maybe: track entropy, cookie naming, volume, and possibly domain age + cert info later for tie-breakers.

import Foundation

struct CookiesAnalyzer {
    static func analyzeAll(from headersCookies: [String]?,
                           httpResponseCode: Int,
                           url: String,
                           urlInfo: inout URLInfo,
                           onlineInfo: inout OnlineURLInfo) -> Void {
        guard let headersCookies = headersCookies, !headersCookies.isEmpty else {
            return
        }
        
        let hostRef =  urlInfo.components.host ?? ""
        
        // Parse each Set-Cookie header into CookieMetadata
        let parsedCookies: [CookieMetadata] = parseCookies(from: headersCookies, for: url)
        let numberOfCookies: Int = parsedCookies.count
        let coreURL = urlInfo.components.coreURL ?? ""
        
        let totalValueSize = parsedCookies.reduce(0) {$0 + $1.value.utf8.count}
        let avgCookieSize = Double(totalValueSize) / Double(numberOfCookies)

        if httpResponseCode != 200 {
            let severity: SecurityWarning.SeverityLevel
            let extraNote: String

            switch avgCookieSize {
            case 0...20:
                severity = .info
                extraNote = " (small average cookie size)"
            case 21...60:
                severity = .suspicious
                extraNote = " (moderate avg cookie size)"
            case 61...100:
                severity = .tracking
                extraNote = " (large avg size — may indicate tracking)"
            default:
                severity = .dangerous
                extraNote = " (extremely large avg size — likely tracking/fingerprinting)"
            }

            urlInfo.warnings.append(SecurityWarning(
                message: "Cookies set during a non-200 response (code \(httpResponseCode)), averaging \(String(format: "%.1f", avgCookieSize)) bytes across \(numberOfCookies) cookies.\(extraNote)",
                severity: severity,
                penalty:  0, /*Penalzised on individual cookie*/
                url: coreURL,
                source: .cookie
            ))
        }
        
        // Per-cookie analysis
        for cookie in parsedCookies {
            let globalSeenCookies = URLQueue.shared.cookiesSeenByRedirectChain.values.reduce(into: Set<String>()) { $0.formUnion($1) }
            let result = analyzeCookie(cookie,
                                       httpResponseCode: httpResponseCode,
                                       seenCookie: globalSeenCookies,
                                       host: hostRef)
//            let penalty = PenaltySystem.penaltyForCookieBitFlags(result.flags)
            let reasons = result.flags.descriptiveReasons().joined(separator: ", ")
            let penalty = PenaltySystem.penaltyForCookieBitFlags(result.flags)
            urlInfo.warnings.append(SecurityWarning(
                message: "Cookie `\(cookie.name)` flagged as \(result.severity). Reasons: \(reasons).",
                severity: result.severity,
                penalty: penalty,
                url: url,
                source: .cookie
            ))
            
            URLQueue.shared.cookiesSeenByRedirectChain[urlInfo.id, default: Set<String>()].insert(cookie.name)
            onlineInfo.cookiesForUI.append(result)
        }
    }
}
