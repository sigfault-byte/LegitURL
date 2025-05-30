//
//  CookiesAnalyzer.swift
//  LegitURL
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
//
// httpCookie makes no difference between sameSitePolicy = none and nil.
// The browser patched it themselves in ~2020. Still if someone uses cookie, it should be correctly configured, or assume that samesite=none is defaul
import Foundation

struct CookiesAnalyzer {
    static func analyzeAll(from headersCookies: [HTTPCookie]?,
                           httpResponseCode: Int,
                           url: String,
                           urlInfo: inout URLInfo,
                           onlineInfo: inout OnlineURLInfo) -> Void {
        guard let headersCookies = headersCookies, !headersCookies.isEmpty else {
            return
        }
        
        let hostRef =  urlInfo.components.host ?? ""
        
        let numberOfCookies: Int = headersCookies.count
        let coreURL = urlInfo.components.coreURL ?? ""
        
        let totalValueSize = headersCookies.reduce(0) { $0 + $1.value.utf8.count }
        let jsCookieExposed = headersCookies.contains { !$0.isHTTPOnly }
        let cookieFlags: WarningFlags = jsCookieExposed ? [.COOKIE_JS_ACCESS] : []
//        print("IS COOKIE JS: ", jsCookieExposed)

        if httpResponseCode != 200 {
            let severity: SecurityWarning.SeverityLevel
            let extraNote: String

            switch Double(totalValueSize) / Double(numberOfCookies) {
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
                message: "Cookies set during a non-200 response (code \(httpResponseCode)), averaging \(String(format: "%.1f", Double(totalValueSize) / Double(numberOfCookies))) bytes across \(numberOfCookies) cookies.\(extraNote)",
                severity: severity,
                penalty:  0, /*Penalzised on individual cookie*/
                url: coreURL,
                source: .cookie,
                bitFlags: cookieFlags
            ))
        }
        
        // Per-cookie analysis
        for cookie in headersCookies {
            let globalSeenCookies = URLQueue.shared.cookiesSeenByRedirectChain.values.reduce(into: Set<String>()) { $0.formUnion($1) }
            let metadata = populateCookieMetadata(cookie)
            let result = analyzeCookie(metadata,
                                       httpResponseCode: httpResponseCode,
                                       seenCookie: globalSeenCookies,
                                       host: hostRef)

            let reasons = result.flags.descriptiveReasons().joined(separator: ", ")
            let penalty = PenaltySystem.penaltyForCookieBitFlags(result.flags)
            var warningFlags: WarningFlags = [cookieFlags]

            switch result.severity {
            case .suspicious, .tracking:
                warningFlags.insert(.COOKIE_TRACKING)
            case .dangerous:
                warningFlags.insert(.COOKIE_DANGEROUS)
            default:
                break
            }

            urlInfo.warnings.append(SecurityWarning(
                message: "Cookie `\(metadata.name)` flagged as \(result.severity). Reasons: \(reasons).",
                severity: result.severity,
                penalty: penalty,
                url: url,
                source: .cookie,
                bitFlags: warningFlags
            ))

            URLQueue.shared.cookiesSeenByRedirectChain[urlInfo.id, default: Set<String>()].insert(metadata.name)
            var resultWithRaw = result
            resultWithRaw.cookie = metadata
            onlineInfo.cookiesForUI.append(resultWithRaw)
        }
    }
}
