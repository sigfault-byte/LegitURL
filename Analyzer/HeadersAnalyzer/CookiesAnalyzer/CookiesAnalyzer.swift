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
//  Might need a set for know cookis, session is ok, but fuck java session cookis, java is a small tell the server is from a script scam kit...
//
//•    sessionid, sid, sess, JSESSIONID, PHPSESSID, etc.
//•    Marketing/Tracking:
//•    utm_, fbp, _ga, _gid, _gcl_au, _gat, ajs_user_id
//•    cluid, visitor_id, trackid, tracker, campaign, click_id
//•    Analytics:
//•    _ga, _gid, __utm, __hssc, __hstc, __cf_bm
//•    Adtech:
//•    ads/, ad_id, affiliate_id, pixel_id
import Foundation

struct CookiesAnalyzer {
    static func analyzeAll(from headersCookies: [String]?,
                           httpResponseCode: Int,
                           url: String,
                           urlInfo: inout URLInfo) -> Void {
        guard let headersCookies = headersCookies, !headersCookies.isEmpty else {
            return
        }
        
        // Parse each Set-Cookie header into CookieMetadata
        let parsedCookies: [CookieMetadata] = parseCookies(from: headersCookies, for: url)
        let numberOfCookies: Int = parsedCookies.count
        let coreURL = urlInfo.components.coreURL ?? ""
        
        //        The size of the cookie is tied to the granularity of info it stores.
        //        let suspicionIndex = (avgCookieSize * Double(numberOfCookies)) / (httpResponseCode != 200 ? 1.5 : 3.0)
        //        let totalSize = headersCookies.reduce(0) { $0 + $1.utf8.count }
        let totalValueSize = parsedCookies.reduce(0) {$0 + $1.value.utf8.count}
        let avgCookieSize = Double(totalValueSize) / Double(numberOfCookies)
        //        Google = grandma of internet, they do not give cookies on a 3xx. If even Google doesn’t do it, no one should.
        if httpResponseCode != 200 {
            urlInfo.warnings.append(SecurityWarning(
                message: "Cookies averaging \(avgCookieSize) bytes set during a redirect or error (code \(httpResponseCode)). \(totalValueSize) bytes total of cookies.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.cookiesOnNon200,
                url: coreURL,
                source: .cookie
            ))
            //Todo => scoring logic and penalty: suspicionIndex ?
        }
        
        //tracking but on a 200 is Okayish
        if httpResponseCode == 200 && avgCookieSize >= 16 {
            urlInfo.warnings.append(SecurityWarning(
                message: "Cookies averaging \(avgCookieSize) bytes. \(totalValueSize) bytes total of cookies.",
                severity: .tracking,
                penalty: PenaltySystem.Penalty.moreThan16BofCookie,
                url: coreURL,
                source: .cookie
            ))
        }
        //Todo => scoring logic and penalty: suspicionIndex
        
        // Per-cookie analysis
        for cookie in parsedCookies {
            let result = analyzeCookie(cookie, httpResponseCode: httpResponseCode)
            let combinedFlags = result.flags.joined(separator: ", ")
            let penalty = PenaltySystem.penaltyForCookieFlags(result.flags)

            urlInfo.warnings.append(SecurityWarning(
                message: "Cookie `\(cookie.name)` flagged as \(result.severity). Reasons: \(combinedFlags).",
                severity: result.severity,
                penalty: penalty,
                url: url,
                source: .cookie
            ))
            //TODO: this is surely very wrong! it throwse on the setter. Need to fix ASAP
            urlInfo.onlineInfo?.cookiesForUI.append(result)
            
        }
    }
}
