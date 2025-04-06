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

struct CookiesAnalyzer {
    static func analyze(from headers: [String: String], warnings : [SecurityWarning]) -> Void {
        
        
    }
}

//
//•    checkKnownTrackingKeys(cookie:)
//•    calculateTotalCookieSize(headers:)
//•    evaluateCookieAttributes(cookie:)
