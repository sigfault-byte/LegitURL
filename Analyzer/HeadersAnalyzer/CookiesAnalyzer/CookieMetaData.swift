//  CookieMetaData.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//

import Foundation
let trackingKeywords = Set(["sessionid", "sid", "sess", "jsessionid", "phpsessid", "utm_", "fbp", "_ga", "_gid", "_gcl_au", "_gat", "ajs_user_id", "cluid", "visitor_id", "trackid", "tracker", "campaign", "click_id", "__utm", "__hssc", "__hstc", "__cf_bm", "ads", "ad_id", "affiliate_id", "pixel_id"])

typealias CookieSeverity = SecurityWarning.SeverityLevel


struct CookieMetadata: Hashable{
    let name: String
    let value: String
    let domain: String
    let path: String
    let expire: Date?
    let sameSite: String // "Lax", "Strict", or "None"
    let secure: Bool
    let httpOnly: Bool
    let comment: String?
    let commentURL: URL?
    let version: Int
    let portList: [NSNumber]?
}

func populateCookieMetadata(_ cookie: HTTPCookie) -> CookieMetadata {
    return CookieMetadata(
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        expire: cookie.expiresDate,
        sameSite: cookie.sameSitePolicy?.rawValue ?? "Lax",
        secure: cookie.isSecure,
        httpOnly: cookie.isHTTPOnly,
        comment: cookie.comment,
        commentURL: cookie.commentURL,
        version: cookie.version,
        portList: cookie.portList
    )
}

func parseCookies(from headers: [String], for url: String) -> [CookieMetadata] {
    guard let urlObject = URL(string: url) else {
        print("Invalid URL format: \(url)")
        return []
    }

    var allCookies: [CookieMetadata] = []

    for cookieString in headers {
        let singleHeader = ["Set-Cookie": cookieString]
        let parsed = HTTPCookie.cookies(withResponseHeaderFields: singleHeader, for: urlObject)
        allCookies.append(contentsOf: parsed.map { populateCookieMetadata($0) })
    }

    return allCookies
}
