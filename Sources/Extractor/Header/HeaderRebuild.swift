////
////  Rebuild.swift
////  LegitURL
////
////  Created by Chief Hakka on 05/05/2025.
////
//

import Foundation
//TODO: The structureCSP should be return as a full string, and not data?
struct HeaderRebuild {
    static func build(from headers: [String: String],
                      cookies: [HTTPCookie],
                      StructuredCSP: [String: [Data: CSPValueType]]?, onlineInfo: inout OnlineURLInfo) {
        // Reconstruct the parsed headers for UI
        let cleanlyFormattedCSPString: String = {
            guard let StructuredCSP = StructuredCSP else { return "Not available." }
            var output: [String] = []
            for (directive, values) in StructuredCSP {
                let decoded = values.keys.compactMap { String(data: $0, encoding: .utf8) }
                //Empty value directive : upgrade-insecure-requests ? block all mixed content
                if decoded.isEmpty {
                    output.append(directive)
                } else {
                    output.append("\(directive): \(decoded.joined(separator: " "))")
                }
            }
            return output.joined(separator: "\n")
        }()

        let formattedCookies: String = cookies.map { cookie in
            var parts = ["\(cookie.name)=\(cookie.value)"]
            parts.append("Path=\(cookie.path)")
            if cookie.isSecure { parts.append("Secure") }
            if cookie.isHTTPOnly { parts.append("HttpOnly") }
            //Date is not a string, date is not a string, date is not a string, date is not a string
            if let expires = cookie.expiresDate {
                let formatter = DateFormatter()
                formatter.dateFormat = "E, dd MMM yyyy HH:mm:ss zzz"
                formatter.locale = Locale(identifier: "en_US")
                formatter.timeZone = TimeZone(secondsFromGMT: 0)
                parts.append("Expires=\(formatter.string(from: expires))")
            }
            return parts.joined(separator: "; ")
        }.joined(separator: "\n")

        var mergedHeaders = headers
        //only merge the correct CSP !!
        if headers.keys.contains(where: { $0.lowercased() == "content-security-policy" }) {
            mergedHeaders["content-security-policy"] = cleanlyFormattedCSPString
        } else if headers.keys.contains(where: { $0.lowercased() == "content-security-policy-report-only" }) {
            mergedHeaders["content-security-policy-report-only"] = cleanlyFormattedCSPString
        }
        if headers.keys.contains(where: {$0.lowercased() == "set-cookie"}){
            mergedHeaders["set-cookie"] = formattedCookies            
        }

        let parsed = parseHeaders(mergedHeaders)
        onlineInfo.parsedHeaders = parsed
    }
    
    private static func parseHeaders(_ responseHeaders: [AnyHashable: Any]) -> ParsedHeaders {
        var normalizedHeaders: [String: [String]] = [:]

        for (key, value) in responseHeaders {
            guard let keyString = key as? String else { continue }
            let lowerKey = keyString.lowercased()
            let valueString = "\(value)"

            if normalizedHeaders[lowerKey] != nil {
                normalizedHeaders[lowerKey]?.append(valueString)
            } else {
                normalizedHeaders[lowerKey] = [valueString]
            }
        }

        var parsedHeaders = ParsedHeaders()

        for (key, values) in normalizedHeaders {
            switch key {
            case "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
                 "x-frame-options", "x-content-type-options", "referrer-policy":
                parsedHeaders.securityHeaders[key] = values.joined(separator: "\n")
            case "set-cookie", "etag", "permissions-policy":
                parsedHeaders.trackingHeaders[key] = values.joined(separator: "\n")
            case "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version":
                parsedHeaders.serverHeaders[key] = values.joined(separator: "\n")
            default:
                parsedHeaders.otherHeaders[key] = values.joined(separator: "\n")
            }
        }
        return parsedHeaders
    }
}
//onlineInfo.parsedHeaders = ParsedHeaders(
//    securityHeaders: [
//        "content-security-policy": cleanlyFormattedCSPString,
//        ...
//    ],
//    trackingHeaders: [
//        "set-cookie": cookies.map { formatSetCookieLine($0) }.joined(separator: "\n")
//    ],
//    serverHeaders: [
//        "server": normalizedHeaders["server"] ?? ""
//    ],
//    otherHeaders: remainingUnclassifiedHeaders
//)
//
//
//func formatSetCookieLine(_ cookie: HTTPCookie) -> String {
//    var parts = ["\(cookie.name)=\(cookie.value)"]
//    parts.append("Path=\(cookie.path)")
//    if cookie.isSecure { parts.append("Secure") }
//    if cookie.isHTTPOnly { parts.append("HttpOnly") }
//    if let expires = cookie.expiresDate {
//        let formatter = DateFormatter()
//        formatter.dateFormat = "E, dd MMM yyyy HH:mm:ss zzz"
//        formatter.locale = Locale(identifier: "en_US")
//        formatter.timeZone = TimeZone(secondsFromGMT: 0)
//        parts.append("Expires=\(formatter.string(from: expires))")
//    }
//    return parts.joined(separator: "; ")
//}
