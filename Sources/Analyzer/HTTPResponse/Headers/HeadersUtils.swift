//
//  HeadersUtils.swift
//  LegitURL
//
//  Created by Chief Hakka on 27/04/2025.
//
struct HeadersUtils {
//    This needs a lot of more thinkerign, likely needs a list or find a heuristic to detect patterns.
//    A leaky server is a tell
    static func checkServerLeak(responseHeaders: [String: String], urlOrigin: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []
        
        if let serverHeader = responseHeaders.first(where: { $0.key.caseInsensitiveCompare("Server") == .orderedSame })?.value {
            
            if serverHeader.contains("/") {
                // Assume server name + version leak
                warnings.append(SecurityWarning(
                    message: "Server leaks name and version: \(serverHeader).",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.serverLeakNameAndVersion,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_LEAK_SERVER_VERSION]
                ))
            }
//            Inconsistent and somehow also interesting, but only if the name s relevant...
//            else {
//                // Only server name leaked
//                warnings.append(SecurityWarning(
//                    message: "Server leaks its name: \(serverHeader).",
//                    severity: .info,
//                    penalty: PenaltySystem.Penalty.informational,
//                    url: urlOrigin,
//                    source: .header,
//                ))
//            }
        }
        
        return warnings
    }
    
    
//    HSTS checks, its basic. There migh be some way to give rewards. But this is infently easy to implement.
    public static func checkStrictTransportSecurity(responseHeaders: [String: String], urlOrigin: String) -> [SecurityWarning] {
        // Check HSTS (Strict-Transport-Security)
        var warnings: [SecurityWarning] = []
        if let hsts = responseHeaders.first(where: { $0.key.lowercased() == "strict-transport-security" })?.value {
            if hsts.lowercased().contains("max-age=") {
                // Check if the max-age value is sufficiently long (at least 6 months)
                let maxAgeMatch = hsts.range(of: #"max-age=(\d+)"#, options: .regularExpression)
                if let match = maxAgeMatch,
                   let maxAgeValue = Int(hsts[match].split(separator: "=").last ?? ""),
                   maxAgeValue >= 10886400 {
                    warnings.append(SecurityWarning(
                        message: "HSTS header is present with a strong max-age.",
                        severity: .info,
                        penalty: 0,
                        url: urlOrigin,
                        source: .header
                    ))
                } else {
                    warnings.append(SecurityWarning(
                        message: "HSTS header is present but the max-age is low.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.lowHSTSValue,
                        url: urlOrigin,
                        source: .header
                    ))
                }
            } else {
                warnings.append(SecurityWarning(
                    message: "HSTS header is present but malformed — missing max-age directive.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.missingHSTS,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_MISSING_HSTS]
                ))
            }
            if hsts.lowercased().contains("max-age=") {
                // Already checked, good.
                
                if hsts.lowercased().contains("includesubdomains") {
                    warnings.append(SecurityWarning(
                        message: "HSTS includeSubDomains directive is present.",
                        severity: .info,
                        penalty: PenaltySystem.Penalty.informational, // mb reward for a unfortunalty rare value ?
                        url: urlOrigin,
                        source: .header
                    ))
//                    TODO: Need to tinker this, night be a reward. Might be entirely uselee. These keywaords are too rare... So a positive signal  maybe.
//                } else {
//                    warnings.append(SecurityWarning(
//                        message: "HSTS is missing includeSubDomains directive. Subdomains are not protected against downgrade attacks.",
//                        severity: .suspicious,
//                        penalty: PenaltySystem.Penalty.lowHSTSValue, // or a slightly lower penalty
//                        url: urlOrigin,
//                        source: .header
//                    ))
//                }
                
//                if hsts.lowercased().contains("preload") {
//                    warnings.append(SecurityWarning(
//                        message: "HSTS preload directive detected. Site is eligible for HSTS preload list.",
//                        severity: .info,
//                        penalty: 0,
//                        url: urlOrigin,
//                        source: .header
//                    ))
                }
            }
        } else {
            warnings.append(SecurityWarning(
                message: "Missing HSTS (Strict-Transport-Security) header.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.missingHSTS,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_MISSING_HSTS]
            ))
        }
        
        
        return warnings
    }
    
    static func checkContentTypeOption(responseHeaders: [String: String], urlOrigin: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []
        
        let contentType = responseHeaders.first(where: { $0.key.lowercased() == "content-type" })?.value
        let xContentTypeOptions = responseHeaders.first(where: { $0.key.lowercased() == "x-content-type-options" })?.value
        
        if contentType == nil {
            warnings.append(SecurityWarning(
                message: "Missing Content-Type header.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.inccorectLogic,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_INCORRECT_LOGIC]
            ))
        } else if !contentType!.lowercased().contains("text/html") {
            warnings.append(SecurityWarning(
                message: "Unexpected Content-Type: \(contentType!). Expected 'text/html' for a page load.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.inccorectLogic,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_INCORRECT_LOGIC]
            ))
        }
        
        if let xcto = xContentTypeOptions {
            if xcto.lowercased() != "nosniff" {
                warnings.append(SecurityWarning(
                    message: "X-Content-Type-Options header is misconfigured: '\(xcto)'. Expected 'nosniff'.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.inccorectLogic,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_INCORRECT_LOGIC]
                ))
            }
            
            if contentType == nil {
                warnings.append(SecurityWarning(
                    message: "X-Content-Type-Options is set but Content-Type is missing.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.inccorectLogic,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_INCORRECT_LOGIC]
                ))
            }
        } else {
            warnings.append(SecurityWarning(
                message: "Missing X-Content-Type-Options header.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.inccorectLogic,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_INCORRECT_LOGIC]
            ))
        }
        
        return warnings
    }
    
    static func checkContentLength(responseHeaders: [String: String], urlOrigin: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []
        
        if let contentLengthValue = responseHeaders.first(where: { $0.key.lowercased() == "content-length" })?.value,
           let contentLengthInt = Int(contentLengthValue) {
            
            if contentLengthInt < 50 {
                warnings.append(SecurityWarning(
                    message: "Content-Length very small (<50 bytes). Response might be incomplete or cloaked.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.inccorectLogic,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_INCORRECT_LOGIC]
                ))
            } else if contentLengthInt > 10_000_000 {
                warnings.append(SecurityWarning(
                    message: "Content-Length very large (>10MB).",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.inccorectLogic,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_INCORRECT_LOGIC]
                ))
            }
//            This does not work and is more of a good practice
//        } else {
//            warnings.append(SecurityWarning(
//                message: "Missing Content-Length header. Transfer size integrity not guaranteed.",
//                severity: .suspicious,
//                penalty: PenaltySystem.Penalty.inccorectLogic,
//                url: urlOrigin,
//                source: .header,
//                bitFlags: [.HEADERS_INCORRECT_LOGIC]
//            ))
        }
        
        return warnings
    }
    
    static func checkReferrerPolicy(responseHeaders: [String: String], urlOrigin: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []
        
        if let referrerPolicy = responseHeaders.first(where: { $0.key.caseInsensitiveCompare("Referrer-Policy") == .orderedSame })?.value.lowercased() {
            
            let goodPolicies = [
                "no-referrer", // Best !
                "strict-origin-when-cross-origin",
                "strict-origin", // good
                "origin", // good
                "origin-when-cross-origin", // Mkay
                "same-origin"
            ]
            
            if !goodPolicies.contains(referrerPolicy) {
                warnings.append(SecurityWarning(
                    message: "Weak or risky Referrer-Policy detected: \(referrerPolicy).",
                    severity: referrerPolicy == "unsafe-url" ? .dangerous : .suspicious,
                    penalty: PenaltySystem.Penalty.weakReferrerPolicy,
                    url: urlOrigin,
                    source: .header,
                ))
            }
        } else {
            warnings.append(SecurityWarning(
                message: "Missing Referrer-Policy header.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.weakReferrerPolicy,
                url: urlOrigin,
                source: .header,
            ))
        }
        
        return warnings
    }
}
