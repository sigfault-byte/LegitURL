//
//  headerCSPViewModel.swift
//  LegitURL
//
//  Created by Chief Hakka on 06/05/2025.
//

struct CSPDirectiveAnalysis {
    let directive: String
    let flags: CSPBitFlag

    var warnings: [String] {
        var result: [String] = []

        if flags.contains(.unsafeInline) {
            result.append("Uses 'unsafe-inline' which weakens all protections.")
        }

        if flags.contains(.unsafeEval) {
            result.append("Allows eval(), which enables dynamic code execution.")
        }

        if (flags.contains(.hasNonce) || flags.contains(.hasHash)) && flags.contains(.unsafeInline) {
            result.append("'Nonce' or 'sha' protection is nullified by 'unsafe-inline'.")
        }

        if directive == "object-src", !flags.contains(.none) {
            result.append("object-src is missing or not set to 'none'. This is required for modern CSP.")
        }

        if flags.contains(.wildcard) {
            result.append("Allows all sources ('*'), which weakens source validation.")
        }

        if flags.contains(.allowsHTTP) {
            result.append("Allows 'http:' script sources — insecure and unnecessary in modern deployments.")
        }
        
        if flags.contains(.wildcard) &&
            (flags.contains(.allowsHTTPS) ||
             flags.contains(.specificURL) ||
             flags.contains(.allowsSelf)) {
            result.append("'*' is combined with other source, which makes no sense")
        }
        
        if flags.contains(.allowsSelf) && (flags.contains(.allowsHTTP) || flags.contains(.allowsHTTPS)) {
            result.append("'self' is combined with insecure HTTP/HTTPS sources, which is overriding the protection.")
        }
        
        if (flags.contains(.specificURL) || flags.contains(.wildcardURL)) && flags.contains(.allowsHTTPS) {
            result.append("Includes both 'https:' and specific HTTPS URLs. Redundant.")
        }
        
        if (flags.contains(.specificURL) || flags.contains(.wildcardURL)) && flags.contains(.allowsHTTP) {
            result.append("Allows 'http:' and includes explicit sources. Consider tightening.")
        }

        return result
    }
//
//    var impactsScore: Bool {
//        directive == "script-src" || directive == "default-src"
//    }
}
