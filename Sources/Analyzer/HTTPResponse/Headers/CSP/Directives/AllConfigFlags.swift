//
//  CSPConfigAnalysis.swift
//  LegitURL
//
//  Created by Chief Hakka on 05/05/2025.
//
// Tricky choice, this is not scam worthy, but it stil bad. wat to do? Info for now

struct CSPConfigAnalysis {
    
    static func analyze(directiveFlags: [String: Int32], url: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []

        for (directive, rawFlags) in directiveFlags {
            let flags = CSPBitFlag(rawValue: rawFlags)

            // Only generate warnings and penalatis for script-src and default-src ( for now )
            guard directive == "script-src" || directive == "default-src" else { continue }

            if flags.contains(.wildcard) && (flags.contains(.allowsHTTPS) || (flags.contains(.allowsHTTP))) {
                warnings.append(SecurityWarning(
                    message: "Directive '\(directive)' allows both wildcard and HTTP sources.",
                    severity: .info,
                    penalty: 0,
                    url: url,
                    source: .header,
                    bitFlags: [.HEADERS_INCORRECT_LOGIC]
                ))
            }

            if flags.contains([.allowsSelf, .wildcard]) {
                warnings.append(SecurityWarning(
                    message: "Directive '\(directive)' includes both 'self' and wildcard (*).",
                    severity: .info,
                    penalty: 0,
                    url: url,
                    source: .header,
                    bitFlags: [.HEADERS_INCORRECT_LOGIC]
                ))
            }

            // Conflict: 'none' used with other sources
            if flags.contains(.none) && (
                flags.contains(.unsafeInline) ||
                flags.contains(.unsafeEval) ||
                flags.contains(.allowsHTTPS) ||
                flags.contains(.allowsBlob) ||
                flags.contains(.allowsData) ||
                flags.contains(.allowsSelf)
            ) {
                warnings.append(SecurityWarning(
                    message: "'none' used alongside other sources in \(directive) — CSP conflict.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                    url: url,
                    source: .header
                ))
            }
        }

        return warnings
    }
}
