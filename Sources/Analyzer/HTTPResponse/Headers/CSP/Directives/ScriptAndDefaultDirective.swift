//
//  CSPDirective.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
//[ Strong  ] : 'self' + some source. If inline is needed sha > nonce. eval always babylon
//
//[ Dangerous ] : 'unsafe-inline' 'unsafe-eval' + hash / nonce ? -> NO nonce is nullyfied by unsafe
//
//[ Dangerous   ] : 'unsafe-inline' 'unsafe-eval' + nonce + strict-dynamic - > same error
//
//[ Dangerous ] : 'unsafe-inline' 'unsafe-eval' (alone)
//
//[ Critical ] : No CSP at all

import Foundation

struct ScriptAndDefaultDirective {

    static func analyze(directiveName: String, bitFlagCSP: CSPBitFlag, sourceCount: [CSPBitFlag: Int] = [:], url: String, source: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []

        // Unsafe Inline
        if bitFlagCSP.contains(.unsafeInline) && !bitFlagCSP.contains(.strictDynamic) {
            var specialWarning = ""
            if bitFlagCSP.contains(.hasNonce) || bitFlagCSP.contains(.hasHash) {
                specialWarning = " It nullifies Nonce or SHA"
            }
            warnings.append(SecurityWarning(
                message: "'unsafe-inline' present in \(directiveName).\(specialWarning).",
                severity: .dangerous,
                penalty: source == "CSP?" ? PenaltySystem.Penalty.unsafeInlineScriptSrc : 0,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_UNSAFE_INLINE]
            ))
        } else if (bitFlagCSP.contains(.hasNonce) || bitFlagCSP.contains(.hasHash)) && bitFlagCSP.contains(.strictDynamic) {
            warnings.append(SecurityWarning(
                message: "Inline script protection via nonce or hash detected in \(directiveName), alongside with strict-dynamic.",
                severity: .info,
                penalty: PenaltySystem.Penalty.informational,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_HAS_NONCE_OR_HASH]
            ))
        }

        // Unsafe Eval
        if bitFlagCSP.contains(.unsafeEval) {
            warnings.append(SecurityWarning(
                message: "'unsafe-eval' present in \(directiveName) this allows dynamic JS execution and cannot be mitigated with nonce/hash.",
                severity: .dangerous,
                penalty: source == "CSP?" ? PenaltySystem.Penalty.unsafeInlineScriptSrc : 0,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_UNSAFE_EVAL]
            ))
        }

        // Wildcard usage
        if bitFlagCSP.contains(.wildcard) {
            warnings.append(SecurityWarning(
                message: "Wildcard (*) detected in directive: \(directiveName) — allows scripts from any origin.",
                severity: .dangerous,
                penalty: source == "CSP?" ? PenaltySystem.Penalty.unsafeInlineScriptSrc : 0,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_WILDCARD]
            ))
        }

        return warnings
    }
    
    public static func evaluate(structuredCSP: [String: [Data: CSPValueType]], url: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []

        let hasDefaultSrc = structuredCSP.keys.contains("default-src")
        let hasScriptSrc = structuredCSP.keys.contains("script-src")
        let hasObjectSrc = structuredCSP.keys.contains("object-src")
        let hasRequiredTrustedTypeFor = structuredCSP.keys.contains("require-trusted-types-for")

        
        //TODO: Poorly implemented. Refactor much needed
        if (!hasDefaultSrc && (!hasScriptSrc || !hasObjectSrc)) && !hasRequiredTrustedTypeFor {
            warnings.append(SecurityWarning(
                message: "CSP is missing both 'default-src' and a critical combination of 'script-src' and 'object-src'.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.fakeCSP,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_FAKE_CSP]
            ))
        } else if hasRequiredTrustedTypeFor {
            if let trustedTypesDirective = structuredCSP["require-trusted-types-for"] {
                let hasScriptRequirement = trustedTypesDirective.keys.contains(where: { data in
                    guard let stringValue = String(data: data, encoding: .utf8) else { return false }
                    return stringValue == "'script'"
                })

                if hasScriptRequirement {
                    warnings.append(SecurityWarning(
                        message: "Modern CSP: Trusted Types enforced for scripts.",
                        severity: .info,
                        penalty: 5,
                        url: url,
                        source: .header,
                        bitFlags: [.HEADERS_CSP_TRUSTED_TYPES]
                    ))
                } else {
                    warnings.append(SecurityWarning(
                        message: "CSP 'require-trusted-types-for' directive found but missing 'script' value. Potential misconfiguration.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.fakeCSP,
                        url: url,
                        source: .header,
                        bitFlags: [.HEADERS_FAKE_CSP]
                    ))
                }
            }
        }

        return warnings
    }

}
