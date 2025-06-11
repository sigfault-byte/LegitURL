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
            var penalty = 0
            var severity = SecurityWarning.SeverityLevel.dangerous
            var bitFlag = WarningFlags.HEADERS_CSP_UNSAFE_INLINE
            if source == "CSP" {
                penalty = PenaltySystem.Penalty.unsafeInlineScriptSrc
            }
            if bitFlagCSP.contains(.hasNonce) || bitFlagCSP.contains(.hasHash) {
                specialWarning = " Nullified by nonce / Hash."
                penalty = 0
                severity = .info
                bitFlag = []
            }
            warnings.append(SecurityWarning(
                message: "'unsafe-inline' present in \(directiveName).\(specialWarning)",
                severity: severity,
                penalty: penalty,
                url: url,
                source: .header,
                bitFlags: bitFlag,
                machineMessage: "csp_unsafe_inline_present"
            ))
        } else if (bitFlagCSP.contains(.hasNonce) || bitFlagCSP.contains(.hasHash)) && bitFlagCSP.contains(.strictDynamic) {
            warnings.append(SecurityWarning(
                message: "Inline script protection via nonce or hash \(directiveName), alongside strict-dynamic.",
                severity: .info,
                penalty: PenaltySystem.Penalty.informational,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_HAS_NONCE_OR_HASH],
                machineMessage: "csp_nonce_or_hash_with_strict_dynamic"
            ))
        }

        // Unsafe Eval
        if bitFlagCSP.contains(.unsafeEval) {
            warnings.append(SecurityWarning(
                message: "'unsafe-eval' present in \(directiveName) allowing dynamic JS execution, which cannot be mitigated.",
                severity: .dangerous,
                penalty: source == "CSP"
                    ? PenaltySystem.Penalty.unsafeEvalScriptSrc
                    : 0,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_UNSAFE_EVAL],
                machineMessage: "csp_unsafe_eval_present"
            ))
        }

        // Wildcard usage
        if bitFlagCSP.contains(.wildcard) {
            warnings.append(SecurityWarning(
                message: "Wildcard (*) detected in directive: \(directiveName) — allows scripts from any origin.",
                severity: .dangerous,
                penalty: source == "CSP" ? PenaltySystem.Penalty.wildcardScriptSrc : 0,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_WILDCARD],
                machineMessage: "csp_wildcard_present"
            ))
        }

        return warnings
    }
    
    public static func evaluate(structuredCSP: [String: [Data: CSPValueType]], url: String, defaultSrcIsNone: Bool) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []

        let hasDefaultSrc = structuredCSP.keys.contains("default-src")
        let hasScriptSrc = structuredCSP.keys.contains("script-src")
        let hasObjectSrc = structuredCSP.keys.contains("object-src")
        let hasRequiredTrustedTypeFor = structuredCSP.keys.contains("require-trusted-types-for")
        
        // Penalize completely missing script-src and default-src
        if !hasDefaultSrc && !hasScriptSrc && !hasRequiredTrustedTypeFor{
            warnings.append(SecurityWarning(
                message: "CSP is missing both 'default-src' and 'script-src' or 'require-trusted-types-for'\n. This CSP offers no meaningful script protection.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.fakeCSP,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_FAKE_CSP],
                machineMessage: "csp_missing_default_and_script_src"
            ))
            
        } else if !hasObjectSrc && !defaultSrcIsNone {
            warnings.append(SecurityWarning(
                message: "CSP is missing 'object-src'. This weakens protection against legacy plugin-based attacks.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.inccorectLogic,
                url: url,
                source: .header,
                machineMessage: "csp_missing_object_src"
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
                        bitFlags: [.HEADERS_CSP_TRUSTED_TYPES],
                        machineMessage: "csp_trusted_types_script_enforced"
                    ))
                } else {
                    warnings.append(SecurityWarning(
                        message: "CSP 'require-trusted-types-for' directive found but missing 'script' value. Potential misconfiguration.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.fakeCSP,
                        url: url,
                        source: .header,
                        bitFlags: [.HEADERS_FAKE_CSP],
                        machineMessage: "csp_trusted_types_script_missing"
                    ))
                }
            }
        }

        return warnings
    }

}
