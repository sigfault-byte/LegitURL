//
//  CSPDirective.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
//[ Strong  ] : 'self'
//
//[ Medium ] : 'unsafe-inline' 'unsafe-eval' + hash / nonce ?
//
//[ Weak   ] : 'unsafe-inline' 'unsafe-eval' + nonce + strict-dynamic
//
//[ Dangerous ] : 'unsafe-inline' 'unsafe-eval' (alone)
//
//[ Critical ] : No CSP at all

import Foundation

struct CSPDirective {

    static func analyzeScriptOrDefaultSrc(directiveName: String, bitFlagCSP: CSPBitFlag, sourceCount: [CSPBitFlag: Int] = [:], url: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []
//debug
//        print ("analyzeScriptOrDefaultSrc \(directiveName) \(bitFlagCSP)")
        
        if bitFlagCSP.contains(.unsafeInline) {
            let message: String
            let severity: SecurityWarning.SeverityLevel
            let penalty: Int
            let bitFlag: WarningFlags

            if bitFlagCSP.contains(.strictDynamic) && bitFlagCSP.contains(.hasNonce) {
                message = "'unsafe-inline' present with strict-dynamic and nonce in \(directiveName) — contained but still risky."
                severity = .suspicious
                penalty = PenaltySystem.Penalty.unsafeInlineStrictDynAndNonce
                bitFlag =  [.HEADERS_CSP_UNSAFE_INLINE_CONTAINED]
            } else if bitFlagCSP.contains(.hasNonce) {
                message = "'unsafe-inline' present with nonce in \(directiveName) — partially contained."
                severity = .suspicious
                penalty = PenaltySystem.Penalty.unsafeInlineStrictDynAndNonce
                bitFlag =  [.HEADERS_CSP_UNSAFE_INLINE_CONTAINED]
            } else if bitFlagCSP.contains(.hasHash) {
                message = "'unsafe-inline' present with script hashes in \(directiveName) — partially hardened."
                severity = .suspicious
                penalty = PenaltySystem.Penalty.unsafeInlineHash
                bitFlag =  [.HEADERS_CSP_UNSAFE_INLINE_CONTAINED]
            } else {
                message = "'unsafe-inline' present in \(directiveName) — freely allowed."
                severity = .dangerous
                penalty = PenaltySystem.Penalty.unsafeInlineScriptSrc
                bitFlag =  [.HEADERS_CSP_UNSAFE_INLINE]
            }

            warnings.append(SecurityWarning(
                message: message,
                severity: severity,
                penalty: penalty,
                url: url,
                source: .header,
                bitFlags: bitFlag
            ))
        }

        if bitFlagCSP.contains(.unsafeEval) {
            let message: String
            let severity: SecurityWarning.SeverityLevel
            let penalty: Int

            if  (bitFlagCSP.contains(.hasNonce) || (bitFlagCSP.contains(.hasHash))){
                message = "'unsafe-eval' present with strict-dynamic and nonce in \(directiveName) — partially contained but still dangerous."
                severity = .suspicious
                penalty = PenaltySystem.Penalty.unsafeEvalScriptContained
            } else {
                message = "'unsafe-eval' present in \(directiveName) — dangerous execution allowed."
                severity = .dangerous
                penalty = PenaltySystem.Penalty.unsafeEvalScriptSrc
            }

            warnings.append(SecurityWarning(
                message: message,
                severity: severity,
                penalty: penalty,
                url: url,
                source: .header,
                bitFlags: [.HEADERS_CSP_UNSAFE_EVAL]
            ))
        }

        if bitFlagCSP.contains(.wildcard) {
            let message: String
            let severity: SecurityWarning.SeverityLevel
            let penalty: Int

            if bitFlagCSP.contains(.strictDynamic) && (bitFlagCSP.contains(.hasNonce) || bitFlagCSP.contains(.hasHash)) {
                message = "Wildcard (*) detected with strict-dynamic and nonce/hash in \(directiveName) — partially contained but still risky."
                severity = .suspicious
                penalty = PenaltySystem.Penalty.wildcardScriptSrcStrictDyn
            } else {
                message = "Wildcard (*) detected in directive: \(directiveName) — allows scripts from any origin."
                severity = .dangerous
                penalty = PenaltySystem.Penalty.wildcardScriptSrc
            }

            warnings.append(SecurityWarning(
                message: message,
                severity: severity,
                penalty: penalty,
                url: url,
                source: .header,
            ))
        }

        if bitFlagCSP.contains(.none) && (
            bitFlagCSP.contains(.unsafeInline) ||
            bitFlagCSP.contains(.unsafeEval) ||
            bitFlagCSP.contains(.allowsHTTPS) ||
            bitFlagCSP.contains(.allowsBlob) ||
            bitFlagCSP.contains(.allowsData) ||
            bitFlagCSP.contains(.allowsSelf)
        ) {
            warnings.append(SecurityWarning(
                message: "'none' used alongside other sources in \(directiveName) — CSP conflict.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                url: url,
                source: .header
            ))
        }

//        Too hectic, keep for later thinking
//        let reasons = bitFlagCSP.descriptiveReasons(sourceCount: sourceCount)
//        if !reasons.isEmpty {
//            warnings.append(SecurityWarning(
//                message: "\(directiveName) allows: \(reasons.joined(separator: ", "))",
//                severity: .info,
//                penalty: 0,
//                url: url,
//                source: .header
//            ))
//        }

        return warnings
    }
}
