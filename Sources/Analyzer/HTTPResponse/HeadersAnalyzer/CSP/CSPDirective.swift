//
//  CSPDirective.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
import Foundation

struct CSPDirective {
//    static func analyze(_ directive: [String: UInt32]) -> [SecurityWarning] {
//        var warnings: [SecurityWarning] = []
//
//        
//        return warnings
//    }

    static func analyzeScriptOrDefaultSrc(directiveName: String, bitFlagCSP: CSPBitFlag, sourceCount: [CSPBitFlag: Int] = [:], url: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []

        
        
        if bitFlagCSP.contains(.unsafeInline) {
            warnings.append(SecurityWarning(
                message: bitFlagCSP.contains(.strictDynamic) ?
                            "'unsafe-inline' is present with strict-dynamic in directive: \(directiveName) — inline script execution allowed but contained." :
                                "'unsafe-inline' is present in directive: \(directiveName) — inline script execution allowed.",
                severity: bitFlagCSP.contains(.strictDynamic) ? .suspicious : .dangerous,
                penalty: bitFlagCSP.contains(.strictDynamic) ?
                            PenaltySystem.Penalty.unsafeInlineStirctDyn :
                                PenaltySystem.Penalty.unsafeInlineScriptSrc,
                url: url,
                source: .header
            ))
        }

        if bitFlagCSP.contains(.unsafeEval) {
            warnings.append(SecurityWarning(
                message: bitFlagCSP.contains(.strictDynamic) ?
                            "'unsafe-eval' is present with strict-dynamic in directive: \(directiveName) — eval script execution allowed but contained." :
                                "'unsafe-eval' is present in directive: \(directiveName) — eval() can execute dynamic strings.",
                severity: bitFlagCSP.contains(.strictDynamic) ? .suspicious : .dangerous,
                penalty: bitFlagCSP.contains(.strictDynamic) ?
                            PenaltySystem.Penalty.unsafeEvalScriptSrcDyn :
                                PenaltySystem.Penalty.unsafeEvalScriptSrc,
                url: url,
                source: .header
            ))
        }

        if bitFlagCSP.contains(.wildcard) {
            warnings.append(SecurityWarning(
                message: "Wildcard (*) detected in directive: \(directiveName) — allows scripts from any origin.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.wildcardScriptSrc,
                url: url,
                source: .header
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
