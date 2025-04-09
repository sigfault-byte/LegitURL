//
//  URLToken.swift
//  URLChecker
//
//  Created by Chief Hakka on 08/04/2025.
//
import Foundation

struct TokenAnalysis {
    let part: String
    var isBrand: Bool = false
    var isPhishing: Bool = false
    var brands: [String] = []
    var phishingTerms: [String] = []
}

extension TokenAnalysis {
    var isRelevant: Bool {
        return isBrand || isPhishing || !brands.isEmpty || !phishingTerms.isEmpty
    }
}

struct TokenCorrelation {
    static func evaluateTokenImpersonation(for tokens: [TokenAnalysis],
                                           in urlInfo: inout URLInfo,
                                           from source: SecurityWarning.SourceType,
                                           url: String) {
        for token in tokens where token.isBrand && token.isPhishing {
            urlInfo.warnings.append(SecurityWarning(
                message: "\(source) segment '\(token.part)' impersonates brand(s) '\(token.brands.joined(separator: ", "))' using scam keyword(s) '\(token.phishingTerms.joined(separator: ", "))'.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: url,
                source: source
            ))
        }
    }
}
