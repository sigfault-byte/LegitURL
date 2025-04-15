//
//  PathAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

import Foundation

struct PathAnalyzer {
    
    static func analyze(urlInfo: inout URLInfo) {
        var tokenResults: [TokenAnalysis] = []
        
        let urlOrigin = urlInfo.components.host ?? ""
        
        guard let rawPath = urlInfo.components.pathEncoded else {
            return
        }
        
        if !rawPath.hasSuffix("/"), urlInfo.components.query != nil {
            urlInfo.warnings.append(SecurityWarning(
                message: "🧠 Suspicious endpoint-like path followed by query.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.pathIsEndpointLike,
                url: urlOrigin,
                source: .path
            ))
        }
        
        let pathRegex = #"^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%]+\/?)*$"#
        if !rawPath.matches(regex: pathRegex) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Malformed path structure detected",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .path
            ))
            return
        }
        
        if rawPath.contains("//") {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Suspicious double slashes in path",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .path
            ))
            return
        }
        
        let pathSegmentsToCheck = rawPath.split(separator: "/").map(String.init)
        for segment in pathSegmentsToCheck {
            if segment.rangeOfCharacter(from: .alphanumerics) == nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Suspicious path segment contains no alphanumeric characters: '\(segment)'",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlOrigin,
                    source: .path
                ))
                return
            }
        }
        
        let trimmedPath = rawPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let pathSegments = trimmedPath.split(separator: "/").map(String.init)
        
        for segment in pathSegments {
            guard !segment.isEmpty else { continue }
            
            // This needs more thinking
            if WhiteList.safePaths.contains(segment.lowercased()) {
                continue
            }
            
            var parts: [String]
            if segment.count > 64 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Suspiciously long path segment: (\(segment.count) chars / \(segment.utf8.count) bytes)",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.suspiciousPathSegment,
                    url: urlOrigin,
                    source: .path
                ))
            }
            if segment.count <= 64 && segment.contains("-") {
                parts = segment.split(separator: "-").map(String.init)
            } else {
                parts = [segment]
            }
            
            for part in parts {
                var analysis = TokenAnalysis(part: part)
                
                if SuspiciousKeywords.scamTerms.contains(part.lowercased()) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🚩 Scam-related word detected in path segment: '\(part)'",
                        severity: .scam,
                        penalty: PenaltySystem.Penalty.scamWordsInPath,
                        url: urlOrigin,
                        source: .path
                    ))
                    analysis.isPhishing = true
                    analysis.phishingTerms.append(part)
                }
                
                if SuspiciousKeywords.phishingWords.contains(part.lowercased()) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🚩 Phishing-related word detected in path segment: '\(part)'",
                        severity: .scam,
                        penalty: PenaltySystem.Penalty.phishingWordsInPath,
                        url: urlOrigin,
                        source: .path
                    ))
                    analysis.isPhishing = true
                    analysis.phishingTerms.append(part)
                }
                // TODO: add levenshtein + n gram check!!
                for brand in KnownBrands.names {
                    if brand == part.lowercased() {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "ℹ️ Exact Brand reference found in path segment: '\(part)'",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.exactBrandInPath,
                            url: urlOrigin,
                            source: .path
                        ))
                        analysis.isBrand = true
                        analysis.brands.append(brand)
                        
                    } else if KnownBrands.names.contains(part.lowercased()) {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "ℹ️ Brand reference found in path segment: '\(part)'",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.containBrandInPath,
                            url: urlOrigin,
                            source: .path
                        ))
                        analysis.isBrand = true
                        analysis.brands.append(brand)
                    }else if part.count >= 3 {
                        let levenshtein = LegitURLTools.levenshtein(part.lowercased(), brand)
                        if levenshtein == 1 {
                            urlInfo.warnings.append(SecurityWarning(
                                message: "⚠️ Path segment '\(part)' is a likely typo of brand '\(brand)' (Levenshtein = 1).",
                                severity: .suspicious,
                                penalty: PenaltySystem.Penalty.brandLookaLike,
                                url: urlOrigin,
                                source: .path
                            ))
                            analysis.isBrand = true
                            analysis.brands.append(brand)
                        }
                        let ngram = LegitURLTools.twoGramSimilarity(part.lowercased(), brand)
                        if ngram > 0.6 {
                            urlInfo.warnings.append(SecurityWarning(
                                message: "⚠️ Path segment '\(part)' is structurally similar to brand '\(brand)' (2-gram similarity = \(String(format: "%.2f", ngram))).",
                                severity: .suspicious,
                                penalty: PenaltySystem.Penalty.brandLookaLike,
                                url: urlOrigin,
                                source: .path
                            ))
                            analysis.isBrand = true
                            analysis.brands.append(brand)
                        }
                    }
                    
                }
                
                if part.contains(".") {
                    let pieces = part.split(separator: ".")
                    if let ext = pieces.last?.lowercased(),
                       SuspiciousKeywords.dangerousExtensions.contains(ext) {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "🚨 Executable file extension detected: '\(ext)'",
                            severity: .dangerous,
                            penalty: PenaltySystem.Penalty.critical,
                            url: urlOrigin,
                            source: .path
                        ))
                    }
                }
                
                if !LegitURLTools.isRealWord(part) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "ℹ️ Path segment '\(part)' is not recognized by the dictionary.",
                        severity: .info,
                        penalty: PenaltySystem.Penalty.informational,
                        url: urlOrigin,
                        source: .path
                    ))
                    
                    let (isHighEntropy, score) = LegitURLTools.isHighEntropy(part)
                    if isHighEntropy, let entropy = score {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "⚠️ Path segment '\(part)' has high entropy (≈ \(String(format: "%.2f", entropy))).",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.highEntropyPathComponent,
                            url: urlOrigin,
                            source: .path
                        ))
                        
                    }
                }
                tokenResults.append(analysis)
            }
        }
        
        if tokenResults.contains(where: { $0.isRelevant }) {
            urlInfo.components.pathTokenAnalysis = tokenResults
        }
        TokenCorrelation.evaluateTokenImpersonation(
            for: tokenResults,
            in: &urlInfo,
            from: .path,
            url: urlOrigin
        )
        
        return
    }
}
