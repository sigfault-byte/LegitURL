//
//  AnalyzeSubdomains.swift
//  URLChecker
//
//  Created by Chief Hakka on 22/03/2025.
//
//Handles the fun chaos:
//    •    Splits by . and further by -, _
//    •    Decodes each chunk with tryToDecode
//    •    Analyzes structure, spoofing, gibberish
//    •    Whitelist exceptions (e.g., Google’s mail.google.com)
//
struct AnalyzeSubdomains {
    static func analyze(urlInfo: inout URLInfo, subdomains: [String]) {
        let urlOrigin = urlInfo.components.coreURL ?? ""
        var tokenResults: [TokenAnalysis] = []

        if subdomains.count == 1, subdomains.first?.lowercased() == "www" {
            return
        }

        for subdomain in subdomains {
            let raw = subdomain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)

            if raw.contains("_") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Subdomain '\(raw)' contains underscores, which are unusual and may be used for obfuscation.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.subdomainUnderscore,
                    url: urlOrigin,
                    source: .host
                ))
            }

            let normalized = raw.replacingOccurrences(of: "_", with: "")
            if raw != normalized {
                urlInfo.warnings.append(SecurityWarning(
                    message: "ℹ️ Subdomain '\(raw)' was normalized by removing underscores → '\(normalized)'.",
                    severity: .info,
                    penalty: PenaltySystem.Penalty.informational,
                    url: urlOrigin,
                    source: .host
                ))
            }

            let parts = normalized.split(separator: "-").map(String.init)

            for part in parts {
                if part.count < 3 &&
                   !KnownBrands.names.contains(part.lowercased()) &&
                   !SuspiciousKeywords.scamTerms.contains(part.lowercased()) &&
                   !SuspiciousKeywords.phishingWords.contains(part.lowercased()) {
                   continue
                }

                var analysis = TokenAnalysis(part: part)

                if checkBrandImpersonation(part, urlInfo: &urlInfo) {
                    analysis.isBrand = true
                    analysis.brands.append(part)
                }

                if checkPhishingAndScamTerms(part, urlInfo: &urlInfo) {
                    analysis.isPhishing = true
                    analysis.phishingTerms.append(part)
                }

                if !analysis.isBrand && !analysis.isPhishing {
                    let isWord = LegitURLTools.isRealWord(part)
                    if !isWord {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "ℹ️ Subdomain segment '\(part)' is not found in the reference dictionary.",
                            severity: .info,
                            penalty: PenaltySystem.Penalty.informational,
                            url: urlOrigin,
                            source: .host
                        ))
                    }

                    let (entropyFlag, score) = LegitURLTools.isHighEntropy(part, 4.2)
                    if entropyFlag {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "⚠️ Subdomain segment '\(part)' appears random or obfuscated (high entropy \(String(format: "%.2f", score ?? 0))).",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.highEntropySubDomain,
                            url: urlOrigin,
                            source: .host
                        ))
                    }
                }

                tokenResults.append(analysis)
            }
        }

        if tokenResults.contains(where: { $0.isRelevant }) {
            urlInfo.components.subdomainTokenAnalysis = tokenResults
        }
        TokenCorrelation.evaluateTokenImpersonation(
            for: tokenResults,
            in: &urlInfo,
            from: .host,
            url: urlOrigin
        )
    }

    private static func checkBrandImpersonation(_ part: String, urlInfo: inout URLInfo) -> Bool {
        let urlOrigin = urlInfo.components.host ?? ""
        var matched = false

        for brand in KnownBrands.names {
            let lowered = part.lowercased()
            let brandLower = brand.lowercased()

            if lowered == brandLower {
                urlInfo.warnings.append(SecurityWarning(
                    message: "🚨 Subdomain segment '\(part)' matches the brand '\(brand)'.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.exactBrandImpersonation,
                    url: urlOrigin,
                    source: .host
                ))
                matched = true
            } else if lowered.contains(brandLower) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Subdomain segment '\(part)' contains known brand '\(brand)'.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.brandImpersonation,
                    url: urlOrigin,
                    source: .host
                ))
                matched = true
            } else {
                let distance = LegitURLTools.levenshtein(lowered, brandLower)
                if distance == 1 && part.count >= 3 {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ Subdomain segment '\(part)' is very similar to the brand '\(brand)' (Levenshtein = 1).",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.brandLookaLike,
                        url: urlOrigin,
                        source: .host
                    ))
                    matched = true
                }

                let ngram = LegitURLTools.twoGramSimilarity(lowered, brandLower)
                if ngram > 0.6 {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ Subdomain segment '\(part)' is structurally similar to brand '\(brand)' (2-gram similarity = \(String(format: "%.2f", ngram))).",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.brandLookaLike,
                        url: urlOrigin,
                        source: .host
                    ))
                    matched = true
                }
            }
        }

        return matched
    }

    private static func checkPhishingAndScamTerms(_ part: String, urlInfo: inout URLInfo) -> Bool {
        let urlOrigin = urlInfo.components.host ?? ""
        let lowercased = part.lowercased()
        if SuspiciousKeywords.phishingWords.contains(lowercased) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' contains a phishing-related term.",
                severity: .scam,
                penalty: PenaltySystem.Penalty.phishingWordsInHost,
                url: urlOrigin,
                source: .host
            ))
            return true
        } else if SuspiciousKeywords.scamTerms.contains(lowercased) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' contains a scam-related term.",
                severity: .scam,
                penalty: PenaltySystem.Penalty.scamWordsInHost,
                url: urlOrigin,
                source: .host
            ))
            return true
        }
        return false
    }

    private static func checkWordOrEntropy(_ part: String, urlInfo: inout URLInfo) {
        let urlOrigin = urlInfo.components.host ?? ""

        let isKnownWord = LegitURLTools.isRealWord(part)
        if !isKnownWord {
            urlInfo.warnings.append(SecurityWarning(
                message: "ℹ️ Subdomain segment '\(part)' is not found in the reference dictionary.",
                severity: .info,
                penalty: PenaltySystem.Penalty.informational,
                url: urlOrigin,
                source: .host
            ))
        }

        let (isEntropyHigh, entropyScore) = LegitURLTools.isHighEntropy(part, 4.2)
        if isEntropyHigh {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' appears random or obfuscated (high entropy \(String(format: "%.2f", entropyScore ?? 0))).",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.highEntropySubDomain,
                url: urlOrigin,
                source: .host
            ))
        }
    }
}
