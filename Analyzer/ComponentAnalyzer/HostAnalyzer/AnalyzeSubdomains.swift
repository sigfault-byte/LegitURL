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
        
        let urlOrigin = urlInfo.components.host ?? ""
        
        if subdomains.count == 1, subdomains.first?.lowercased() == "www" {
            return
        }
        
        for subdomain in subdomains {
            let raw = subdomain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)

            if raw.contains("_") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Subdomain '\(raw)' contains underscores, which are unusual and may be used for obfuscation.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.subdomainUnderscore
            }

            // Treat underscores as noise → replace with nothing, then split on dash
            let normalized = raw.replacingOccurrences(of: "_", with: "")
            if raw != normalized {
                urlInfo.warnings.append(SecurityWarning(
                    message: "ℹ️ Subdomain '\(raw)' was normalized by removing underscores → '\(normalized)'.",
                    severity: .info,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
            }
            let parts = normalized.split(separator: "-").map(String.init)

            for part in parts {
                guard part.count >= 3 else { continue }

                if checkBrandImpersonation(part, urlInfo: &urlInfo) {
                    continue
                }

                if checkPhishingAndScamTerms(part, urlInfo: &urlInfo) {
                    continue
                }

                checkWordOrEntropy(part, urlInfo: &urlInfo)
            }
        }
    }

    private static func checkBrandImpersonation(_ part: String, urlInfo: inout URLInfo) -> Bool {
        let urlOrigin = urlInfo.components.host ?? ""
        for brand in KnownBrands.names {
            let distance = LegitURLTools.levenshtein(part, brand)
            if distance == 0 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "🚨 Subdomain segment '\(part)' matches the brand '\(brand)'.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.brandImpersonation
                return true
            } else if distance == 1 && part.count > 4 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Subdomain segment '\(part)' is very similar to the brand '\(brand)'.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.brandLookaLike
            }
        }
        return false
    }

    private static func checkPhishingAndScamTerms(_ part: String, urlInfo: inout URLInfo) -> Bool {
        let urlOrigin = urlInfo.components.host ?? ""
        let lowercased = part.lowercased()
        if SuspiciousKeywords.phishingWords.contains(lowercased) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' contains a phishing-related term.",
                severity: .scam,
                url: urlOrigin,
                source: .offlineAnalysis
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
            return true
        } else if SuspiciousKeywords.scamTerms.contains(lowercased) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' contains a scam-related term.",
                severity: .scam,
                url: urlOrigin,
                source: .offlineAnalysis
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.scamWordsInHost
            return true
        }
        return false
    }

    private static func checkWordOrEntropy(_ part: String, urlInfo: inout URLInfo) {
        let urlOrigin = urlInfo.components.host ?? ""
        if !LegitURLTools.isRealWord(part) {
            let (isEntropyHigh, entropyScore) = LegitURLTools.isHighEntropy(part)
            if isEntropyHigh {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Subdomain segment '\(part)' appears random or obfuscated (high entropy \(String(format: "%.2f", entropyScore ?? 0))).",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.highEntropySubDomain
            }
        }
    }
}
