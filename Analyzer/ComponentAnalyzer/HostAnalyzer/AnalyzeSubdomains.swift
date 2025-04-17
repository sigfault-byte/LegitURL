struct AnalyzeSubdomains {
    static func analyze(urlInfo: inout URLInfo, subdomains: [String]) {
        let urlOrigin = urlInfo.components.coreURL ?? ""
        
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
                    source: .host,
                    bitFlags: WarningFlags.ABNORMAL_URL_STRUCTURE
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
                
                checkBrandImpersonation(part, urlInfo: &urlInfo)
                
                checkPhishingAndScamTerms(part, urlInfo: &urlInfo)
                
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
                        source: .host,
                        bitFlags: WarningFlags.ABNORMAL_URL_STRUCTURE
                    ))
                }
            }
        }
    }
    
    private static func checkBrandImpersonation(_ part: String, urlInfo: inout URLInfo) -> Void {
        let urlOrigin = urlInfo.components.host ?? ""
        
        for brand in KnownBrands.names {
            let lowered = part.lowercased()
            let brandLower = brand.lowercased()
            
            if lowered == brandLower {
                urlInfo.warnings.append(SecurityWarning(
                    message: "🚨 Subdomain segment '\(part)' matches the brand '\(brand)'.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.exactBrandImpersonation,
                    url: urlOrigin,
                    source: .host,
                    bitFlags: WarningFlags.DOMAIN_EXACT_BRAND_MATCH
                ))
            } else if lowered.contains(brandLower) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Subdomain segment '\(part)' contains known brand '\(brand)'.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.brandImpersonation,
                    url: urlOrigin,
                    source: .host,
                    bitFlags: WarningFlags.DOMAIN_CONTAINS_BANRD
                ))
                
            } else {
                let distance = LegitURLTools.levenshtein(lowered, brandLower)
                if distance == 1 && part.count >= 3 {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ Subdomain segment '\(part)' is very similar to the brand '\(brand)' (Levenshtein = 1).",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.brandLookaLike,
                        url: urlOrigin,
                        source: .host,
                        bitFlags: WarningFlags.DOMAIN_LOOKALIKE_BRAND_MATCH
                    ))
                }
                
                let ngram = LegitURLTools.twoGramSimilarity(lowered, brandLower)
                if ngram > 0.6 {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ Subdomain segment '\(part)' is structurally similar to brand '\(brand)' (2-gram similarity = \(String(format: "%.2f", ngram))).",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.brandLookaLike,
                        url: urlOrigin,
                        source: .host,
                        bitFlags: WarningFlags.DOMAIN_LOOKALIKE_BRAND_MATCH
                    ))
                }
            }
        }
    }
    
    private static func checkPhishingAndScamTerms(_ part: String, urlInfo: inout URLInfo) -> Void {
        let urlOrigin = urlInfo.components.host ?? ""
        let lowercased = part.lowercased()
        if SuspiciousKeywords.phishingWords.contains(lowercased) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' contains a phishing-related term.",
                severity: .scam,
                penalty: PenaltySystem.Penalty.phishingWordsInHost,
                url: urlOrigin,
                source: .host,
                bitFlags: WarningFlags.DOMAIN_SCAM_OR_PHISHING
            ))
        } else if SuspiciousKeywords.scamTerms.contains(lowercased) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' contains a scam-related term.",
                severity: .scam,
                penalty: PenaltySystem.Penalty.scamWordsInHost,
                url: urlOrigin,
                source: .host,
                bitFlags: WarningFlags.DOMAIN_SCAM_OR_PHISHING
            ))
        }
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
        
        let (isEntropyHigh, entropyScore) = LegitURLTools.isHighEntropy(part, 4.3)
        if isEntropyHigh {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Subdomain segment '\(part)' appears random or obfuscated (high entropy \(String(format: "%.2f", entropyScore ?? 0))).",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.highEntropySubDomain,
                url: urlOrigin,
                source: .host,
                bitFlags: WarningFlags.ABNORMAL_URL_STRUCTURE
            ))
        }
    }
}
