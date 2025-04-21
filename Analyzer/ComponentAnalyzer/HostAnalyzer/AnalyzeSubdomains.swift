struct AnalyzeSubdomains {
    static func analyze(urlInfo: inout URLInfo, subdomains: [String]) {
        let urlOrigin = urlInfo.components.coreURL ?? ""
        let userBrands = UserHeuristicsCache.brands
        let allBrands = userBrands
        let userScamwords = UserHeuristicsCache.scamwords
        let allScamwords = userScamwords
        let trustedDomains = UserHeuristicsCache.trustedDomains
        let allDomains = trustedDomains
        
        let domain: String = urlInfo.components.extractedDomain ?? ""
        var isTrusted: Bool = false
        if allDomains.contains(domain) {
            isTrusted = true
        }
        
        
        if subdomains.count == 1, subdomains.first?.lowercased() == "www" {
            return
        }
        
        let subdomainLowercased = subdomains.map { $0.lowercased() }.joined()
        
        for userBrand in userBrands where userBrand.contains("-") {
            if isTrusted && userBrand == domain { continue }

            if subdomainLowercased.contains(userBrand) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Subdomain contains the brand '\(userBrand)'.",
                    severity: SecurityWarning.SeverityLevel.dangerous,
                    penalty: PenaltySystem.Penalty.containBrandInPath,
                    url: urlOrigin,
                    source: .host,
                    bitFlags: WarningFlags.SUBDOMAIN_CONTAINS_BRAND
                ))
            }
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
                    !allBrands.contains(part.lowercased()) &&
                    !allScamwords.contains(part.lowercased()) &&
                    !SuspiciousKeywords.phishingWords.contains(part.lowercased()) {
                    continue
                }
                
                checkBrandImpersonation(part, urlInfo: &urlInfo, allBrands: allBrands, isTrusted: isTrusted)
                
                checkPhishingAndScamTerms(part, urlInfo: &urlInfo, allScamwords: allScamwords)
                
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
    
    private static func checkBrandImpersonation(_ part: String, urlInfo: inout URLInfo, allBrands: Set<String>, isTrusted: Bool) -> Void {
        let urlOrigin = urlInfo.components.host ?? ""
        let domain = urlInfo.components.extractedDomain ?? ""
        
        for brand in allBrands {
            let lowered = part.lowercased()
            let brandLower = brand.lowercased()
//            skip the brand if its the domain
            if isTrusted && brandLower == domain { continue }
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
    
    private static func checkPhishingAndScamTerms(_ part: String, urlInfo: inout URLInfo, allScamwords: Set<String>) -> Void {
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
        } else if allScamwords.contains(lowercased) {
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
