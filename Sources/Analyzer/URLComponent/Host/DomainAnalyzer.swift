//
//  DomainAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 22/03/2025.
//
import Punycode

struct DomainAnalyzer {
    static func analyze(in urlInfo: inout URLInfo, domain: String, tld: String) {
        let userBrands = UserHeuristicsCache.brands
        let allBrands = userBrands
        let userScamwords = UserHeuristicsCache.scamwords
        let allScamwords = userScamwords
        let trustedDomains = UserHeuristicsCache.trustedDomains
        let allDomains = trustedDomains
        
        
        // Step 1: Compare punycode-encoded and decoded versions.
        // If they differ, keep both for deeper analysis.
        let idnaEncodedDomain = urlInfo.components.idnaEncodedExtractedDomain ?? ""
        let idnaDecodedDomain = urlInfo.components.idnaDecodedExtractedDomain ?? ""
        
        if domain != idnaDecodedDomain {
            urlInfo.warnings.append(SecurityWarning(
                message: "Domain '\(domain)' mismatch: '\(idnaDecodedDomain)' decoded from '\(idnaEncodedDomain)'. Possible homograph or internationalized domain.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.domainNonASCII,
                url: urlInfo.components.coreURL ?? "",
                source: .host
            ))
        }
        
        // Step 2: Script analysis on the DECODED!!!!! IDIOT
        checkScriptMismatch(domain: idnaDecodedDomain, tld: tld, urlInfo: &urlInfo)
        
        // Step 3: WhiteList check
        if isWhitelisted(domain: idnaEncodedDomain.lowercased(), tld: tld, urlInfo: &urlInfo, userTrustedDomains: allDomains) {
            return
        }
        
        // Step 3.5: Detect if domain root is entirely a brand
        checkSingleBrandRootDomain(domain: domain, urlInfo: &urlInfo, allBrands: allBrands)
        
        // Step 4: Normalize domain input into array of tokens.
        
        let domainParts = domain.contains("-") ? domain.split(separator: "-").map(String.init) : [domain]
        
        // Step 4.5: Check against user added brand with hyphen
        let fullLowerDomain = domain.lowercased()

        //TODO: This part's useless because checkSingleBrandRootDomain
//        for userBrand in userBrands where userBrand.contains("-") {
//            if fullLowerDomain.contains(userBrand) {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "Domain '\(domain)' contains the user-defined brand '\(userBrand)', which may indicate impersonation.",
//                    severity: .dangerous,
//                    penalty: PenaltySystem.Penalty.brandImpersonation,
//                    url: urlInfo.components.coreURL ?? "",
//                    source: .host,
//                    bitFlags: WarningFlags.DOMAIN_CONTAINS_BANRD
//                ))
//            }
//        }
        
        // Step 4.5: Check against user added scam with hyphen
        for scamword in allScamwords where allScamwords.contains("-"){
            if fullLowerDomain.contains(scamword) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain '\(domain)' contains the user-defined scamword '\(scamword)', which may indicate phishing or malware.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scamWordsInHost,
                    url: urlInfo.components.coreURL ?? "",
                    source: .host,
                    bitFlags: WarningFlags.DOMAIN_SCAM_OR_PHISHING
                ))
            }
            
        }
        
        // TODO: progressive penalty when there are more hyphen
        if domainParts.count >= 5 {
            urlInfo.warnings.append(SecurityWarning(
                message: "Domain '\(domain)' contains \(domainParts.count) segments split by hyphens, which may be an attempt to obfuscate.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.tooManyHyphensInDomain,
                url: urlInfo.components.coreURL ?? "",
                source: .host,
                bitFlags: WarningFlags.ABNORMAL_URL_STRUCTURE
            ))
        }
        
        // Step 5: Iterate over each domain token for analysis.
        for part in domainParts {
            
            for brand in allBrands {
                if part.lowercased() == brand {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Domain segment '\(part)' might be impersonating '\(brand)'.",
                        severity: .dangerous,
                        penalty: PenaltySystem.Penalty.exactBrandImpersonation,
                        url: urlInfo.components.coreURL ?? "",
                        source: .host,
                        bitFlags: WarningFlags.DOMAIN_EXACT_BRAND_MATCH
                    ))
                } else if part.lowercased().contains(brand) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Domain segment '\(part)' contains known brand '\(brand)'.",
                        severity: .dangerous,
                        penalty: PenaltySystem.Penalty.brandImpersonation,
                        url: urlInfo.components.coreURL ?? "",
                        source: .host
                    ))
                } else if part.count >= 3 {
                    let levenshtein = CoomonTools.levenshtein(part.lowercased(), brand)
                    if levenshtein == 1 {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Domain segment '\(part)' is a likely typo of '\(brand)' (Levenshtein = 1).",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.brandLookaLike,
                            url: urlInfo.components.coreURL ?? "",
                            source: .host,
                            bitFlags: WarningFlags.DOMAIN_LOOKALIKE_BRAND_MATCH
                        ))
                    }
                    
                    let ngram = CoomonTools.twoGramSimilarity(part.lowercased(), brand)
                    if ngram > 0.6 {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Domain segment '\(part)' is structurally similar to brand '\(brand)' (2-gram similarity = \(String(format: "%.2f", ngram))).",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.brandLookaLike,
                            url: urlInfo.components.coreURL ?? "",
                            source: .host,
                            bitFlags: WarningFlags.DOMAIN_LOOKALIKE_BRAND_MATCH
                        ))
                    }
                }
            }
            
            let lower = part.lowercased()
            for keyword in SuspiciousKeywords.phishingWords {
                if lower.contains(keyword) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Domain segment '\(part)' contains phishing-related keyword '\(keyword)'.",
                        severity: .scam,
                        penalty: PenaltySystem.Penalty.phishingWordsInHost,
                        url: urlInfo.components.coreURL ?? "",
                        source: .host,
                        bitFlags: WarningFlags.DOMAIN_SCAM_OR_PHISHING
                    ))
                }
            }
            
            for scam in allScamwords {
                if lower.contains(scam) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Domain segment '\(part)' contains scam-related term '\(scam)'.",
                        severity: .scam,
                        penalty: PenaltySystem.Penalty.scamWordsInHost,
                        url: urlInfo.components.coreURL ?? "",
                        source: .host,
                        bitFlags: WarningFlags.DOMAIN_SCAM_OR_PHISHING
                    ))
                }
            }
            
            let (isHighEntropy, entropyScore) = CoomonTools.isHighEntropy(part, 4.2)
            if isHighEntropy {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain segment '\(part)' appears random or obfuscated (high entropy \(String(format: "%.2f", entropyScore ?? 0))).",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.highEntropyDomain,
                    url: urlInfo.components.coreURL ?? "",
                    source: .host,
                    bitFlags: WarningFlags.ABNORMAL_URL_STRUCTURE
                ))
            }
        }
    }
//
//    Refactor: Use tthe function to shortcut checks when findings were al ready found...
//
//    private static func checkForBrandMatch(in part: String, urlInfo: inout URLInfo) -> TokenAnalysis? {
//        let urlOrigin = urlInfo.components.coreURL ?? ""
//        for brand in KnownBrands.names {
//            if part.lowercased() == brand {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "Domain segment '\(part)' might be impersonating '\(brand)'.",
//                    severity: .dangerous,
//                    penalty: PenaltySystem.Penalty.exactBrandImpersonation,
//                    url: urlOrigin,
//                    source: .host
//                ))
//                return TokenAnalysis(part: part, isBrand: true, brands: [brand])
//
//            } else if part.lowercased().contains(brand) {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "Domain segment '\(part)' contains known brand '\(brand)'.",
//                    severity: .dangerous,
//                    penalty: PenaltySystem.Penalty.brandImpersonation,
//                    url: urlOrigin,
//                    source: .host
//                ))
//                return TokenAnalysis(part: part, isBrand: true, brands: [brand])
//
//                // Todo more testing to leverage the granularity
//            } else if part.count >= 3 {
//                let levenshtein = LegitURLTools.levenshtein(part.lowercased(), brand)
//                if levenshtein == 1 {
//                    urlInfo.warnings.append(SecurityWarning(
//                        message: " Domain segment '\(part)' is a likely typo of '\(brand)' (Levenshtein = 1).",
//                        severity: .suspicious,
//                        penalty: PenaltySystem.Penalty.brandLookaLike,
//                        url: urlOrigin,
//                        source: .host
//                    ))
//                    return TokenAnalysis(part: part, isBrand: true, brands: [brand])
//                }
//
//                let ngram = LegitURLTools.twoGramSimilarity(part.lowercased(), brand)
//                if ngram > 0.6 {
//                    urlInfo.warnings.append(SecurityWarning(
//                        message: "Domain segment '\(part)' is structurally similar to brand '\(brand)' (2-gram similarity = \(String(format: "%.2f", ngram))).",
//                        severity: .suspicious,
//                        penalty: PenaltySystem.Penalty.brandLookaLike,
//                        url: urlInfo.components.coreURL ?? "",
//                        source: .host
//                    ))
//                    return TokenAnalysis(part: part, isBrand: true, brands: [brand])
//                }
//            }
//        }
//        return nil
//    }
//
//    private static func checkForPhishingKeyword(in part: String, urlInfo: inout URLInfo) -> TokenAnalysis? {
//        let lower = part.lowercased()
//        let urlOrigin = urlInfo.components.coreURL ?? ""
//
//        for keyword in SuspiciousKeywords.phishingWords {
//            if lower.contains(keyword) {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "Domain segment '\(part)' contains phishing-related keyword '\(keyword)'.",
//                    severity: .scam,
//                    penalty: PenaltySystem.Penalty.phishingWordsInHost,
//                    url: urlOrigin,
//                    source: .host
//                ))
//                return TokenAnalysis(part: part, isPhishing: true, phishingTerms: [keyword])
//            }
//        }
//
//        for scam in SuspiciousKeywords.scamTerms {
//            if lower.contains(scam) {
//                urlInfo.warnings.append(SecurityWarning(
//                    message: "Domain segment '\(part)' contains scam-related term '\(scam)'.",
//                    severity: .scam,
//                    penalty: PenaltySystem.Penalty.scamWordsInHost,
//                    url: urlOrigin,
//                    source: .host
//                ))
//                return TokenAnalysis(part: part, isPhishing: true, phishingTerms: [scam])
//            }
//        }
//        return nil
//    }
    
    private static func checkSingleBrandRootDomain(domain: String, urlInfo: inout URLInfo, allBrands: Set<String> = []) {
        let lowercasedDomain = domain.lowercased()

        if allBrands.contains(lowercasedDomain) {
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Domain '\(domain)' is entirely composed of a known or user-defined brand name, which strongly indicates impersonation.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: domain,
                source: .host
            ))
        }
    }
}

private func checkScriptMismatch(domain: String, tld: String, urlInfo: inout URLInfo) {
    let scriptSet = analyzeUnicodeScripts(in: domain)
    let tldScriptSet = analyzeUnicodeScripts(in: tld)
    
    let urlOrigin = urlInfo.components.coreURL ?? ""
    
    if scriptSet.count == 1 {
        if scriptSet.contains(.ascii) {
            // It's just plain ASCII — no need to warn.
            return
        }
        if let script = scriptSet.first, !tldScriptSet.contains(script) {
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Domain '\(domain)' uses only \(script) characters, but its TLD '\(tld)' is from a different script family.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .host
            ))
            return
        } else {
            urlInfo.warnings.append(SecurityWarning(
                message: "ℹ️ Domain '\(domain)' is fully non-Latin but matches the script of the TLD '\(tld)'.",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .host
            ))
        }
        
    } else if scriptSet.contains(.ascii) && scriptSet.contains(.latinExtended) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Domain '\(domain)' mixes basic Latin and Extended Latin characters, which may indicate subtle obfuscation.",
            severity: .suspicious,
            penalty: PenaltySystem.Penalty.domainNonASCII,
            url: urlOrigin,
            source: .host
        ))
        
    } else if scriptSet.contains(.ascii) && (scriptSet.contains(.cyrillic) || scriptSet.contains(.greek)) {
        urlInfo.warnings.append(SecurityWarning(
            message: "🚨 Domain '\(domain)' mixes Latin and non-Latin characters, which strongly indicates a homograph attack.",
            severity: .critical,
            penalty: PenaltySystem.Penalty.critical,
            url: urlOrigin,
            source: .host
        ))
        return
    } else if scriptSet.contains(.cyrillic) || scriptSet.contains(.greek) || scriptSet.contains(.other) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Domain '\(domain)' contains non-Latin characters, which may be deceptive.",
            severity: .suspicious,
            penalty: PenaltySystem.Penalty.domainNonASCII,
            url: urlOrigin,
            source: .host
        ))
    }
}

/// Returns true if the domain is in the trusted whitelist.
private func isWhitelisted(domain: String, tld: String, urlInfo: inout URLInfo, userTrustedDomains: Set<String> = []) -> Bool {
    let urlOrigin = urlInfo.components.coreURL ?? ""
    let rootDomain = "\(domain).\(tld)"

    if userTrustedDomains.contains(rootDomain) {
        urlInfo.warnings.append(SecurityWarning(
            message: "The domain \(rootDomain) is trusted; further host checks are not required.",
            severity: .info,
            penalty: 0,
            url: urlOrigin,
            source: .host
        ))
        return true
    }
    return false
}
