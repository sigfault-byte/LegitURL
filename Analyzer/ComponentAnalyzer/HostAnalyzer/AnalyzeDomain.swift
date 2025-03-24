//
//  AnalyzeDomain.swift
//  URLChecker
//
//  Created by Chief Hakka on 22/03/2025.
//
////Handles domain-only logic:
//•    Whitelist checks
//•    tryToDecode + replacements
//•    Levenshtein against known brands
//•    Entropy and spelling penalties
//•    Possibly avoids _ splits (as planned)
//"раураӏ.com", "ɡооɡΙе.com", "facebоok.com", "gíthùb.com", "paypal.com" -> homograph
import Punycode

struct AnalyzeDomain {
    static func analyze(in urlInfo: inout URLInfo, domain: String, tld: String) {
        // Step 1: Compare punycode-encoded and decoded versions.
        // If they differ, keep both for deeper analysis.
        let idnaEncodedDomain = urlInfo.components.idnaEncodedExtractedDomain ?? ""
        let idnaDecodedDomain = urlInfo.components.idnaDecodedExtractedDomain ?? ""

        if domain != idnaEncodedDomain || domain != idnaDecodedDomain || idnaDecodedDomain != idnaEncodedDomain {
            urlInfo.warnings.append(SecurityWarning(
                message: "Domain '\(domain)' mismatch: '\(idnaDecodedDomain)' decoded from '\(idnaEncodedDomain)'. Possible homograph or internationalized domain.",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.domainNonASCII
        }
        
        // Step 2: Script analysis on the DECODED!
        checkScriptMismatch(domain: idnaDecodedDomain, tld: tld, urlInfo: &urlInfo)
        
        // Step 3: WhiteList check
        if isWhitelisted(domain: idnaEncodedDomain.lowercased(), tld: tld, urlInfo: &urlInfo) {
            return
        }
                
        // Step 4: Normalize domain input into array of tokens.
        let domainParts = domain.contains("-") ? domain.split(separator: "-").map(String.init) : [domain]

        if domainParts.count >= 5 {
            urlInfo.warnings.append(SecurityWarning(
                message: "Domain '\(domain)' contains \(domainParts.count) segments split by hyphens, which may be an attempt to obfuscate.",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.tooManyHyphensInDomain
        }
        
        // Step 5: Iterate over each domain token for analysis.
        for part in domainParts {
            if checkForBrandMatch(in: part, urlInfo: &urlInfo) {
                continue // Skip remaining checks for this part
            }

            if checkForPhishingKeyword(in: part, urlInfo: &urlInfo) {
                continue // Skip entropy if phishing/scam term found
            }

            if !LegitURLTools.isRealWord(part) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain segment '\(part)' was not found in the user's English dictionary.",
                    severity: .info
                ))
                let (isHighEntropy, score) = LegitURLTools.isHighEntropy(part)
                if isHighEntropy, let entropy = score {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Domain segment '\(part)' has high entropy (≈ \(String(format: "%.2f", entropy))).",
                        severity: .suspicious
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.highEntropyDomain
                }
            }
        }
    }

    private static func checkForBrandMatch(in part: String, urlInfo: inout URLInfo) -> Bool {
        for brand in KnownBrands.names {
            if part.lowercased().contains(brand) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain segment '\(part)' contains known brand '\(brand)'.",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.brandImpersonation
                return true
            } else if LegitURLTools.levenshtein(part.lowercased(), brand) <= 2 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain segment '\(part)' is similar to known brand '\(brand)' (Levenshtein ≤ 2).",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.brandLookaLike
                return true
            }
        }
        return false
    }
    
    private static func checkForPhishingKeyword(in part: String, urlInfo: inout URLInfo) -> Bool {
        let lower = part.lowercased()

        for keyword in SuspiciousKeywords.phishingWords {
            if lower.contains(keyword) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain segment '\(part)' contains phishing-related keyword '\(keyword)'.",
                    severity: .suspicious
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                return true
            }
        }

        for scam in SuspiciousKeywords.scamTerms {
            if lower.contains(scam) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain segment '\(part)' contains scam-related term '\(scam)'.",
                    severity: .suspicious
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.scamWordsInHost
                return true
            }
        }
        return false
    }
}

private func checkScriptMismatch(domain: String, tld: String, urlInfo: inout URLInfo) {
    let scriptSet = analyzeUnicodeScripts(in: domain)
    let tldScriptSet = analyzeUnicodeScripts(in: tld)

    if scriptSet.count == 1 {
        if scriptSet.contains(.ascii) {
            // It's just plain ASCII — no need to warn.
            return
        }
        if let script = scriptSet.first, !tldScriptSet.contains(script) {
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Domain '\(domain)' uses only \(script) characters, but its TLD '\(tld)' is from a different script family.",
                severity: .critical
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
            return
        } else {
            urlInfo.warnings.append(SecurityWarning(
                message: "ℹ️ Domain '\(domain)' is fully non-Latin but matches the script of the TLD '\(tld)'.",
                severity: .info
            ))
        }
    } else if scriptSet.contains(.ascii) && scriptSet.contains(.latinExtended) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Domain '\(domain)' mixes basic Latin and Extended Latin characters, which may indicate subtle obfuscation.",
            severity: .suspicious
        ))
        URLQueue.shared.LegitScore += PenaltySystem.Penalty.domainNonASCII
    } else if scriptSet.contains(.ascii) && (scriptSet.contains(.cyrillic) || scriptSet.contains(.greek)) {
        print("hello")
        urlInfo.warnings.append(SecurityWarning(
            message: "🚨 Domain '\(domain)' mixes Latin and non-Latin characters, which strongly indicates a homograph attack.",
            severity: .critical
        ))
        URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
        return
    } else if scriptSet.contains(.cyrillic) || scriptSet.contains(.greek) || scriptSet.contains(.other) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Domain '\(domain)' contains non-Latin characters, which may be deceptive.",
            severity: .suspicious
        ))
        URLQueue.shared.LegitScore += PenaltySystem.Penalty.domainNonASCII
    }
}

/// Returns true if the domain is in the trusted whitelist.
private func isWhitelisted(domain: String, tld: String, urlInfo: inout URLInfo) -> Bool {
    let rootDomain = "\(domain).\(tld)"
    if WhiteList.trustedDomains.contains(rootDomain) {
        urlInfo.warnings.append(SecurityWarning(
            message: "The domain \(rootDomain) is trusted; further host checks are not required.",
            severity: .info
        ))
        return true
    }
    return false
}
