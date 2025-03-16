//
//  HostAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 08/03/2025.
//  Refactored on 10/03/2025
//

import Foundation

struct HostAnalyzer {
    
    /// Analyzes URL host components for security risks.
    static func analyze(urlInfo: URLInfo) -> URLInfo {
        var urlInfo = urlInfo
        let components = urlInfo.components
        
        // 1. Validate and force lowercase on required URL components.
        guard let rawHost = components.host,
              let rawPunycodeEncoded = components.punycodeHostEncoded,
              let rawPunycodeDecoded = components.punycodeHostDecoded,
              let rawDomain = components.extractedDomain?.lowercased(),
              //              let punycodeEncodedDomain = rawDomain.idnaEncoded,
              //              let punycodeDecodedDomain = rawDomain.idnaDecoded,
                let rawTld = components.extractedTLD else {
            urlInfo.warnings.append(SecurityWarning(
                message: "Missing essential URL components (host, domain, or TLD).",
                severity: .critical
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
            return urlInfo
        }
        
        // Force lowercase extraction.
        let host = rawHost.lowercased()
        let hostPunycodeEncoded = rawPunycodeEncoded.lowercased()
        let hostPunycodeDecoded = rawPunycodeDecoded.lowercased()
        let domain = rawDomain.lowercased() /*-> Al ready done !!!!url*/
        let tld = rawTld.lowercased()
        let subdomainRaw = components.subdomain?.lowercased()  // may be nil
        
        // 2. Preliminary checks: user info and port.
        checkUserInfo(components: components, urlInfo: &urlInfo, hostPunycode: hostPunycodeEncoded)
        checkPort(components: components, urlInfo: &urlInfo)
        
        // 3. Whitelist check – if trusted, skip further checks.
        if isWhitelisted(domain: domain, tld: tld, urlInfo: &urlInfo) {
            return urlInfo
        }
        
        // 4. Check for direct IP usage.
        checkDirectIP(host: host, urlInfo: &urlInfo)
        
        // 5. Detect homograph attacks at the host level and double check domain.
        checkHomographInHost(host: host, punycodeEncoded: hostPunycodeEncoded, punycodeDecoded: hostPunycodeDecoded, urlInfo: &urlInfo)
        //        checkHomographInDomain(domain: rawDomain, punycodeEncodedDomain: punycodeEncodedDomain, punycodeDecodedDomain: punycodeDecodedDomain, urlInfo: &urlInfo) -> Mightnot be needed
        
        // 6. Analyze domain keywords (including hyphen-split tokens and spell-check suggestions).
        analyzeDomainKeywords(domain: domain, urlInfo: &urlInfo)
        
        // 7. Check TLD reputation.
        checkTLDReputation(tld: tld, urlInfo: &urlInfo)
        
        // 8. Analyze subdomains (if any) with similar keyword checks.
        if let rawSub = subdomainRaw, !rawSub.isEmpty {
            analyzeSubdomains(subdomainString: rawSub, urlInfo: &urlInfo)
        }
        
        return urlInfo
    }
    
    // MARK: - Helper Functions
    
    /// Checks for suspicious user credentials embedded in the URL.
    private static func checkUserInfo(components: URLComponentsInfo, urlInfo: inout URLInfo, hostPunycode: String) {
        if let user = components.userinfo {
            urlInfo.warnings.append(SecurityWarning(
                message: "URL contains userinfo (`\(user)`) which can be a phishing trick!",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.passwordInHost
        }
        if let password = components.userPassword {
            urlInfo.warnings.append(SecurityWarning(
                message: "Password (\(password)) in clear text found in the host (\(hostPunycode)). Highly suspicious.",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.passwordInHost
        }
    }
    
    /// Validates the port number; only HTTPS port (443) is expected.
    private static func checkPort(components: URLComponentsInfo, urlInfo: inout URLInfo) {
        if let port = components.port, port != "443" {
            urlInfo.warnings.append(SecurityWarning(
                message: "The port (\(port)) is not the standard HTTPS (443) port. Highly suspicious.",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.unusualPort
        }
    }
    
    /// Returns true if the domain is in the trusted whitelist.
    private static func isWhitelisted(domain: String, tld: String, urlInfo: inout URLInfo) -> Bool {
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
    
    /// Flags if the host is a direct IP address.
    private static func checkDirectIP(host: String, urlInfo: inout URLInfo) {
        if LegitURLTools.isIPv4(host) || LegitURLTools.isIPv6(host) {
            urlInfo.warnings.append(SecurityWarning(
                message: "Host is a direct IP address, which is highly suspicious.",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.hostIsIpAddress
        }
    }
    
    /// Detects possible homograph attacks by comparing the punycode-decoded and encoded host.
    private static func checkHomographInHost(host: String, punycodeEncoded: String, punycodeDecoded: String, urlInfo: inout URLInfo) {
        // Compare after forcing lowercase.
        if punycodeDecoded != punycodeEncoded {
            urlInfo.warnings.append(SecurityWarning(
                message: "Host has non-standard ASCII encoding (possible homograph attack): \(host) != \(punycodeEncoded).",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.hostNonASCII
        }
    }
    
    /// Detects possible homograph attacks by comparing the punycode-decoded and encoded host. NOT USED
    private static func checkHomographInDomain(domain: String, punycodeEncodedDomain: String, punycodeDecodedDomain: String, urlInfo: inout URLInfo) {
        // Compare after forcing lowercase.
        if punycodeDecodedDomain != punycodeEncodedDomain {
            urlInfo.warnings.append(SecurityWarning(
                message: "Domain has non-standard ASCII encoding (possible homograph attack): \(domain) != \(punycodeEncodedDomain). Be extremely cautious!",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.hostNonASCII
        }
    }
    
    /// Analyzes the domain against known brands and suspicious keywords.
    /// Performs homograph detection, exact match checks (including hyphen-split tokens), and typosquatting checks.
    private static func analyzeDomainKeywords(domain: String, urlInfo: inout URLInfo) {
        let normalizedDomain = domain.normalizedConfusable()
        print("normalizedDomain: ", normalizedDomain, "domain:", domain)
        let isHomograph = (domain != normalizedDomain /*|| domain != domain.idnaEncoded*/) // -> This might be not correct, if domain != idnaEncode -> homograph. Normalize is ONLY for human eyes, for the character that did got mapped to their honograph
        let lowerDomain = normalizedDomain.lowercased()
        
        if isHomograph {
            urlInfo.warnings.append(SecurityWarning(
                message: "Potential homograph attack detected: Domain '\(domain)' normalized to '\(normalizedDomain)'.", /* Normalized is to help human read. Still the punycode needs to be explained and shown */
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.domainNonASCII
        }
        
        
        
        // Exact match check for the whole domain.
        if KnownBrands.names.contains(lowerDomain) {
            if isHomograph {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Critical: Homograph brand impersonation detected: Domain '\(domain)' normalized to '\(normalizedDomain)' impersonates '\(lowerDomain.capitalized)'.",
                    severity: .critical
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack * 2
            } else {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Brand impersonation detected: Domain '\(domain)' exactly matches known brand '\(lowerDomain.capitalized)'.",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack
            }
        } else if SuspiciousKeywords.phishingWords.contains(lowerDomain) || SuspiciousKeywords.scamTerms.contains(lowerDomain) {
            urlInfo.warnings.append(SecurityWarning(
                message: "Direct suspicious keyword detected in domain: '\(domain)' matches a known scam/phishing term.",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
        }
        
        // Hyphen-split check: process each token.
        if domain.contains("-") {
            let tokens = domain.split(separator: "-").map(String.init)
            for token in tokens {
                let normalizedToken = token.normalizedConfusable()
                let lowerToken = normalizedToken.lowercased()
                let isTokenHomograph = (token != normalizedToken)
                if KnownBrands.names.contains(lowerToken) {
                    if isTokenHomograph {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Critical: Homograph brand impersonation detected in domain token '\(token)' (normalized to '\(normalizedToken)') within '\(domain)' impersonates '\(lowerToken.capitalized)'.",
                            severity: .critical
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack * 2
                    } else {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Brand impersonation detected: Domain token '\(token)' in '\(domain)' exactly matches known brand '\(lowerToken.capitalized)'.",
                            severity: .dangerous
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack * 2
                    }
                } else if SuspiciousKeywords.phishingWords.contains(lowerToken) || SuspiciousKeywords.scamTerms.contains(lowerToken) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Direct suspicious keyword detected in domain token: '\(token)' in '\(domain)' matches a known scam/phishing term.",
                        severity: .dangerous
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                } else if !LegitURLTools.isRealWord(lowerToken){
                    urlInfo.warnings.append(SecurityWarning(
                        message: "The domain token '\(lowerToken)' in '\(domain)' appears to be gibberish. This could be a typo, or a deliberate attempt to deceive users.",
                        severity: .suspicious
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                }
            }
        }
        
        // Typosquatting check via spell-check suggestions.
        let suggestionCandidates = LegitURLTools.getAllSpellCheckSuggestions(domain)
        for candidate in suggestionCandidates {
            let lowerCandidate = candidate.lowercased()
            if KnownBrands.names.contains(lowerCandidate) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "🔍 Domain '\(domain)' is similar to known brand '\(candidate.capitalized)'.\nThis may be an innocent coincidence, but could also be intentional obfuscation.",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack
                break
            }
            if SuspiciousKeywords.phishingWords.contains(lowerCandidate) || SuspiciousKeywords.scamTerms.contains(lowerCandidate) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Domain '\(domain)' is similar to scam/phishing term '\(candidate.capitalized)'.\nThis may be an innocent coincidence, or a deliberate attempt to deceive users.",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                break
            }
        }
        // check if the domain is a real world as a fallback if all other fails
        if !LegitURLTools.isRealWord(lowerDomain){
            urlInfo.warnings.append(SecurityWarning(
                message: "The domain '\(lowerDomain)' appears to be gibberish. This could be a typo, or a deliberate attempt to deceive users.",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
        }
    }
    
    /// Validates the reputation of the TLD.
    private static func checkTLDReputation(tld: String, urlInfo: inout URLInfo) {
        let penalty = TLDAnalyzer.getTLDScore(tld)
        if penalty != 0 {
            urlInfo.warnings.append(SecurityWarning(
                message: "The TLD \(tld) has a poor reputation and is often used for phishing.",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += penalty
        }
    }
    
    /// Analyzes subdomains for suspicious patterns using similar checks as for the domain.
    /// - Strips leading "www" if present.
    /// - Flags subdomains ≤ 2 characters as "Suspiciously Short" (unless whitelisted as common acronyms).
    /// - Performs homograph detection, exact match, hyphen-split token analysis, and typosquatting detection.
    private static func analyzeSubdomains(subdomainString: String, urlInfo: inout URLInfo) {
        // Split subdomains on "." and strip leading "www" if present.
        var tokens = subdomainString.split(separator: ".").map { String($0) }
        if let first = tokens.first, first == "www" {
            tokens.removeFirst()
        }
        guard !tokens.isEmpty else { return }
        
        // Process each subdomain.
        for (index, subdomain) in tokens.enumerated() {
            let normalized = subdomain.normalizedConfusable()
            let lowerSubdomain = normalized.lowercased()
            let isHomograph = (subdomain != normalized)
            
            // Homograph detection.
            if isHomograph {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Potential homograph attack detected in subdomain \(index + 1): '\(subdomain)' normalized to '\(normalized)'.",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack
            }
            
            // Check for suspiciously short subdomains (≤2 characters) that are not common acronyms.
            if subdomain.count <= 3 && !WhiteList.commonAcronyms.contains(subdomain) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Subdomain '\(subdomain)' is suspiciously short.",
                    severity: .suspicious
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.shortSubdomain
            }
            
            // Exact match check.
            if KnownBrands.names.contains(lowerSubdomain) {
                if isHomograph {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Critical: Homograph brand impersonation detected in subdomain \(index + 1): '\(subdomain)' normalized to '\(normalized)' impersonates '\(lowerSubdomain.capitalized)'.",
                        severity: .critical
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack * 2
                } else {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Brand impersonation detected in subdomain \(index + 1): '\(subdomain)' exactly matches known brand '\(lowerSubdomain.capitalized)'.",
                        severity: .dangerous
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack
                }
            } else if SuspiciousKeywords.phishingWords.contains(lowerSubdomain) || SuspiciousKeywords.scamTerms.contains(lowerSubdomain) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Direct suspicious keyword detected in subdomain \(index + 1): '\(subdomain)' matches a known scam/phishing term.",
                    severity: .dangerous
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
            }
        
            // Hyphen-split check: process tokens from subdomain.
            if subdomain.contains("-") {
                let parts = subdomain.split(separator: "-").map { String($0) }
                for part in parts {
                    let normalizedPart = part.normalizedConfusable()
                    let lowerPart = normalizedPart.lowercased()
                    let isPartHomograph = (part != normalizedPart)
                    if KnownBrands.names.contains(lowerPart) {
                        if isPartHomograph {
                            urlInfo.warnings.append(SecurityWarning(
                                message: "Critical: Homograph brand impersonation detected in subdomain \(index + 1) token '\(part)' (normalized to '\(normalizedPart)') within '\(subdomain)' impersonates '\(lowerPart.capitalized)'.",
                                severity: .critical
                            ))
                            URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack * 2
                        } else {
                            urlInfo.warnings.append(SecurityWarning(
                                message: "Brand impersonation detected in subdomain \(index + 1): Token '\(part)' in '\(subdomain)' exactly matches known brand '\(lowerPart.capitalized)'.",
                                severity: .dangerous
                            ))
                            URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack
                        }
                    } else if SuspiciousKeywords.phishingWords.contains(lowerPart) || SuspiciousKeywords.scamTerms.contains(lowerPart) {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Direct suspicious keyword detected in subdomain \(index + 1): Token '\(part)' in '\(subdomain)' matches a known scam/phishing term.",
                            severity: .dangerous
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                    } else if !LegitURLTools.isRealWord(lowerPart){
                        urlInfo.warnings.append(SecurityWarning(
                            message: "The \(index + 1) subdomain '\(subdomain)' has a token '\(lowerPart)', that appears to be gibberish. This could be a typo, or a deliberate attempt to deceive users.",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                    }
                }
                // fallback to check if subdomain is gibberish
            } else if !LegitURLTools.isRealWord(subdomain){
                urlInfo.warnings.append(SecurityWarning(
                    message: "The subdomain '\(subdomain)', appears to be gibberish. This could be a typo, or a deliberate attempt to deceive users.",
                    severity: .suspicious
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
            }
            
            // Typosquatting detection for the subdomain using spell-check suggestions.
            let suggestionCandidates = LegitURLTools.getAllSpellCheckSuggestions(subdomain)
            for candidate in suggestionCandidates {
                let lowerCandidate = candidate.lowercased()
                if KnownBrands.names.contains(lowerCandidate) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Typosquatting detected in subdomain \(index + 1): '\(subdomain)' is similar to known brand '\(candidate.capitalized)'.",
                        severity: .dangerous
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.homoGraphAttack
                    break
                }
                if SuspiciousKeywords.phishingWords.contains(lowerCandidate) || SuspiciousKeywords.scamTerms.contains(lowerCandidate) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Typosquatting detected in subdomain \(index + 1): '\(subdomain)' is similar to a scam/phishing term '\(candidate.capitalized)'.",
                        severity: .dangerous
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInHost
                    break
                }
            }
        }
    }
}
