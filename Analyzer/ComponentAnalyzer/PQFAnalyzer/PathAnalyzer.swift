//
//  PathAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

import Foundation

struct PathAnalyzer {
    
    static func analyze(urlInfo: URLInfo) -> URLInfo {
        var urlInfo = urlInfo
        // Updated regex remains unchanged
        
        if urlInfo.components.path == nil {return urlInfo}

        
        let pathRegex = #"^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%]+\/?)*$"#
        
        // Use percentEncodedPath to account for encoded characters like %2F, %40, %C3%A9
        guard let extractedPath = urlInfo.components.pathEncoded,
              extractedPath.matches(regex: pathRegex) else {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Malformed path structure detected",
                severity: .critical
            ))
            return urlInfo
        }
        
        // Check for suspicious double slashes
        if extractedPath.contains("//") {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Suspicious double slashes in path",
                severity: .critical
            ))
            return urlInfo
        }
        
        // Trim leading & trailing slashes to optimize path depth calculation
        let trimmedPath = extractedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let pathComponents = trimmedPath.split(separator: "/")
        
        // Process each path segment
        for component in pathComponents {
            let segment = String(component)
            
            // Skip known safe paths
            if WhiteList.safePaths.contains(segment.lowercased()) {
                continue
            }
            
            // Split segment into subsegments on '-' if applicable
            let subSegments = segment.contains("-") ? segment.split(separator: "-").map(String.init) : [segment]
            
            // Containers to aggregate scam and phishing keywords for the segment
            var scamMatches = Set<String>()
            var phishingMatches = Set<String>()
            
            for subSegment in subSegments {
                // Check for scam keywords
                if let matchedKeywords = LegitURLTools.findMatchingKeywords(in: subSegment, keywords: SuspiciousKeywords.scamTerms) {
                    scamMatches.formUnion(matchedKeywords)
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.scamWordsInPath
                    continue // Skip further checks for this subsegment
                }
                
                // Check for phishing keywords
                if let matchedKeywords = LegitURLTools.findMatchingKeywords(in: subSegment, keywords: SuspiciousKeywords.phishingWords) {
                    phishingMatches.formUnion(matchedKeywords)
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInPath
                    continue // Skip further checks for this subsegment
                }
                
                // Check for known brand references (info-level warning)
                if let brandReference = LegitURLTools.findMatchingKeywords(in: subSegment, keywords: KnownBrands.names) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "ℹ️ Brand '\(brandReference)' reference detected in path: '\(subSegment)'. This could be a marketing tactic.",
                        severity: .info
                    ))
                    continue
                }
                
                // Check for executable file extensions (only if a dot is present)
                if subSegment.contains(".") {
                    let parts = subSegment.split(separator: ".")
                    if let ext = parts.last {
                        let extensionStr = String(ext).lowercased()
                        if ["exe", "sh", "bat", "dll", "apk", "msi", "scr"].contains(extensionStr) {
                            urlInfo.warnings.append(SecurityWarning(
                                message: "🚨 Executable file extension detected: '\(extensionStr)'",
                                severity: .critical
                            ))
                        }
                    }
                }
                
                // Spell Check: flag if not a recognized word
                if !LegitURLTools.isRealWord(subSegment) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ Unusual path word: '\(subSegment)' (Potentially gibberish or obfuscated)",
                        severity: .suspicious
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.suspiciousPathSegment
                }
                
                // Entropy Check: flag high-entropy segments that may indicate obfuscation
                let (isHighEntropy, entropy) = LegitURLTools.isHighEntropy(subSegment)
                if isHighEntropy {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ High-entropy '\(entropy ?? 0.0) path segment: '\(subSegment)' (Possible obfuscation)",
                        severity: .suspicious
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.highEntropyPathComponent
                }
            }
            
            // Aggregate and report scam-related warnings if any
            if !scamMatches.isEmpty {
                let scamWordsList = scamMatches.joined(separator: ", ")
                urlInfo.warnings.append(SecurityWarning(
                    message: "🚩 Suspicious path segment contains scam-related keywords: \(scamWordsList)",
                    severity: .suspicious
                ))
            }
            
            // Aggregate and report phishing-related warnings if any
            if !phishingMatches.isEmpty {
                let phishingWordsList = phishingMatches.joined(separator: ", ")
                urlInfo.warnings.append(SecurityWarning(
                    message: "🚩 Suspicious path segment contains phishing-related keywords: \(phishingWordsList)",
                    severity: .suspicious
                ))
            }
        }
        
        // Debug output for validated path
        print("Validated Path:", extractedPath)
        return urlInfo
    }
}
