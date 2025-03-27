//
//  NodeAnalyzer.swift
//  URLChecker
//
//  Created by Chief Hakka on 25/03/2025.
//
import Foundation

struct NodeAnalyzer {
    
    /// Detect email addresses in a string.
    /// - Returns: `[String]?` — `nil` if no emails were found, otherwise an array of found emails.
    static func detectEmail(_ value: String) -> [String]? {
        let emails = LegitURLTools.detectEmailAddresses(in: value)
        return emails.isEmpty ? nil : emails
    }
    
    /// Check if an IP is detected (IPv4 or IPv6)
    static func checkIfIp4(_ value: String) -> String? {
        if LegitURLTools.isIPv4(value) {
            return value
        }
        return nil
    }
    static func checkIfIPv6(_ value: String) -> String? {
        if LegitURLTools.isIPv6(value) {
            return value
        }
        return nil
    }
    
    // Look if the value is a url
    static func detectURL(_ value: String) -> String? {
        if LegitURLTools.isValueURL(value) {
            return value
        }
        return nil
    }
    
    // Look if the value is one or many uuid CORRECTLY structured and return a struc with details of the uuid(s)
    static func detectUUIDs(from value: String) -> [DecodingTools.UUIDAnalysisResult] {
        var results: [DecodingTools.UUIDAnalysisResult] = []
        
        // Direct check: if the entire value is a possible UUID
        if value.count == 36 || value.count == 32 {
            let directResult = DecodingTools.analyzeUUID(value)
            if directResult.classification != "Not a UUID" {
                results.append(directResult)
            }
        }
        
        // Chunk check: if the string's length suggests multiple concatenated UUIDs
        if (value.count >= 32 && value.count % 32 == 0) || (value.count >= 36 && value.count % 36 == 0) {
            let chunkSize = value.contains("-") ? 36 : 32
            // Use non-overlapping chunks
            for chunkStart in stride(from: 0, to: value.count - chunkSize + 1, by: chunkSize) {
                let startIndex = value.index(value.startIndex, offsetBy: chunkStart)
                let endIndex = value.index(startIndex, offsetBy: chunkSize)
                let possibleUUID = String(value[startIndex..<endIndex])
                
                let chunkResult = DecodingTools.analyzeUUID(possibleUUID)
                if chunkResult.classification != "Not a UUID" {
                    results.append(chunkResult)
                }
            }
        }
        let unique = Dictionary(grouping: results, by: { $0.formatted ?? $0.original })
            .compactMap { $0.value.first }
        
        return unique
    }
    
    // Look for scamWords
    static func detectScanWords(_ value: String) -> String?{
        if SuspiciousKeywords.scamTerms.contains(value) {
            return value
        }
        return nil
    }
    
    // Look for phishingWords
    static func detectPhishingWords(_ value: String) -> String?{
        if SuspiciousKeywords.phishingWords.contains(value) {
            return value
        }
        return nil
    }
    
    // Check if value containt any redirect or js know word that scream exploit scam or phishing
    static func detectExploitWords(_ value: String) -> String?{
        if SuspiciousKeywords.redirectAndJSExploitationKeywords.contains(where: value.contains) {
            return value
        }
        return nil
    }
    
    // Check if its a word in the dictionnary, if not, check its entropy
    static func checkIfRealWordAndEntropy(_ value: String) -> DecodedNode.NodeFinding? {
        if !LegitURLTools.isRealWord(value) {
            let (isHighEntropy, entropyValue) = LegitURLTools.isHighEntropy(value)
            if isHighEntropy, let entropy = entropyValue {
                return .entropy(score: Double(entropy), value: value)
            }
//             If long and low entropy, still suspicious
            if value.count >= 50 {
                return .longEntropyLike(value: value)
            }
        }
        return nil
    }
}
