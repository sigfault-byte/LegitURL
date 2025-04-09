//
//  QueryAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//
import Foundation


enum QueryRegexType {
    case strict
    case wide
}

struct QueryAnalyzer {
    static func analyze(urlInfo: inout URLInfo) -> (String?) {
        let urlOrigin = urlInfo.components.host ?? ""
        // Get both the raw query and the cleaned (decoded) query.
        guard let rawQuery = urlInfo.components.rawQuery,
              let cleanedQuery = urlInfo.components.query else {
            return (nil)
        }
        
        // This is surely useless, but also double checks the query and raw query relationship
        if rawQuery.isEmpty || cleanedQuery.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "Query is empty despite the ? query separator.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.emptyQuery,
                url: urlOrigin,
                source: .query
            ))
            return(nil)
        }
        
        let pairs = rawQuery.split(separator: "&", omittingEmptySubsequences: false)
        var malformedPairFound = false
        let allowedKeyChars = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let allowedValueChars = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~=%:/@")
        
        for pair in pairs {
            let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if components.count != 2 || components[0].isEmpty || components[1].isEmpty {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query pair '\(pair)' is malformed. It should follow key=value format.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.malformedQueryPair,
                    url: urlOrigin,
                    source: .query
                ))
                malformedPairFound = true
                continue
            }
            
            let key = components[0]
            let value = components[1]
            
            if key.rangeOfCharacter(from: allowedKeyChars.inverted) != nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query key '\(key)' contains forbidden characters.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.queryKeyForbiddenCharacters,
                    url: urlOrigin,
                    source: .query
                ))
                malformedPairFound = true
            }
            
            if key == key.uppercased(), key.count > 8 {
                let (isHigh, score) = LegitURLTools.isHighEntropy(String(key), 4.3)
                if isHigh, let entropy = score {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Query key '\(key)' is all uppercase and appears to be random or encoded (entropy ≈ \(String(format: "%.2f", entropy))).",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.keyIsHighEntropy,
                        url: urlOrigin,
                        source: .query
                    ))
                }
                
                if value.rangeOfCharacter(from: allowedValueChars.inverted) != nil {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Query value '\(value)' for key '\(key)' contains forbidden characters.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.valueForbiddenCharacters,
                        url: urlOrigin,
                        source: .query
                    ))
                    malformedPairFound = true
                }
            }
            
            if malformedPairFound {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query does not fully conform to expected key value pair format or character set.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.malformedQueryPair,
                    url: urlOrigin,
                    source: .query
                ))
                
                //            // TODO: This is useless, we all ready know this failed the key=value contract. See later!
                //            let deepWarnings = DeepScamHellCheck.analyze(queryOrFragment: rawQuery, isFragment: false, urlOrigin: urlOrigin)
                //            urlInfo.warnings.append(contentsOf: deepWarnings)
                
                return (nil)
            }
        }
        // Extract key-value pairs.
        let (keys, values) = KeyValuePairExtract.extractAsArray(from: cleanedQuery)
        urlInfo.components.queryKeys = keys
        urlInfo.components.queryValues = values
        
        
        // Perform  analysis on key-value pairs.
        var foundURL: String?
        (urlInfo, foundURL) = KeyValuePairAnalyzer.analyze(urlInfo: &urlInfo)
        return (foundURL)
    }
}
