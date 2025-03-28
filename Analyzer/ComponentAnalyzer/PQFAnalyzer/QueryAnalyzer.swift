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
        
        if rawQuery.isEmpty || cleanedQuery.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "Query is empty despite the ? query separator.",
                severity: .suspicious,
                url: urlOrigin,
                source: .offlineAnalysis
            ))
            return(nil)
        }
        
        let pairs = rawQuery.split(separator: "&", omittingEmptySubsequences: false)
        var malformedPairFound = false
        let allowedChars = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~=%:/")

        for pair in pairs {
            let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if components.count != 2 || components[0].isEmpty || components[1].isEmpty {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query pair '\(pair)' is malformed. It should follow key=value format.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                malformedPairFound = true
                continue
            }

            let key = components[0]
            let value = components[1]

            if key.rangeOfCharacter(from: allowedChars.inverted) != nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query key '\(key)' contains forbidden characters.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                malformedPairFound = true
            }

            if value.rangeOfCharacter(from: allowedChars.inverted) != nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query value '\(value)' for key '\(key)' contains forbidden characters.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .offlineAnalysis
                ))
                malformedPairFound = true
            }
        }

        if malformedPairFound {
            urlInfo.warnings.append(SecurityWarning(
                message: "Query does not fully conform to expected key value pair format or character set.",
                severity: .dangerous,
                url: urlOrigin,
                source: .offlineAnalysis
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.malformedQueryPair
            
            // TODO: Clean malformed query before sending to Lamai. Use that instead of rawQuery.
            let deepWarnings = DeepScamHellCheck.analyze(queryOrFragment: rawQuery, isFragment: false, urlOrigin: urlOrigin)
            urlInfo.warnings.append(contentsOf: deepWarnings)
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
            return (nil)
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
