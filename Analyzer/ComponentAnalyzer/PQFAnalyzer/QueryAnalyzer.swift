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
        
        // Get both the raw query and the cleaned (decoded) query.
        guard let rawQuery = urlInfo.components.rawQuery,
              let cleanedQuery = urlInfo.components.query else {
            return (nil)
        }
        
        if rawQuery.isEmpty || cleanedQuery.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "Query is empty",
                severity: .info
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
                    message: "Query pair '\(pair)' is malformed. Must follow key=value format.",
                    severity: .suspicious
                ))
                malformedPairFound = true
                continue
            }

            if pair.rangeOfCharacter(from: allowedChars.inverted) != nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query pair '\(pair)' contains forbidden characters.",
                    severity: .suspicious
                ))
                malformedPairFound = true
            }
        }

        if malformedPairFound {
            urlInfo.warnings.append(SecurityWarning(
                message: "Query does not fully conform to expected format or character set.",
                severity: .critical
            ))
            let deepWarnings = DeepScamHellCheck.analyze(queryOrFragment: rawQuery, isFragment: false)
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
