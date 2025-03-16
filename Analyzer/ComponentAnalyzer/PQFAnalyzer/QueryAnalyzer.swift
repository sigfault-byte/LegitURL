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
    static func analyze(urlInfo: URLInfo) -> (URLInfo, String?) {
        var urlInfo = urlInfo
        
        // Get both the raw query and the cleaned (decoded) query.
            guard let rawQuery = urlInfo.components.rawQuery,
                  let cleanedQuery = urlInfo.components.query else {
                return (urlInfo, nil)
            }
        
        if rawQuery.isEmpty || cleanedQuery.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "Query is empty",
                severity: .info
            ))
            return(urlInfo, nil)
        }
        
        // First, check with the strict regex.
        if !rawQuery.matches(regex: Regex.strictQueryRegex) {
            // Strict regex failed.
            let explanation = explainMalformedQuery(query: rawQuery, regexType: .strict)
            urlInfo.warnings.append(SecurityWarning(
                message: "Query does not strictly conform to RFC 3986: \(explanation)",
                severity: .suspicious
            ))
            
            // Now, try the wide regex.
            if rawQuery.matches(regex: Regex.wideQueryRegex) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query passed only when allowing raw '=' or '://' as possible characters.",
                    severity: .suspicious
                ))
            } else {
                // Even wide regex failed.
                // First, explain why it failed normal query checks
                let explanation = explainMalformedQuery(query: rawQuery, regexType: .wide)
                urlInfo.warnings.append(SecurityWarning(
                    message: "Query is malformed and does not have a well-formed key value pair structure: \(explanation)",
                    severity: .critical
                ))

                // Then, run DeepScamHellCheck as a fallback
                let deepWarnings = DeepScamHellCheck.analyze(queryOrFragment: rawQuery, isFragment: false)
                urlInfo.warnings.append(contentsOf: deepWarnings)

                // Always apply a critical penalty, as it failed all checks
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
                return (urlInfo, nil)
            }
        }
        
        // Extract key-value pairs.
        let (keys, values) = KeyValuePairExtract.extractAsArray(from: cleanedQuery)
        urlInfo.components.queryKeys = keys
        urlInfo.components.queryValues = values
        
        
        // Check for forbidden characters.
        let forbiddenWarnings = KeyValuePairExtract.checkForbiddenCharacters(keys: keys, values: values)
        for warning in forbiddenWarnings {
            urlInfo.warnings.append(SecurityWarning(
                message: warning,
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.malformedQueryPair
        }
        
        // Perform additional analysis on key-value pairs.
        var foundURL: String?
        (urlInfo, foundURL) = KeyValuePairAnalyzer.analyze(urlInfo: urlInfo)
        return (urlInfo, foundURL)
    }

    // General-purpose helper for explaining why a string is malformed.
    public static func explainInvalidCharacters(in string: String, allowedSet: CharacterSet, allowPercentEncoding: Bool, componentName: String = "Component") -> String {
        // Check for an empty string first.
        if string.isEmpty {
            return "\(componentName) is missing."
        }
        if let invalidIndex = firstInvalidIndex(in: string, allowedSet: allowedSet, allowPercentEncoding: allowPercentEncoding) {
            let invalidChar = string[string.index(string.startIndex, offsetBy: invalidIndex)]
            let errorSubstring = string[string.index(string.startIndex, offsetBy: invalidIndex)...]
            return "Invalid character '\(invalidChar)' at position \(invalidIndex): \"\(errorSubstring)\""
        }
        return "\(componentName) does not match the required pattern."
    }
    
    // Now we update explainMalformedQuery to accept which regex type is applied.
    public static func explainMalformedQuery(query: String, regexType: QueryRegexType, comp: String = "query") -> String {
        // First, split the query into pairs using '&'
        let pairs = query.split(separator: "&", omittingEmptySubsequences: false)
        for pair in pairs {
            // Each valid pair must contain exactly one "=" separator.
            let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if components.count != 2 {
                return "\(comp.capitalized) pair '\(pair)' is missing the '=' separator."
            }
            let key = String(components[0])
            let value = String(components[1])
            var explanationPrefix = ""
            if comp.lowercased() == "fragment" {
                explanationPrefix = "Fragment query-like: "
            }
            if key.isEmpty {
                return "\(explanationPrefix)Key is missing in \(comp) pair \"\(pair)\"."
            }
            if value.isEmpty {
                return "\(explanationPrefix)Value is missing in \(comp) pair \"\(pair)\"."
            }
        }
        
        // If no pair is missing a key or value, then fall back to character-based explanation.
        let allowedSet: CharacterSet
        switch regexType {
        case .strict:
            // Strict allowed characters: only unreserved.
            allowedSet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        case .wide:
            // Wide allowed characters: unreserved plus raw '=' and ':' and '/'.
            allowedSet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~=%:/")
        }
        return explainInvalidCharacters(in: query, allowedSet: allowedSet, allowPercentEncoding: true, componentName: "Query")
    }
    
    private static func firstInvalidIndex(in component: String, allowedSet: CharacterSet, allowPercentEncoding: Bool) -> Int? {
        var index = component.startIndex
        var offset = 0
        while index < component.endIndex {
            let ch = component[index]
            if ch == "%" && allowPercentEncoding {
                let nextIndex = component.index(index, offsetBy: 3, limitedBy: component.endIndex) ?? component.endIndex
                let percentSequence = component[index..<nextIndex]
                if percentSequence.count < 3 || !percentSequence.dropFirst().allSatisfy({ $0.isHexDigit }) {
                    return offset
                }
                offset += 3
                index = nextIndex
            } else if let scalar = ch.unicodeScalars.first, allowedSet.contains(scalar) {
                index = component.index(after: index)
                offset += 1
            } else {
                return offset
            }
        }
        return nil
    }
}
