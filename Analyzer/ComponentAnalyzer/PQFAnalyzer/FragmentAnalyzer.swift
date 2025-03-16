//
//  FragmentAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 12/03/2025.
//

import Foundation

struct FragmentAnalyzer {
    static func analyze(urlInfo: URLInfo) -> (URLInfo, String?) {
        var urlInfo = urlInfo
        var newURL: String? = nil
        
        if let fragment = urlInfo.components.fragment {
            // First, check if the fragment is a “normal” UI fragment.
            if fragment.matches(regex: Regex.normalFragmentRegex) {
                urlInfo.components.fragmentKeys = []
                urlInfo.components.fragmentValues = [fragment]
            }
            else if fragment.matches(regex: Regex.wideQueryRegex) {
                // The fragment isn't "normal" but it matches our wide query regex,
                // so we treat it as a query-like fragment.
                urlInfo.warnings.append(SecurityWarning(
                    message: "Fragment is 'query-like.' and uses key=value pairs",
                    severity: .info
                ))
                // Extract key-value pairs from the fragment.
                let (keys, values) = KeyValuePairExtract.extractAsArray(from: fragment)
                urlInfo.components.fragmentKeys = keys
                urlInfo.components.fragmentValues = values
                
                // Optionally, check for forbidden characters.
                let forbiddenWarnings = KeyValuePairExtract.checkForbiddenCharacters(keys: keys, values: values, comp: "fragment")
                for warning in forbiddenWarnings {
                    urlInfo.warnings.append(SecurityWarning(
                        message: warning,
                        severity: .info
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.malformedFragment
                }
                
                // Run additional analysis on key-value pairs.
                var foundURL: String?
                (urlInfo, foundURL) = KeyValuePairAnalyzer.analyze(urlInfo: urlInfo, comp: "fragment")
                newURL = foundURL
            }
            else {
                // First, explain why it failed normal checks
                let explanation = QueryAnalyzer.explainMalformedQuery(query: fragment, regexType: .wide, comp: "fragment")
                urlInfo.warnings.append(SecurityWarning(
                    message: "Fragment is neither a valid UI fragment nor a structured query-like fragment: \(explanation)",
                    severity: .critical
                ))

                // Then, run DeepScamHellCheck as a fallback
                let deepWarnings = DeepScamHellCheck.analyze(queryOrFragment: fragment, isFragment: true)
                urlInfo.warnings.append(contentsOf: deepWarnings)

                // Always apply a critical penalty, as it failed all checks
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
                return (urlInfo, nil)
            }
        }
        
        return (urlInfo, nil)
    }
}
