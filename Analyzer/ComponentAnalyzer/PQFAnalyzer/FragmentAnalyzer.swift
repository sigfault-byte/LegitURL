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
            let allowedChars = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~=%:/")
            let isNormalString = fragment.matches(regex: Regex.normalFragmentRegex)

            if isNormalString {
                urlInfo.components.fragmentKeys = []
                urlInfo.components.fragmentValues = [fragment]
            } else {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Fragment is not a normal UI string fragment.",
                    severity: .info
                ))

                let pairs = fragment.split(separator: "&", omittingEmptySubsequences: false)
                var malformedPairFound = false

                for pair in pairs {
                    let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                    if components.count != 2 || components[0].isEmpty || components[1].isEmpty {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Fragment pair '\(pair)' is malformed. Must follow key=value format.",
                            severity: .suspicious
                        ))
                        malformedPairFound = true
                        continue
                    }

                    if pair.rangeOfCharacter(from: allowedChars.inverted) != nil {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Fragment pair '\(pair)' contains forbidden characters.",
                            severity: .suspicious
                        ))
                        malformedPairFound = true
                    }
                }

                if malformedPairFound {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Fragment does not fully conform to expected format or character set.",
                        severity: .critical
                    ))
                    let deepWarnings = DeepScamHellCheck.analyze(queryOrFragment: fragment, isFragment: true)
                    urlInfo.warnings.append(contentsOf: deepWarnings)
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
                    return (urlInfo, nil)
                }

                // If it's a valid query-like fragment, extract key-value pairs and analyze further.
                urlInfo.warnings.append(SecurityWarning(
                    message: "Fragment is 'query-like' and uses key=value pairs.",
                    severity: .info
                ))
                let (keys, values) = KeyValuePairExtract.extractAsArray(from: fragment)
                urlInfo.components.fragmentKeys = keys
                urlInfo.components.fragmentValues = values

                var foundURL: String?
                (urlInfo, foundURL) = KeyValuePairAnalyzer.analyze(urlInfo: &urlInfo, comp: "fragment")
                newURL = foundURL
            }
        }
        
        return (urlInfo, nil)
    }
}
