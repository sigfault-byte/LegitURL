//
//  PathAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

import Foundation

struct PathAnalyzer {
    
    static func analyze(urlInfo: inout URLInfo) {
        guard let rawPath = urlInfo.components.pathEncoded else {
            return
        }

        if !rawPath.hasSuffix("/"), urlInfo.components.query != nil {
            urlInfo.components.isPathEndpointLike = true
            urlInfo.warnings.append(SecurityWarning(
                message: "🧠 Suspicious endpoint-like path followed by query.",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.pathIsEndpointLike
        }

        let pathRegex = #"^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%]+\/?)*$"#
        if !rawPath.matches(regex: pathRegex) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Malformed path structure detected",
                severity: .critical
            ))
            return
        }

        if rawPath.contains("//") {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Suspicious double slashes in path",
                severity: .critical
            ))
            return
        }

        let pathSegmentsToCheck = rawPath.split(separator: "/").map(String.init)
        for segment in pathSegmentsToCheck {
            if segment.rangeOfCharacter(from: .alphanumerics) == nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Suspicious path segment contains no alphanumeric characters: '\(segment)'",
                    severity: .critical
                ))
                return
            }
        }

        let trimmedPath = rawPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let pathSegments = trimmedPath.split(separator: "/").map(String.init)

        for segment in pathSegments {
            guard !segment.isEmpty else { continue }

            if WhiteList.safePaths.contains(segment.lowercased()) {
                continue
            }

            var parts: [String]
            if segment.count < 25 && segment.contains("-") {
                parts = segment.split(separator: "-").map(String.init)
            } else {
                parts = [segment]
            }

            // Apply scam/phishing/brand detection only to top-level path segments
            if parts.count == 1 {
                let part = parts[0]

                if SuspiciousKeywords.scamTerms.contains(part.lowercased()) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🚩 Scam-related word detected in path segment: '\(part)'",
                        severity: .suspicious
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.scamWordsInPath
                }

                if SuspiciousKeywords.phishingWords.contains(part.lowercased()) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🚩 Phishing-related word detected in path segment: '\(part)'",
                        severity: .suspicious
                    ))
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInPath
                }

                if KnownBrands.names.contains(part.lowercased()) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "ℹ️ Brand reference found in path segment: '\(part)'",
                        severity: .info
                    ))
                }

                if part.contains(".") {
                    let pieces = part.split(separator: ".")
                    if let ext = pieces.last?.lowercased(),
                       ["exe", "sh", "bat", "dll", "apk", "msi", "scr"].contains(ext) {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "🚨 Executable file extension detected: '\(ext)'",
                            severity: .critical
                        ))
                    }
                }
            }

            for part in parts {
                if !LegitURLTools.isRealWord(part) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "Path segment '\(part)' is not recognized by the dictionnary.",
                        severity: .info
                    ))
                    let (isHighEntropy, score) = LegitURLTools.isHighEntropy(part)
                    if isHighEntropy, let entropy = score {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Path segment '\(part)' has high entropy (≈ \(String(format: "%.2f", entropy))).",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.highEntropyDomain
                    }
                }
            }
        }

        return
    }
}
