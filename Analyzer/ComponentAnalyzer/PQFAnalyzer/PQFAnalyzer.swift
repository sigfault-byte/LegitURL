//
//  PQFAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

struct PQFAnalyzer {
    
    static func analyze(urlInfo: URLInfo) -> (URLInfo, String?) {
        var urlInfo = urlInfo
        var newURL: String?
        
        // Bad strict check of #? and ?#
        if let rawURL = urlInfo.components.fullURL {
            if rawURL.contains("#?") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "The URL contains a fragment (`#`) before a query (`?`).\nThis is an obfuscation technique used by scammers to manipulate URL parsing and tracking systems.",
                    severity: .critical
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
                return (urlInfo, nil)
            } else if rawURL.contains("?#") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "The URL contains a query (`?`) before a fragment (`#`).\nThis is an obfuscation technique used by scammers to manipulate URL parsing and tracking systems.",
                    severity: .critical
                ))
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
                return (urlInfo, nil)
            }
        }
        
        // Analyze path: if the path is not just "/", process it.
        if urlInfo.components.path != "/" {
            urlInfo = PathAnalyzer.analyze(urlInfo: urlInfo)
        }
        
        // Analyze Query:
        // Use the cleaned query if non-empty; otherwise, if a raw query exists but is empty, trigger a warning.
        if let query = urlInfo.components.query, !query.isEmpty {
            (urlInfo, newURL) = QueryAnalyzer.analyze(urlInfo: urlInfo)
        } else if let rawQuery = urlInfo.components.rawQuery, rawQuery.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "The URL contains an empty query section (i.e., nothing follows '?').",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.emptyQueryString
        }
        
        // Analyze Fragment:
        // If the fragment is non-empty, process it; if it's present but empty, trigger a warning.
        if let fragment = urlInfo.components.fragment, !fragment.isEmpty {
            (urlInfo, newURL) = FragmentAnalyzer.analyze(urlInfo: urlInfo)
        } else if let rawFragment = urlInfo.components.fragment, rawFragment.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "The URL contains an empty fragment section (i.e., nothing follows '#').",
                severity: .suspicious
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.emptyFragment
        }
        
        
        return (urlInfo, newURL)
    }
}
