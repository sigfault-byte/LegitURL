struct PQFAnalyzer {
    
    static func analyze(urlInfo: inout URLInfo) -> String? {
        var newURL: String?
        let urlOrigin = urlInfo.components.coreURL ?? ""
        
        // Bad strict check of #? and ?#
        //TODO -> send to lamai? Is it really necessary, this is obvious bait
        if let rawURL = urlInfo.components.fullURL {
            if rawURL.contains("#?") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "The URL contains a fragment (`#`) before a query (`?`). This is obfuscation by design.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlOrigin,
                    source: .fragment
                ))
                return (nil)
                
            } else if rawURL.contains("?#") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "The URL contains a query (`?`) before a fragment (`#`). This is obfuscation by design.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlOrigin,
                    source: .query
                ))
                return (nil)
            }
        }
        
//         Analyze path: if the path is not just "/", process it.
        if urlInfo.components.path != "/" {
            PathAnalyzer.analyze(urlInfo: &urlInfo)
        }
        
        // Analyze Query:
        // Use the cleaned query if non-empty; otherwise, if a raw query exists but is empty, trigger a warning.
        if let query = urlInfo.components.query, !query.isEmpty {
            newURL = QueryAnalyzer.analyze(urlInfo: &urlInfo)
        } else if let rawQuery = urlInfo.components.rawQuery, rawQuery.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "The URL contains an empty query section (i.e., nothing follows '?').",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.emptyQuery,
                url: urlOrigin,
                source: .query
            ))
        }
        
//         Analyze Fragment:
//         If the fragment is non-empty, process it; if it's present but empty, trigger a warning.
        if let fragment = urlInfo.components.fragment, !fragment.isEmpty {
            (newURL) = FragmentAnalyzer.analyze(urlInfo: &urlInfo)
        } else if let rawFragment = urlInfo.components.fragment, rawFragment.isEmpty {
            urlInfo.warnings.append(SecurityWarning(
                message: "The URL contains an empty fragment section (i.e., nothing follows '#').",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.emptyQuery,
                url: urlOrigin,
                source: .fragment
            ))
        }
        
        return newURL
    }
}
