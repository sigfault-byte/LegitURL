import Foundation
struct PQFAnalyzer {
    
    static func analyze(urlInfo: inout URLInfo) -> String? {
        var newURL: String?
        let urlOrigin = urlInfo.components.coreURL ?? ""
        
        // Bad strict check of #? and ?#
        //TODO -> send to lamai? Is it really necessary, this is obvious bait
        if let rawURL = urlInfo.components.fullURL {
            let (query, fragment) = (rawURL.contains("?#"), rawURL.contains("#?"))
            let source = query ? SecurityWarning.SourceType.query : SecurityWarning.SourceType.fragment
            var decodedBlob = ""
            if query || fragment {
                if var blob = query ? urlInfo.components.query : urlInfo.components.fragment {
                    blob.removeFirst()
                    if let normalizedBlob = DecodingTools.normalizeBase64(blob){
                        if let data = Data(base64Encoded: normalizedBlob) {
                            if let b64Str = String(data: data, encoding: .utf8){
                                decodedBlob = b64Str
                            }
                        }
                    }
                }
                var label = query
                    ? "Query parameter is prefixed with a '#' — "
                    : "Fragment parameter is prefixed with a '?' — "
                label += "This is an obfuscation attempt to trick parsers."
                let subMessage = decodedBlob.isEmpty ? "" : "\nThe base64 payload is: \(decodedBlob)"
                urlInfo.warnings.append(SecurityWarning(
                    message: label + subMessage,
                    severity: SecurityWarning.SeverityLevel.critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlOrigin,
                    source: source
                ))
                return(nil)
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
