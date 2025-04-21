import Foundation
struct PathAnalyzer {
    
    static func analyze(urlInfo: inout URLInfo) {
        
        let urlOrigin = urlInfo.components.coreURL ?? ""
        var foundURL: [String] = []
        guard let rawPath = urlInfo.components.pathEncoded else {
            return
        }

        if !rawPath.hasSuffix("/"), urlInfo.components.query != nil {
            urlInfo.warnings.append(SecurityWarning(
                message: "🧠 Suspicious endpoint-like path followed by query.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.pathIsEndpointLike,
                url: urlOrigin,
                source: .path,
                bitFlags: WarningFlags.PATH_ENDPOINTLIKE
            ))
        }
        
        let pathRegex = #"^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%]+\/?)*$"#
        if !rawPath.matches(regex: pathRegex) {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Malformed path structure detected",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .path
            ))
            return
        }
        
        if rawPath.contains("//") {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ Suspicious double slashes in path",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .path
            ))
            return
        }
        
        let pathSegmentsToCheck = rawPath.split(separator: "/").map(String.init)
        for segment in pathSegmentsToCheck {
            if segment.rangeOfCharacter(from: .alphanumerics) == nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Suspicious path segment contains no alphanumeric characters: '\(segment)'",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlOrigin,
                    source: .path
                ))
                return
            }
        }
        
        let trimmedPath = rawPath.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let pathSegments = trimmedPath.split(separator: "/").map(String.init)
        
        for segment in pathSegments {
            guard !segment.isEmpty else { continue }
//            This should be a var, but is a let while the combo is not working properly
            let comboWasRelevant = false
            
            // This needs more thinking
            if WhiteList.safePaths.contains(segment.lowercased()) {
                continue
            }
            
//            // Try all contiguous path combinations from this segment onward
//            TODO: This needs more thinking the logic fails because multiple warning are given for the same warning.
//            MAYBE: Traverse the node tree just like WalkTheNode
//            Collect all findings with their associated source labels, values, scores, etc.
//            Store them in a temporary buffer
//            Apply deduplication / suppression / scoring consolidation
//            THEN emit a final filtered list of warnings but this will be for a later update 1.0 will not do it
            
//            let index = pathSegments.firstIndex(of: segment) ?? 0
//            for endIndex in index..<pathSegments.count {
//                let combo = pathSegments[index...endIndex].joined(separator: "/")
//                guard combo.count > 4 else { continue }
//                let valueNode = LamaiDecoding.decode(input: combo, maxDepth: 6)
//                if valueNode.findings.onlyContainsEntropy {
//                    continue // Skip saving pure entropy-only combos
//                }
//                if valueNode.hasDeepDescendant() {
//                    comboWasRelevant = true
//                }
//                let label = "combo\(index)-\(endIndex)"
//                let url = WalkTheNode.analyze(node: valueNode, urlInfo: &urlInfo, comp: "path", label: label)
//                if let url = url, !url.isEmpty {
//                    foundURL.append(url)
//                }
//            }
            
            
            var parts: [String]
            if segment.count > 64 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Suspiciously long path segment: (\(segment.count) chars / \(segment.utf8.count) bytes)",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.suspiciousPathSegment,
                    url: urlOrigin,
                    source: .path,
                    bitFlags: WarningFlags.PATH_OBFUSCATED_STRUCTURE
                ))
            }
            let isSuspiciouslyLong = segment.count > 64
            let hasHyphen = segment.contains("-")
            
//            Irrelevant without the pathcombo logic
//            if comboWasRelevant { return }
            if !comboWasRelevant {
                if !isSuspiciouslyLong && hasHyphen {
                    parts = segment.split(separator: "-").map(String.init)
                } else {
                    parts = [segment]
                }
                var partNumber: Int = 0
                for part in parts {
                    let delimiters: [Character] = ["+", "|", ":", ";", "~", "_"]
                    var subParts: [String] = [part]
                    
                    for delimiter in delimiters {
                        if part.contains(delimiter) {
                            subParts = part.split(separator: delimiter).map(String.init)
                            break
                        }
                    }
                    
                    //Real words are not flagged correctly
                    for (subIndex, subPart) in subParts.enumerated() {
                        guard subPart.count > 4 else { continue }
                        let valueNode = LamaiDecoding.decode(input: subPart, maxDepth: 6)
                        if valueNode.hasDeepDescendant() {
                            urlInfo.components.lamaiTrees[.path, default: []].append(valueNode)
                        }
                        partNumber += 1
                        let label = "part\(partNumber).sub\(subIndex)"
                        if let url = WalkTheNode.analyze(node: valueNode, urlInfo: &urlInfo, comp: "path", label: label), !url.isEmpty {
                            foundURL.append(url)
                        }
                    }
                }
            }
        }
        return
    }
}
