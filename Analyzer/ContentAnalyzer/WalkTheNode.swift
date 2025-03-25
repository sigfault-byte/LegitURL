struct WalkTheNode {
    
    static func analyze(node: DecodedNode, urlInfo: inout URLInfo, comp: String = "query", label: String) -> String? {
        var foundURLs: [String] = []
        var didWarnForDepth = false

        func walk(_ node: DecodedNode) {
            if !didWarnForDepth && node.depth > 1 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "👁️ Decoded value detected by Lamai in \(comp) \(label). This was found through recursive decoding. Check the URLComponent tree for decoding layers.",
                    severity: .info
                ))
                didWarnForDepth = true
            }
            if node.wasRelevant {
                for finding in node.findings {
                    switch finding {
                    case .url(let url):
                        foundURLs.append(url)
                        urlInfo.warnings.append(SecurityWarning(
                            message: "🔗 Found URL in \(comp) \(label): \(url)",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.urlInQueryValue
                        
                    case .uuid(let result):
                        let uuidText = result.formatted ?? result.original
                        urlInfo.warnings.append(SecurityWarning(
                            message: "🧬 UUID in \(comp) \(label): \(uuidText) (\(result.classification))",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.uuidInQuery
                        
                    case .scamWord(let word):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "⚠️ Scam keyword in \(comp) \(label): \(word)",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInValue
                        
                    case .phishingWord(let word):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "⚠️ Phishing keyword in \(comp) \(label): \(word)",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInValue
                        
                    case .entropy(let score, let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "🧪 High entropy in \(comp) \(label): '\(value)' (≈ \(String(format: "%.2f", score)))",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.highEntropyKeyOrValue
                        
                        
                    case .longEntropyLike(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "🧪 Suspicious long query value in \(comp) \(label): '\(value)'",
                            severity: .info
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.longUnrecognisedValue
                        
                    case .isIPv4(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "📡 IPv4 address in \(comp) \(label): '\(value)'",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.hiddenIP
                        
                    case .isIPv6(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "📡 IPv6 address in \(comp) \(label): '\(value)'",
                            severity: .suspicious
                        ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.hiddenIP
                        
                    case .email(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "📧 Email address in \(comp) \(label): '\(value)'",
                            severity: .suspicious
                            ))
                        URLQueue.shared.LegitScore += PenaltySystem.Penalty.hiddenIP
                    }
                }
            }
            for child in node.children {
                walk(child)
            }
        }

        walk(node)

        if checkMultipleURLs(foundURLs, urlInfo: &urlInfo, comp: comp) {
            return nil
        }

        if foundURLs.count == 1 {
            return foundURLs.first
        }

        return nil
    }
    
}

private func checkMultipleURLs(_ foundURLs: [String?], urlInfo: inout URLInfo, comp: String) -> Bool {
    let nonNilURLs = foundURLs.compactMap { $0 } // Remove nil values
    if nonNilURLs.count > 1 {
        let urlList = nonNilURLs.joined(separator: "\n") // Format URLs on new lines
        urlInfo.warnings.append(SecurityWarning(
            message: "❌ Multiple URLs detected in \(comp) parameters. This is highly suspicious:\n\(urlList)",
            severity: .critical
        ))
        URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
        return true  // 🚨 Indicate that analysis should halt
    }
    return false  // ✅ Continue normally
}
