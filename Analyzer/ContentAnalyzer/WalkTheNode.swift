struct WalkTheNode {
    
    static func walkAndAnalyze(node: DecodedNode, urlInfo: inout URLInfo, comp: String = "query", label: String) -> String? {
        var newURL: [String?] = []
        let isLeaf = node.children.isEmpty
        let isFullyDecoded = node.decoded != nil && isLeaf
        let isRawLeaf = node.decoded == nil && isLeaf
        node.printTree()
        
        let contentToAnalyze = node.decoded ?? node.value
        let wasEncoded = node.decoded != nil
        let url = ContentAnalyzer.analyze(
            value: contentToAnalyze,
            wasEncoded: wasEncoded,
            comp: comp,
            urlInfo: &urlInfo,
            label: label
        )
        if url != nil {
            newURL.append(url)
        }
        
        for child in node.children {
            let childResult = walkAndAnalyze(node: child, urlInfo: &urlInfo, comp: comp, label: label)
            if let childURL = childResult {
                newURL.append(childURL)
            }
        }
        
        if newURL.count > 1 {
            // message append that there are to omany url found, this is critical, and not normal but i do not know what to do
            if checkMultipleURLs(newURL, urlInfo: &urlInfo, comp: comp) {
                return nil
            }
        }
        if newURL.count == 1, let singleURL = newURL.first ?? nil {
            return singleURL
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
