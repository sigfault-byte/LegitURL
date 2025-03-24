//
//  KeyValuePairAnalyzer2.swift
//  URLChecker
//
//  Created by Chief Hakka on 24/03/2025.
//
struct KeyValuePairAnalyzer {
    
    
    static func analyze(urlInfo: inout URLInfo, comp: String = "query") -> (URLInfo, String?) {
        var urlInfo = urlInfo
        var foundURL: [String] = []
        var score = 0
        
        // Determine if we are processing a fragment.
        let isFragment = comp.lowercased() == "fragment"
        
        // Choose the appropriate arrays.
        var keys: [String?] = isFragment ? urlInfo.components.fragmentKeys : urlInfo.components.queryKeys
        var values: [String?] = isFragment ? urlInfo.components.fragmentValues : urlInfo.components.queryValues
        
        
        // Loop over indices to access parallel arrays of keys and values.
        for index in keys.indices {
            // Process the key.
            if let key = keys[index], !key.isEmpty {
                let keyNode = LamaiDecoding.decode(input: key, maxDepth: 6)
                if let url = WalkTheNode.walkAndAnalyze(node: keyNode, urlInfo: &urlInfo, comp: "comp", label: "key"), !url.isEmpty{
                    foundURL.append(url)
                }
                
            }
            
            // Process the value if available.
            if let value = values[index] {
                let valueNode = LamaiDecoding.decode(input: value, maxDepth: 6)
                if let url = WalkTheNode.walkAndAnalyze(node: valueNode, urlInfo: &urlInfo, comp: comp, label: "value"), !url.isEmpty{
                    foundURL.append(url)
                }
            }
        }
        
        if checkMultipleURLs(foundURL, urlInfo: &urlInfo, comp: comp) {
            return (urlInfo, nil)  // Halt analysis, do not return any URLs for further processing
        }
        URLQueue.shared.LegitScore += score
        return (urlInfo, foundURL.first)
    }
    
    private static func checkMultipleURLs(_ foundURLs: [String?], urlInfo: inout URLInfo, comp: String) -> Bool {
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
}
