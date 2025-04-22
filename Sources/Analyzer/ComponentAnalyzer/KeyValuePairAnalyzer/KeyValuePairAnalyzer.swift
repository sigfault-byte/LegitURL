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
        
        // Determine if we are processing a fragment.
        let isFragment = comp.lowercased() == "fragment"
        
        // Choose the appropriate arrays.
        let keys: [String?] = isFragment ? urlInfo.components.fragmentKeys : urlInfo.components.queryKeys
        let values: [String?] = isFragment ? urlInfo.components.fragmentValues : urlInfo.components.queryValues
        
        
        // Loop over indices to access parallel arrays of keys and values.
        for index in keys.indices {
            // Process the key.
            if let key = keys[index], !key.isEmpty {
                let keyNode = LamaiDecoding.decode(input: key, maxDepth: 4)
                if keyNode.hasDeepDescendant() {
                    // store lamai findings for the view
                    if comp == "query" {
                        urlInfo.components.lamaiTrees[.queryKey, default: []].append(keyNode)
                    } else {
                        urlInfo.components.lamaiTrees[.fragmentKey, default: []].append(keyNode)
                    }
                }
                
                if let url = WalkTheNode.analyze(node: keyNode, urlInfo: &urlInfo, comp: "comp", label: "key"), !url.isEmpty{
                    foundURL.append(url)
                }
            }
            
            // Process the value if available.
            if let value = values[index] {
//                deeper because value are supposedly more obfuscated
                let valueNode = LamaiDecoding.decode(input: value, maxDepth: 6)
                if valueNode.hasDeepDescendant() {
                    // store lamai findings for the view
                    if comp == "query" {
                        urlInfo.components.lamaiTrees[.queryValue, default: []].append(valueNode)
                    } else {
                        urlInfo.components.lamaiTrees[.fragmentValue, default: []].append(valueNode)
                    }
                }
                if let url = WalkTheNode.analyze(node: valueNode, urlInfo: &urlInfo, comp: comp, label: "value"), !url.isEmpty{
                    foundURL.append(url)
                }
            }
        }
        // If multiple urls are found halt analysis
        if checkMultipleURLs(foundURL, urlInfo: &urlInfo, comp: comp) {
            return (urlInfo, nil)
        }
        return (urlInfo, foundURL.first)
    }
    
    private static func checkMultipleURLs(_ foundURLs: [String?], urlInfo: inout URLInfo, comp: String) -> Bool {
        let nonNilURLs = foundURLs.compactMap { $0 } // emove nil values
        let urlOrigin = urlInfo.components.coreURL ?? ""
        var source = SecurityWarning.SourceType.query
        if nonNilURLs.count > 1 {
            if comp == "fragment"{
                source = SecurityWarning.SourceType.fragment
            }
            let urlList = nonNilURLs.joined(separator: "\n") // Format URLs on new lines
            urlInfo.warnings.append(SecurityWarning(
                message: "Multiple URLs detected in \(comp) parameters.\n\(urlList)",
                severity: .critical,
                penalty:  -100,
                url: urlOrigin,
                source: source
            ))
            return true  // 🚨 Indicate that analysis should halt
        }
        return false  // ✅ Continue normally
    }
}
