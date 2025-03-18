import Foundation

struct KeyValuePairAnalyzer {
    //
    //    /// Processes both query keys and values with all security checks:
    //    /// - Decodes the string (if applicable).
    //    /// - Checks for phishing, scam, and redirect-related keywords.
    //    /// - Evaluates the entropy to flag obfuscation.
    //    /// - Checks if the component appears to be a URL.
    //    ///
    //    /// - Parameters:
    //    ///   - component: The original query key or value.
    //    ///   - label: A string ("key" or "value") indicating the type.
    //    /// - Returns: The processed string (decoded if applicable).
    static func analyze(urlInfo: URLInfo, comp: String = "query") -> (URLInfo, String?) {
        var urlInfo = urlInfo
        var foundURL: [String] = []
        var score = 0
        
        // Determine if we are processing a fragment.
        let isFragment = comp.lowercased() == "fragment"
        
        // Choose the appropriate arrays.
        var keys: [String?] = isFragment ? urlInfo.components.fragmentKeys : urlInfo.components.queryKeys
        var values: [String?] = isFragment ? urlInfo.components.fragmentValues : urlInfo.components.queryValues
        
        print("keys = ", keys)
        print("values = ", values)
        
        // Loop over indices to access parallel arrays of keys and values.
        for index in keys.indices {
            // Process the key.
            if let key = keys[index], !key.isEmpty {
                let processedKey = processComponent(key, label: "key")
                keys[index] = processedKey
            }
            
            // Process the value if available.
            if let value = values[index] {
                let processedValue = processComponent(value, label: "value")
                values[index] = processedValue
            }
        }
        
        if checkMultipleURLs(foundURL, urlInfo: &urlInfo, comp: comp) {
            return (urlInfo, nil)  // Halt analysis, do not return any URLs for further processing
        }
        URLQueue.shared.LegitScore += score
        return (urlInfo, foundURL.first)
        
        // Local helper function to process a query component (either key or value).
        func processComponent(_ component: String, label: String) -> String {
            var result = component
            var foundUUID = false
            
            // Pre-check for UUID before decoding
            
            if (component.count >= 32 && component.count % 32 == 0) || (component.count >= 36 && component.count % 36 == 0) {
                let chunkSize = component.contains("-") ? 36 : 32  // Adjust chunk size based on hyphen presence
                
                for chunk in stride(from: 0, to: component.count, by: chunkSize) {
                    let startIndex = component.index(component.startIndex, offsetBy: chunk)
                    let endIndex = component.index(startIndex, offsetBy: chunkSize)
                    let possibleUUID = String(component[startIndex..<endIndex])
                    
                    let uuidResult = DecodingTools.analyzeUUID(possibleUUID)
                    if uuidResult.classification != "Not a UUID" {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "⚠️ \(comp.capitalized) \(label) contains a UUID: '\(uuidResult.formatted ?? possibleUUID)' (\(uuidResult.classification))",
                            severity: .suspicious
                        ))
                        foundUUID = true
                        
                        // Apply penalties based on UUID type
                        if label == "key" {
                            score += PenaltySystem.Penalty.hiddenUUIDKey
                        } else {
                            score += comp == "fragment" ? PenaltySystem.Penalty.uuidInFragment : PenaltySystem.Penalty.uuidInQuery
                        }
                    }
                }
                
                if foundUUID {
                    urlInfo.warnings.append(SecurityWarning(
                        message:"⚠️ \(comp.capitalized) \(label) contains one or more embedded UUID(s)!",
                        severity: .suspicious))
                    return component  // Return the original component if UUIDs were found
                }
            }
            
            // 1. Attempt to decode the component.
            if !foundUUID {
                switch DecodingTools.attemptToDecode(component) {
                case .success(let decodedResult) where decodedResult.decodedString != component:
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🔍 \(comp.capitalized) \(label) decoded from: '\(component)' → '\(decodedResult.decodedString)'",
                        severity: .info
                    ))
                    result = decodedResult.decodedString
                default:
                    break
                }}
            
            if (component.count >= 32 && component.count % 32 == 0) || (component.count >= 36 && component.count % 36 == 0) {
                let chunkSize = component.contains("-") ? 36 : 32  // Adjust chunk size based on hyphen presence
                
                for chunk in stride(from: 0, to: component.count, by: chunkSize) {
                    let startIndex = component.index(component.startIndex, offsetBy: chunk)
                    let endIndex = component.index(startIndex, offsetBy: chunkSize)
                    let possibleUUID = String(component[startIndex..<endIndex])
                    
                    let uuidResult = DecodingTools.analyzeUUID(possibleUUID)
                    if uuidResult.classification != "Not a UUID" {
                        urlInfo.warnings.append(SecurityWarning(
                            message: "⚠️ \(comp.capitalized) \(label) contains a UUID: '\(uuidResult.formatted ?? possibleUUID)' (\(uuidResult.classification))",
                            severity: .suspicious
                        ))
                        foundUUID = true
                        
                        // Apply penalties based on UUID type
                        if label == "key" {
                            score += PenaltySystem.Penalty.hiddenUUIDKey
                        } else {
                            score += comp == "fragment" ? PenaltySystem.Penalty.hiddenUUIDInFragment : PenaltySystem.Penalty.hiddenUUIDinQueryValue
                        }
                    }
                }
                
                if foundUUID {
                    urlInfo.warnings.append(SecurityWarning(
                        message:"⚠️ \(comp.capitalized) \(label) contains one or more embedded UUID(s)!",
                        severity: .suspicious))
                    return component  // Return the original component if UUIDs were found
                }
            }
            
            // 2. Check if the component appears to be a URL.
            if  LegitURLTools.isValueURL(result) {
                foundURL.append(result)
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ URL detected in \(comp) \(label): '\(result)'",
                    severity: .suspicious
                ))
                if label == "key" {
                    score += PenaltySystem.Penalty.urlInQueryKey
                } else {
                    score += PenaltySystem.Penalty.urlInQueryValue
                }
                return result
            }
            
            // 3. Check for suspicious keywords.
            if SuspiciousKeywords.phishingWords.contains(result) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Suspicious \(comp) \(label) '\(result)' (possible phishing)",
                    severity: .suspicious
                ))
                if label == "key" {
                    score += PenaltySystem.Penalty.phishingWordsInKey
                } else {
                    score += PenaltySystem.Penalty.phishingWordsInValue
                }
                return result
            }
            
            if SuspiciousKeywords.scamTerms.contains(result) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ \(comp.capitalized) \(label) '\(result)' is often used in scams",
                    severity: .suspicious
                ))
                if label == "key" {
                    score += PenaltySystem.Penalty.scammingWordsInKey
                } else {
                    score += PenaltySystem.Penalty.scammingWordsInValue
                }
                return result
            }
            
            if SuspiciousKeywords.redirectAndJSExploitationKeywords.contains(result) {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Redirect-like \(comp) \(label) '\(result)' detected",
                    severity: .dangerous
                ))
                if label == "key" {
                    score += PenaltySystem.Penalty.jsRedirectInKey
                } else {
                    score += PenaltySystem.Penalty.jsRedirectInValue
                }
                return result
            }
            
            // 4. Check for high entropy (indicating possible obfuscation).
            let (isHighEntropy, entropyValue) = LegitURLTools.isHighEntropy(result)
            if isHighEntropy {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ \(comp.capitalized) \(label) '\(result)' has high entropy (\(entropyValue ?? 0.0)) – may be obfuscated",
                    severity: .suspicious
                ))
                score += PenaltySystem.Penalty.highEntropyKeyOrValue
            }
            return result
        }
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
