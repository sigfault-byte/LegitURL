struct ContentAnalyzer {
    static func analyze(
        value: String,
        wasEncoded: Bool,
        comp: String,
        urlInfo: inout URLInfo,
        label: String)
    -> String? {
        
        //Check if UUID
        if checkIfUUID(value: value, urlInfo: &urlInfo, comp: comp, label: label) {
            return nil
        }
        //Check if there is an url
        if let newURL = detectURL(value: value, urlInfo: &urlInfo, comp: comp, label: label), !newURL.isEmpty {
            return newURL
        }
        
        //Check if suspicious keywords
        if checkScamWords(value: value, urlInfo: &urlInfo, comp: comp, label: label) {
            return nil
        }
        //Check if phishing
        if checkPhishingWords(value: value, urlInfo: &urlInfo, comp: comp, label: label) {
            return nil
        }
        //Check entropy and "real" word
        if checkIfHighEntropy(value: value, urlInfo: &urlInfo, comp: comp, label: label) {
            return nil
        }
        
        return nil
    }
}

private func checkIfUUID(value: String, urlInfo: inout URLInfo, comp: String, label: String) -> Bool {
    var foundUUID = false

    // Only try to analyze if it's a possible UUID
    if value.count == 36 || value.count == 32 {
        let directUUIDResult = DecodingTools.analyzeUUID(value)
        if directUUIDResult.classification != "Not a UUID" {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ \(comp.capitalized) \(label) contains a UUID: '\(directUUIDResult.formatted ?? value)' (\(directUUIDResult.classification))",
                severity: .suspicious
            ))
            foundUUID = true

            if label == "key" {
                URLQueue.shared.LegitScore += PenaltySystem.Penalty.hiddenUUIDKey
            } else {
                URLQueue.shared.LegitScore += comp == "fragment" ? PenaltySystem.Penalty.uuidInFragment : PenaltySystem.Penalty.uuidInQuery
            }
        }
    }

    // Then still do chunk check if it's long enough
    if (value.count >= 32 && value.count % 32 == 0) || (value.count >= 36 && value.count % 36 == 0) {
        let chunkSize = value.contains("-") ? 36 : 32
        for chunk in stride(from: 0, to: value.count - chunkSize + 1, by: chunkSize) {
            let startIndex = value.index(value.startIndex, offsetBy: chunk)
            let endIndex = value.index(startIndex, offsetBy: chunkSize)
            let possibleUUID = String(value[startIndex..<endIndex])

            let uuidResult = DecodingTools.analyzeUUID(possibleUUID)
            if uuidResult.classification != "Not a UUID" {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ \(comp.capitalized) \(label) contains a UUID: '\(uuidResult.formatted ?? possibleUUID)' (\(uuidResult.classification))",
                    severity: .suspicious
                ))
                foundUUID = true

                if label == "key" {
                    URLQueue.shared.LegitScore += PenaltySystem.Penalty.hiddenUUIDKey
                } else {
                    URLQueue.shared.LegitScore += comp == "fragment" ? PenaltySystem.Penalty.uuidInFragment : PenaltySystem.Penalty.uuidInQuery
                }
            }
        }
    }

    if foundUUID {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ \(comp.capitalized) \(label) contains one or more embedded UUID(s)!",
            severity: .suspicious))
    }

    return foundUUID
}

private func detectURL(value: String, urlInfo: inout URLInfo, comp: String, label: String) -> String? {
    var foundURL = ""
    if  LegitURLTools.isValueURL(value) {
        foundURL.append(value)
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ URL detected in \(comp) \(label): '\(value)'",
            severity: .suspicious
        ))
        if label == "key" {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.urlInQueryKey
        } else {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.urlInQueryValue
        }
        return foundURL
    }
    return foundURL
}

private func checkScamWords(value: String, urlInfo: inout URLInfo, comp: String, label: String) -> Bool {
    if SuspiciousKeywords.scamTerms.contains(value) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Suspicious \(comp) \(label) '\(value)' (possible scam)",
            severity: .suspicious
        ))
        if label == "key" {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInKey
        } else {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInValue
        }
        return true
    } else {
        return false
    }
}

private func checkPhishingWords(value: String, urlInfo: inout URLInfo, comp: String, label: String) -> Bool {
    if SuspiciousKeywords.phishingWords.contains(value) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Suspicious \(comp) \(label) '\(value)' (possible phishing)",
            severity: .suspicious
        ))
        if label == "key" {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInKey
        } else {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.phishingWordsInValue
        }
        return true
    } else {
        return false
    }
}

private func checkRedirectAndJSExploit(value: String, urlInfo: inout URLInfo, comp: String, label: String) -> Bool {
    if SuspiciousKeywords.redirectAndJSExploitationKeywords.contains(value) {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ Redirect-like \(comp) \(label) '\(value)' detected",
            severity: .dangerous
        ))
        if label == "key" {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.jsRedirectInKey
        } else {
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.jsRedirectInValue
        }
        return true
    } else {
        return false
    }
}

private func checkIfHighEntropy(value: String, urlInfo: inout URLInfo, comp: String, label: String) -> Bool {
    let (isHighEntropy, entropyValue) = LegitURLTools.isHighEntropy(value)
    if isHighEntropy {
        urlInfo.warnings.append(SecurityWarning(
            message: "⚠️ \(comp.capitalized) \(label) '\(value)' has high entropy (\(entropyValue ?? 0.0)) – may be obfuscated",
            severity: .suspicious
        ))
        URLQueue.shared.LegitScore += PenaltySystem.Penalty.highEntropyKeyOrValue
        return true
    } else {
        return false
    }
}
