import Foundation

struct BodyAnalyzer {
    static func analyze(bodyData: Data, contentType: String, responseCode: Int, urlOrigin: String) -> [SecurityWarning] {
        var warnings = [SecurityWarning]()
        var matchedAnyCriticalOrSuspicious = false
        
        // Only analyze text or html content types
        if contentType.contains("text/html") || contentType.contains("text/plain") {
            let htmlOpen = HTMLEntities.htmlOpen
            let htmlClose = HTMLEntities.htmlClose
            
            let htmlStartIsNearTop = bodyData.prefix(40).containsBytesCaseInsensitive(of: htmlOpen)
            let htmlCloseIsNearEnd = bodyData.suffix(40).containsBytesCaseInsensitive(of: htmlClose)
            
            if !htmlStartIsNearTop || !htmlCloseIsNearEnd {
                warnings.append(SecurityWarning(
                    message: "Body does not appear to be a proper HTML page. <html tag not near top or </html> not near end.",
                    severity: .critical,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            if bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.scriptSrc) {
                warnings.append(SecurityWarning(
                    message: "External script tag found (script src=...). May be used to hide malicious JavaScript.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            if bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.clientMinJS) {
                warnings.append(SecurityWarning(
                    message: "Known suspicious script file 'client.min.js' found. Often used in fingerprinting or cloaking shells.",
                    severity: .tracking,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            // Look for auto-submitting form behavior: document.getElementById(...) followed closely by .submit
            let docPattern = ScamByteSignatures.documentGetElementById
            let submitPattern = Array(".submit".utf8)
            let rangeLimit = 32
            let totalLength = bodyData.count
            if totalLength >= docPattern.count + submitPattern.count {
                for i in 0...(totalLength - docPattern.count) {
                    if i + docPattern.count > totalLength { break }
                    let docWindow = bodyData[i..<i + docPattern.count]

                    if docWindow.elementsEqual(docPattern) {
                        let submitSearchStart = i + docPattern.count
                        let submitSearchEnd = min(submitSearchStart + rangeLimit, totalLength)
                        if submitSearchStart < submitSearchEnd {
                            let searchWindow = bodyData[submitSearchStart..<submitSearchEnd]
                            if searchWindow.containsBytes(of: submitPattern) {
                                warnings.append(SecurityWarning(
                                    message: "Detected silent auto-submitting script using document.getElementById().submit().",
                                    severity: .dangerous,
                                    url: urlOrigin,
                                    source: .onlineAnalysis
                                ))
                                matchedAnyCriticalOrSuspicious = true
                                break // only flag once
                            }
                        }
                    }
                }
            }
            
            // fallback scans
            if bodyData.containsBytes(of: ScamByteSignatures.evalCall) {
                warnings.append(SecurityWarning(
                    message: "Raw byte pattern 'eval(' found in body. Potential obfuscated JavaScript.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            if bodyData.containsBytes(of: ScamByteSignatures.atobCall) {
                warnings.append(SecurityWarning(
                    message: "Raw byte pattern 'atob(' found in body. Potential encoded payload.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            if bodyData.containsBytes(of: ScamByteSignatures.unescapeCall) {
                warnings.append(SecurityWarning(
                    message: "Raw byte pattern 'unescape(' found in body. Potential obfuscated payload.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            // New check for meta refresh
            if responseCode == 200 && bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.metaRefresh) {
                warnings.append(SecurityWarning(
                    message: "Meta refresh redirect found in body on 200 OK page. This is often used to cloak malicious redirects.",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            // Obfuscation patterns (still decode because these are flexible, not fixed byte sequences)
            if !matchedAnyCriticalOrSuspicious, let decodedBody = String(data: bodyData, encoding: .utf8) {
                if decodedBody.contains("eval(") || decodedBody.contains("atob(") || decodedBody.contains("unescape(") {
                    warnings.append(SecurityWarning(
                        message: "Obfuscated or encoded JavaScript found in body (eval, atob, unescape, etc.).",
                        severity: .dangerous,
                        url: urlOrigin,
                        source: .onlineAnalysis
                    ))
                }
                
                if responseCode == 200 && decodedBody.contains("<meta http-equiv=\"refresh\"") {
                    warnings.append(SecurityWarning(
                        message: "Meta refresh redirect found in body on 200 OK page. This is often used to cloak malicious redirects.",
                        severity: .suspicious,
                        url: urlOrigin,
                        source: .onlineAnalysis
                    ))
                }
            }
        }
        
        return warnings
    }
}
