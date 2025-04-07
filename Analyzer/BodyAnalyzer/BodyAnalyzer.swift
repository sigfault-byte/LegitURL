import Foundation

struct BodyAnalyzer {
    static func analyze(bodyData: Data, contentType: String, responseCode: Int, urlOrigin: String, warnings: inout [SecurityWarning]) {
        var scriptRatio = 0.0
        var matchedAnyCriticalOrSuspicious = false
        guard responseCode == 200 else {
            return
        }
        
        // Only analyze text or html content types
        if contentType.contains("text/html") || contentType.contains("text/plain") {
            let htmlOpen = HTMLEntities.htmlOpen
            let htmlClose = HTMLEntities.htmlClose
            
            
            /// Initial prefix was 40, but some website ( hello www.apple.com pad the html before the current code ? need to thinke about a cleaning logic )
            let htmlStartIsNearTop = bodyData.prefix(512).containsBytesCaseInsensitive(of: htmlOpen)
            let htmlCloseIsNearEnd = bodyData.suffix(512).containsBytesCaseInsensitive(of: htmlClose)
            
            if !htmlStartIsNearTop || !htmlCloseIsNearEnd {
                warnings.append(SecurityWarning(
                    message: "Body does not contain HTML.\nThis is surely a security risk.",
                    severity: .critical,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            if let htmlStartRange = bodyData.range(of: Data(HTMLEntities.htmlOpen)),
               let htmlEndRange = bodyData.range(of: Data(HTMLEntities.htmlClose)),
               htmlStartRange.lowerBound < htmlEndRange.upperBound {
                
                let htmlRange = htmlStartRange.lowerBound..<htmlEndRange.upperBound
                let htmlBytes = bodyData[htmlRange]
                
                var totalScriptBytes = 0
                var searchStart = htmlBytes.startIndex
                
                while let scriptStart = htmlBytes.range(of: Data(HTMLEntities.scriptOpen), options: [], in: searchStart..<htmlBytes.endIndex),
                      let scriptEnd = htmlBytes.range(of: Data(HTMLEntities.scriptClose), options: [], in: scriptStart.upperBound..<htmlBytes.endIndex) {
                    
                    totalScriptBytes += scriptEnd.upperBound - scriptStart.lowerBound
                    searchStart = scriptEnd.upperBound
                }
                
                scriptRatio = Double(totalScriptBytes) / Double(htmlBytes.count)
                if scriptRatio >= 0.2 {
                    let level: Int
                    if scriptRatio >= 0.8 {
                        level = 30
                    } else if scriptRatio >= 0.5 {
                        level = 20
                    } else {
                        level = 10
                    }
                    
                    warnings.append(SecurityWarning(
                        message: "JavaScript accounts for \(Int(scriptRatio * 100))% of page body.",
                        severity: .suspicious,
                        url: urlOrigin,
                        source: .onlineAnalysis
                    ))
                    URLQueue.shared.LegitScore -= level
                }
            }
            
            if bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.scriptSrc) {
                warnings.append(SecurityWarning(
                    message: "External script tag found (script src=...).",
                    severity: .suspicious,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            if responseCode == 200 && bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.metaRefresh) {
                warnings.append(SecurityWarning(
                    message: "Meta refresh redirect found in body on 200 OK page.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
            if bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.clientMinJS) {
                warnings.append(SecurityWarning(
                    message: "Known suspicious script file 'client.min.js' found. Known fingerprinting js library.",
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
                    let docWindow = bodyData[i..<i + docPattern.count]
                    
                    if docWindow.elementsEqual(docPattern) {
                        let submitSearchStart = i + docPattern.count
                        let submitSearchEnd = min(submitSearchStart + rangeLimit, totalLength)
                        if submitSearchStart < submitSearchEnd {
                            let searchWindow = bodyData[submitSearchStart..<submitSearchEnd]
                            if searchWindow.containsBytes(of: submitPattern) {
                                warnings.append(SecurityWarning(
                                    message: "Detected silent auto-submitting script using document.getElementById().submit().",
                                    severity: .critical,
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
            
            // Look for forced redirect using window.location followed by .href, .replace, or .assign
            let locationPattern = ScamByteSignatures.windowLocation
            let expectedSuffixes: [[UInt8]] = [ScamByteSignatures.href, ScamByteSignatures.replace, ScamByteSignatures.assign]
            if totalLength >= locationPattern.count {
                for i in 0...(totalLength - locationPattern.count) {
                    if bodyData[i..<i + locationPattern.count].elementsEqual(locationPattern) {
                        let afterIndex = i + locationPattern.count
                        var foundExpected = false
                        for suffix in expectedSuffixes {
                            if afterIndex + suffix.count <= totalLength {
                                let followingBytes = bodyData[afterIndex..<afterIndex + suffix.count]
                                if followingBytes.elementsEqual(suffix) {
                                    foundExpected = true;
                                    break
                                }
                            }
                        }
                        if foundExpected {
                            warnings.append(SecurityWarning(
                                message: "Forced redirect detected using window.location with immediate redirect method in a \(Int(scriptRatio * 100))% script-only page.",
//                                If page is > 70% scrip bytes and uses windows relocation its bail
                                severity: scriptRatio >= 0.7 ? .critical : .suspicious,
                                url: urlOrigin,
                                source: .onlineAnalysis
                            ))
                            matchedAnyCriticalOrSuspicious = true
                            break
                        }
                    }
                }
            }
            
            // fallback scans
            if bodyData.containsBytes(of: ScamByteSignatures.evalCall) {
                warnings.append(SecurityWarning(
                    message: "Raw byte pattern 'eval(' found in body.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            if bodyData.containsBytes(of: ScamByteSignatures.atobCall) {
                warnings.append(SecurityWarning(
                    message: "Raw byte pattern 'atob(' found in body.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            if bodyData.containsBytes(of: ScamByteSignatures.unescapeCall) {
                warnings.append(SecurityWarning(
                    message: "Raw byte pattern 'unescape(' found in body.",
                    severity: .dangerous,
                    url: urlOrigin,
                    source: .onlineAnalysis
                ))
                matchedAnyCriticalOrSuspicious = true
            }
            
//            // Obfuscation patterns (still decode because these are flexible, not fixed byte sequences)
//            if !matchedAnyCriticalOrSuspicious, let decodedBody = urlInfo.onlineInfo?.formattedBody {
//                if decodedBody.contains("eval(") || decodedBody.contains("atob(") || decodedBody.contains("unescape(") {
//                    warnings.append(SecurityWarning(
//                        message: "Obfuscated or encoded JavaScript found in body (eval, atob, unescape, etc.).",
//                        severity: .dangerous,
//                        url: urlOrigin,
//                        source: .onlineAnalysis
//                    ))
//                }
//
//            }
        }
    }
}
