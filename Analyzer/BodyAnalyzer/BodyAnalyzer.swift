import Foundation
//TODO : create a generic function for the call of the various script byte check
struct BodyAnalyzer {
    static func analyze(bodyData: Data, contentType: String, responseCode: Int, urlOrigin: String, warnings: inout [SecurityWarning]) {
        var scriptRatio = 0.0
        guard responseCode == 200 else {
            return
        }
        
        // Only analyze text or html content types
        if contentType.contains("text/html") /*|| contentType.contains("text/plain")*/{
            // gotta check i am not converting to string and converting back to bytes....!
            /// Initial prefix was 40, but some website ( hello www.apple.com pad the html before the current code ? need to thinke about a cleaning logic )
            let htmlStartIsNearTop = bodyData.prefix(512).containsBytesCaseInsensitive(of: HTMLEntities.htmlOpen)
            let htmlCloseIsNearEnd = bodyData.suffix(512).containsBytesCaseInsensitive(of: HTMLEntities.htmlClose)
            
            switch (htmlStartIsNearTop, htmlCloseIsNearEnd) {
            case (true, true):
                if let htmlStartRange = bodyData.range(of: Data(HTMLEntities.htmlOpen)),
                   let htmlEndRange = bodyData.range(of: Data(HTMLEntities.htmlClose)){
                    scriptRatio = scriptRatioHtmlScript(in: bodyData, htmlStartRange: htmlStartRange, htmlEndRange: htmlEndRange)
                    if scriptRatio > 0.8 {
                        warnings.append(SecurityWarning(message: "Despite a '\(contentType)' content type in header, JavaScript accounts for \(Int(scriptRatio * 100))% of page body",
                                                        severity: .dangerous,
                                                        penalty: PenaltySystem.Penalty.scriptIs80Percent,
                                                        url: urlOrigin,
                                                        source: .body))
                    } else if scriptRatio > 0.5 {
                        warnings.append(SecurityWarning(message: "Despite a '\(contentType)' content type in header, JavaScript accounts for \(Int(scriptRatio * 100))% of page body",
                                                        severity: .suspicious,
                                                        penalty: PenaltySystem.Penalty.scriptIs50Percent,
                                                        url: urlOrigin,
                                                        source: .body))
                    } else if scriptRatio > 0.3 {
                        warnings.append(SecurityWarning(message: "Despite a '\(contentType)' content type in header, JavaScript accounts for \(Int(scriptRatio * 100))% of page body",
                                                        severity: .suspicious,
                                                        penalty: PenaltySystem.Penalty.scriptIs30Percent,
                                                        url: urlOrigin,
                                                        source: .body))
                    }
                }
                break // proceed with full analysis below
                
            case (true, false):
                warnings.append(SecurityWarning(
                    message: "Body does not contain properly closed HTML.\nLikely hotdogwater devs at work, or scam.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.hotdogWaterDev,
                    url: urlOrigin,
                    source: .body
                ))
                if let htmlStartRange = bodyData.range(of: Data(HTMLEntities.htmlOpen)) {
                    let htmlEndRange = htmlStartRange.lowerBound..<bodyData.endIndex
                    let approxRatio = scriptRatioHtmlScript(in: bodyData, htmlStartRange: htmlStartRange, htmlEndRange: htmlEndRange, baseOverride: bodyData.count)
                    
                    if approxRatio > 0.8 {
                        warnings.append(SecurityWarning(
                            message: "HTML is unclosed, but JavaScript still dominates: \(Int(approxRatio * 100))% of content is script.",
                            severity: .dangerous,
                            penalty: PenaltySystem.Penalty.scriptIs80Percent,
                            url: urlOrigin,
                            source: .body
                        ))
                    } else if approxRatio > 0.5 {
                        warnings.append(SecurityWarning(
                            message: "HTML is unclosed, but script usage is high: \(Int(approxRatio * 100))% script.",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.scriptIs50Percent,
                            url: urlOrigin,
                            source: .body
                        ))
                    } else if scriptRatio > 0.3 {
                        warnings.append(SecurityWarning(
                            message: "Despite a '\(contentType)' content type in header, JavaScript accounts for \(Int(scriptRatio * 100))% of page body",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.scriptIs30Percent,
                            url: urlOrigin,
                            source: .body
                        ))
                    }
                }
                
            case (false, _):
                warnings.append(SecurityWarning(
                    message: "🚨 No <html> tag found. This is not a proper HTML response for a '\(contentType)' content type header.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlOrigin,
                    source: .body
                ))
                return // critical failure, stop analysis
            }
            //        Switch case end
            // proceed with generic checks
            let checkExternalScriptTag = checkExternalScriptTag(bodyData: bodyData, urlOrigin: urlOrigin, warnings: &warnings)
            let checkMetaRefresh = checkMetaRefresh(bodyData: bodyData, responseCode: responseCode, urlOrigin: urlOrigin, warnings: &warnings)
            let checkClientMinJs = checkClientMinJS(bodyData: bodyData, urlOrigin: urlOrigin, warnings: &warnings)
            let checkAutosubmitForm = checkAutoSubmittingForm(bodyData: bodyData, urlOrigin: urlOrigin, warnings: &warnings)
            let checkForceRedir = checkForcedRedirect(bodyData: bodyData, scriptRatio: scriptRatio, urlOrigin: urlOrigin, warnings: &warnings)
            let checkEvalCall = checkEvalCall(bodyData: bodyData, urlOrigin: urlOrigin, warnings: &warnings)
            let checkAtobCall = checkAtobCall(bodyData: bodyData, urlOrigin: urlOrigin, warnings: &warnings)
            let checkUnescapeCall = checkUnescapeCall(bodyData: bodyData, urlOrigin: urlOrigin, warnings: &warnings)
            
            
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
        } else { /*other content type*/}
    }
    
    // Helper function to check for an external script tag
    private static func checkExternalScriptTag(bodyData: Data, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        if bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.scriptSrc) {
            let numberOfScritpsrs = bodyData.countsBytesInsensitive(of: ScamByteSignatures.scriptSrc)
            warnings.append(SecurityWarning(
                message: " '\(numberOfScritpsrs)' External script tag found (script src=...).",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.extScriptSrc * numberOfScritpsrs,
                url: urlOrigin,
                source: .body
            ))
            return true
        }
        return false
    }
    
    // Helper function to check for meta refresh redirect
    private static func checkMetaRefresh(bodyData: Data, responseCode: Int, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        if responseCode == 200 && bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.metaRefresh) {
            warnings.append(SecurityWarning(
                message: "Meta refresh redirect found in body on 200 OK page.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.redirectToDifferentDomain,
                url: urlOrigin,
                source: .body
            ))
            return true
        }
        return false
    }
    
    // Helper function to check for 'client.min.js' script
    private static func checkClientMinJS(bodyData: Data, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        if bodyData.containsBytesCaseInsensitive(of: ScamByteSignatures.clientMinJS) {
            warnings.append(SecurityWarning(
                message: "Known suspicious script file 'client.min.js' found. Known fingerprinting js library.",
                severity: .scam,
                penalty: PenaltySystem.Penalty.jsFingerPrinting,
                url: urlOrigin,
                source: .body
            ))
            return true
        }
        return false
    }
    
    // Helper function to check for auto-submitting form behavior
    private static func checkAutoSubmittingForm(bodyData: Data, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        let docPattern = ScamByteSignatures.documentGetElementById
        let submitPattern = ScamByteSignatures.submitPattern
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
                                penalty: PenaltySystem.Penalty.critical,
                                url: urlOrigin,
                                source: .body
                            ))
                            return true
                        }
                    }
                }
            }
        }
        return false
    }
    
    // Helper function to check for forced redirect using window.location
    private static func checkForcedRedirect(bodyData: Data, scriptRatio: Double, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        let locationPattern = ScamByteSignatures.windowLocation
        let expectedSuffixes: [[UInt8]] = [ScamByteSignatures.href, ScamByteSignatures.replace, ScamByteSignatures.assign]
        let totalLength = bodyData.count
        
        if totalLength >= locationPattern.count {
            for i in 0...(totalLength - locationPattern.count) {
                if bodyData[i..<i + locationPattern.count].elementsEqual(locationPattern) {
                    let afterIndex = i + locationPattern.count
                    var foundExpected = false
                    for suffix in expectedSuffixes {
                        if afterIndex + suffix.count <= totalLength {
                            let followingBytes = bodyData[afterIndex..<afterIndex + suffix.count]
                            if followingBytes.elementsEqual(suffix) {
                                foundExpected = true
                                break
                            }
                        }
                    }
                    //                    Logic here should be: small body size + windows reloc => scam, big body size reloc => big company doing big company things. But, it would be easy to add dogwater gibberish and add it in the middle...
                    if foundExpected {
                        warnings.append(SecurityWarning(
                            message: "Forced redirect detected using window.location with immediate redirect method in a \(Int(scriptRatio * 100))% script-only page.",
                            severity: scriptRatio >= 0.6 ? .critical : .suspicious,
                            penalty: scriptRatio >= 0.6 ? PenaltySystem.Penalty.critical : PenaltySystem.Penalty.jsWindowsRedirect,
                            url: urlOrigin,
                            source: .body
                        ))
                        return true
                    }
                }
            }
        }
        return false
    }
    
    // Helper function to check for raw 'eval(' byte pattern
    private static func checkEvalCall(bodyData: Data, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        if bodyData.containsBytes(of: ScamByteSignatures.evalCall) {
            warnings.append(SecurityWarning(
                message: "Raw byte pattern 'eval(' found in body.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.jsEvalInBody,
                url: urlOrigin,
                source: .body
            ))
            return true
        }
        return false
    }
    
    // Helper function to check for raw 'atob(' byte pattern
    private static func checkAtobCall(bodyData: Data, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        if bodyData.containsBytes(of: ScamByteSignatures.atobCall) {
            warnings.append(SecurityWarning(
                message: "Raw byte pattern 'atob(' found in body.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.jsEvalInBody,
                url: urlOrigin,
                source: .body
            ))
            return true
        }
        return false
    }
    
    // Helper function to check for raw 'unescape(' byte pattern
    private static func checkUnescapeCall(bodyData: Data, urlOrigin: String, warnings: inout [SecurityWarning]) -> Bool {
        if bodyData.containsBytes(of: ScamByteSignatures.unescapeCall) {
            warnings.append(SecurityWarning(
                message: "Raw byte pattern 'unescape(' found in body.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.jsEvalInBody,
                url: urlOrigin,
                source: .body
            ))
            return true
        }
        return false
    }
    
    private static func scriptRatioHtmlScript(in bodyData: Data, htmlStartRange: Range<Data.Index>, htmlEndRange: Range<Data.Index>, baseOverride: Int? = nil) -> Double {
        guard htmlStartRange.lowerBound < htmlEndRange.upperBound else {
            return 0.0
        }
        
        let htmlRange = htmlStartRange.lowerBound..<htmlEndRange.upperBound
        let htmlBytes = bodyData[htmlRange]
        
        var totalScriptBytes = 0
        var searchStart = htmlBytes.startIndex
        
        while let scriptStart = htmlBytes.range(of: Data(HTMLEntities.scriptOpen), options: [], in: searchStart..<htmlBytes.endIndex),
              let scriptEnd = htmlBytes.range(of: Data(HTMLEntities.scriptClose), options: [], in: scriptStart.upperBound..<htmlBytes.endIndex) {
            
            totalScriptBytes += scriptEnd.upperBound - scriptStart.lowerBound
            searchStart = scriptEnd.upperBound
        }
        
        let base = Double(baseOverride ?? htmlBytes.count)
        return base > 0 ? Double(totalScriptBytes) / base : 0.0
    }
}
