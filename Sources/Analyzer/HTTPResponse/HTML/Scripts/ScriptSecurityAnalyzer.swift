//  ScriptSecurityAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//
// TODO: when script has relative URL, check for presence of integrity attribute.
// TODO: Penalize missing integrity even for relative src scripts.
// TODO: Reward presence of integrity with a security bonus (SRI usage) ?????.
import Foundation
struct ScriptSecurityAnalyzer {
    static func analyze(scripts: inout ScriptExtractionResult, body: Data, origin: String, htmlRange: Range<Int>, into warnings: inout [SecurityWarning]) -> ScriptSourceToMatchCSP {
        
        
        let totalInlineScriptBytes = computeInlineScriptBytes(scripts.scripts)
        //Cpmpute html to script ratio
        computeScriptsToHtmlRation(scriptSize: totalInlineScriptBytes, htmlRange: htmlRange, originURL: origin, into: &warnings)
        
        #if DEBUG
//        for script in scripts {
//            let previewStart = script.start
//            let previewEnd = script.endTagPos ?? previewStart + 40
//            let previewData = body[previewStart..<previewEnd + 7]
//            if let previewString = String(data: previewData, encoding: .utf8) {
//                if script.endTagPos == nil {
//                    print("NO END")
//                }
//                print("Preview for \(script.origin?.rawValue): \(previewStart). First 1024 bytes:\n\(previewString)")
//            } else {
//                print(" Unclosed script tag at \(previewStart). Unable to decode preview.")
//            }
//        }
        #endif
        // Flag abnormal script origin
        let (dataURICount,
             protocolRelativeCounter,
             protocolRelativeCounterWithIntegrity) = checkingScriptOrigin(originURL: origin, scripts: &scripts, warnings: &warnings)
        
        //TODO: Double check the script possibilities ( ??? )
        warningMessageForURIAndProtocol(from :(dataURICount,
                                               protocolRelativeCounter,
                                               protocolRelativeCounterWithIntegrity),
                                        warnings: &warnings,
                                        origin: origin)
        
        //TODO: compute nonce value entropy, maybe add script hash to ?
        let (nonceList, srcList, internalCount) = extractScriptAttributes(from: scripts.scripts)
        
        checkScriptDensity(internalCount: internalCount, externalCount: srcList.count, htmlSize: htmlRange.count, originURL: origin, into: &warnings)
        
        ScriptInlineAnalyzer.analyze(scripts: &scripts, body: body, origin: origin, into: &warnings)

        
        return ScriptSourceToMatchCSP(nonceList: nonceList, externalSources: srcList)
    }
    
    //MARK --- Helper
    
    private static func checkingScriptOrigin(originURL: String, scripts: inout ScriptExtractionResult, warnings: inout [SecurityWarning]) -> (Int, Int, Int) {
        var dataUriCounter = 0
        var protocolRelativeCounter = 0
        var protocolRelativeCounterWithIntegrity: Int = 0

        for (index, script) in scripts.scripts.enumerated() {
            guard let origin = script.origin else { continue }

            switch origin {
            case .httpExternal:
                scripts.scripts[index].findings4UI = [("HTTP script detected", SecurityWarning.SeverityLevel.critical, 0)]
                warnings.append(SecurityWarning(
                    message: "External script loaded over HTTP. This is insecure and exposes users to injection risks.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: originURL,
                    source: .body
                ))
            case .protocolRelative:
                    
                    if let integrity = script.integrityValue, !integrity.isEmpty {
                        scripts.scripts[index].findings4UI = [("Protocol relative (with SRI)", .info, 0)]
                        protocolRelativeCounterWithIntegrity += 1
                    } else {
                        scripts.scripts[index].findings4UI = [("Protocol relative", .suspicious, 0)]
                        protocolRelativeCounter += 1
                    }
            case .dataURI:
                    scripts.scripts[index].findings4UI = [("Data URI script detected", .dangerous, 0)]
                    if let nonce = script.nonceValue, !nonce.isEmpty {
                        scripts.scripts[index].findings4UI = [("'nonce' attribute does not work for DATA URI it is for Inline Scripts", .suspicious, 0)]
                    }
                    dataUriCounter += 1
            case .unknown:
                scripts.scripts[index].findings4UI = [("Script origin unknown", SecurityWarning.SeverityLevel.dangerous, 0)]
                warnings.append(SecurityWarning(
                    message: "Script origin could not be determined. This may indicate cloaking or malformed attributes.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scriptUnknownOrigin,
                    url: originURL,
                    source: .body,
                    bitFlags: WarningFlags.BODY_SCRIPT_UNKNOWN_ORIGIN
                ))
            case .malformed:
                scripts.scripts[index].findings4UI = [("Script is malformed", SecurityWarning.SeverityLevel.suspicious, 0)]
                warnings.append(SecurityWarning(
                    message: "Malformed script tag or broken src attribute detected.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.scriptMalformed,
                    url: originURL,
                    source: .body,
                    bitFlags: WarningFlags.BODY_SCRIPT_UNKNOWN_ORIGIN
                ))
            default:
                break
            }
        }

        return (dataUriCounter, protocolRelativeCounter, protocolRelativeCounterWithIntegrity)
    }
    
    private static func computeInlineScriptBytes(_ scripts: [ScriptScanTarget]) -> Int {
        return scripts.reduce(0) { sum, script in
            guard script.origin == .inline,
                  let end = script.end,
                  let endTag = script.endTagPos else { return sum }
            return sum + (endTag - end)
        }
    }
    
    private static func computeScriptsToHtmlRation(scriptSize: Int, htmlRange: Range<Int>, originURL: String, into warnings: inout [SecurityWarning]) {
        let htmlSize = htmlRange.count
        guard htmlSize > 0 else { return }
        var smallHTMLBonus: Int

        // Need to consider that the higher the in a small html is suspicious
        if htmlSize < 896 {
            smallHTMLBonus = 15
        } else if htmlSize < 1408 {
            smallHTMLBonus = 10
        } else {
            smallHTMLBonus = 0
        }
        
        let ratio = Double(scriptSize) / Double(htmlSize)
        let percent = Int(ratio * 100)
        #if DEBUG
//        print(" Inline JS Ratio: \(percent)% (\(scriptSize) bytes of \(htmlSize) HTML)")
        #endif
        if htmlSize < 896 && percent >= 50 {
            warnings.append(SecurityWarning(
                message: "This page relies almost entirely on JavaScript to function, yet contains no visible content or fallback for non-JS environments. This is highly indicative of cloaked content or malicious redirection.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.scriptIs70Percent + 15,
                url: originURL,
                source: .body,
            ))
            return
        }

        switch percent {
        case 0..<40:
            // no warning needed, but log for debug
            break
        case 40..<50:
            warnings.append(SecurityWarning(
                message: "Inline JS makes up \(percent)% of the HTML content. This may indicate excessive inline scripting. Modern frontend frameworks often inline JS, but excessive use can impact clarity, security, and maintainability.",
                severity: .info,
                penalty: PenaltySystem.Penalty.informational + smallHTMLBonus,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_JS_RATIO
            ))
        case 50..<70:
            warnings.append(SecurityWarning(
                message: "Inline JS dominates \(percent)% of the HTML content. This suggests heavy client-side scripting. Modern frontend frameworks often inline JS, but excessive use can impact clarity, security, and maintainability.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.scriptIs5070Percent + smallHTMLBonus,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_JS_RATIO
            ))
        case 70...:
            warnings.append(SecurityWarning(
                message: "Inline JS makes up \(percent)% of the HTML. This is highly suspicious and may indicate obfuscation or cloaking. Modern frontend frameworks often inline JS, but excessive use can impact clarity, security, and maintainability.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.scriptIs70Percent + smallHTMLBonus,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_JS_RATIO
            ))
        default:
            break
        }
    }
    
    private static func checkScriptDensity(internalCount: Int, externalCount: Int, htmlSize: Int, originURL: String, into warnings: inout [SecurityWarning]) {
        guard htmlSize > 0 else { return }

        let totalCount = internalCount + externalCount
        let ratio = Double(totalCount) / Double(htmlSize)
//        scripts per 1000 bytes, a kind of “density per KB"
        let normalized = ratio * 1000
        let rounded = String(format: "%.3f", normalized)

        // Detect excessive script count on large pages
        if totalCount >= 100 && htmlSize >= 1_000_000 {
            warnings.append(SecurityWarning(
                message: "This page includes \(totalCount) script tags and over 1MB of HTML content. This is highly abnormal and may indicate a script payload (cloaking kit or obfuscated attack).",
                severity: .critical,
                penalty: PenaltySystem.Penalty.bomboclotScript,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_SCRIPT_COUNT_LARGE_PAGE
            ))
        }

        switch normalized {
        case 0..<0.05:
            break
        case 0.05..<0.1:
            warnings.append(SecurityWarning(
                message: "Script density is \(rounded) script per 1000 bytes. This may be typical of apps using moderate scripting.",
                severity: .info,
                penalty: 0,
                url: originURL,
                source: .body
            ))
        case 0.1..<0.2:
            warnings.append(SecurityWarning(
                message: "Script density is \(rounded) script per 1000 bytes. This could indicate heavy client-side logic or potential cloaking.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.mediumScritpDensity,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_SCRIPT_DENSITY
            ))
        case 0.2...:
            warnings.append(SecurityWarning(
                message: "High script density detected (\(rounded)) script per 1000 bytes. This is abnormal and may signal obfuscation or cloaked logic.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.highScriptDensity,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_SCRIPT_DENSITY
            ))
        default:
            break
        }
    }
    
    private static func extractScriptAttributes(from scripts: [ScriptScanTarget]) -> (nonceList: [String], externalSources: [String], internalCount: Int) {
        var nonceList: [String] = []
        var srcList: [String] = []
        var internalCount = 0

        for script in scripts {
            if let nonce = script.nonceValue, script.origin == .inline {
                nonceList.append(nonce)
            }
            if let src = script.extractedSrc, script.origin == .httpsExternal {
                srcList.append(src)
            }
            if script.origin == .relative {
                internalCount += 1
            }
        }

        return (nonceList, srcList, internalCount)
    }
    
    private static func warningMessageForURIAndProtocol(from counters:(Int, Int, Int), warnings: inout [SecurityWarning], origin: String){
        let dataURICount = counters.0
        let protocolRelativeCounter = counters.1
        let protocolRelativeCounterWithIntegrity = counters.2
        if dataURICount > 0 {
            warnings.append(SecurityWarning(
                message: "This page includes \(dataURICount) script(s) using data: URIs. These are often used for obfuscation or tracking.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.scriptDataURI,
                url: origin,
                source: .body,
                bitFlags: WarningFlags.BODY_SCRIPT_DATAURI
            ))
        }
        if protocolRelativeCounter > 0 {
            warnings.append(SecurityWarning(
                message: "This page includes \(protocolRelativeCounter) script(s) using protocol-relative URLs. These are archaic and risky, as they rely on the current protocol and can lead to mixed content issues.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.protocolRelativeScriptSrc,
                url: origin,
                source: .body,
                bitFlags: WarningFlags.BODY_JS_SCRIPT_PROTOCOL
            ))
        }
        if protocolRelativeCounterWithIntegrity > 0 {
            warnings.append(SecurityWarning(
                message: "This page includes \(protocolRelativeCounterWithIntegrity) script(s) using protocol-relative URLs with integrity attributes. (Their correctness was not verified). While protected, these are archaic and risky, as they rely on the current protocol and can lead to mixed content issues.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.protocolRelativeScriptSRI,
                url: origin,
                source: .body,
                bitFlags: WarningFlags.BODY_JS_SCRIPT_PROTOCOL
            ))
        }
        if protocolRelativeCounter > 0, protocolRelativeCounterWithIntegrity > 0, protocolRelativeCounter != protocolRelativeCounterWithIntegrity {
            warnings.append(SecurityWarning(
                message: "\(protocolRelativeCounterWithIntegrity) protocol-relative script URLs have integrity attributes, while \(protocolRelativeCounter) others do not.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.protocolRelativeScriptSrc,
                url: origin,
                source: .body,
                bitFlags: WarningFlags.BODY_JS_SCRIPT_PROTOCOL
            ))
        }
    }
}
