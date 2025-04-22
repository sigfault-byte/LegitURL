//  ScriptSecurityAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation
struct ScriptSecurityAnalyzer {
    static func analyze(scripts: [ScriptScanTarget], body: Data, origin: String, htmlRange: Range<Int>, into warnings: inout [SecurityWarning]) -> ScriptSourceToMatchCSP {
        
        let totalInlineScriptBytes = computeInlineScriptBytes(scripts)
        //Cpmpute html to script ratio
        computeScriptsToHtmlRation(scriptSize: totalInlineScriptBytes, htmlRange: htmlRange, originURL: origin, into: &warnings)
        
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
        
        // Flag abnormal script origin
        let dataURICount = checkingScriptOrigin(originURL: origin, scripts: scripts, warnings: &warnings)
        //TODO Double check the script possibilities
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
        
        let (nonceList, srcList, internalCount) = extractScriptAttributes(from: scripts)
        
        checkScriptDensity(internalCount: internalCount, externalCount: srcList.count, htmlSize: htmlRange.count, originURL: origin, into: &warnings)
        
        ScriptInlineAnalyzer.analyze(scripts: scripts, body: body, origin: origin, into: &warnings)

        return ScriptSourceToMatchCSP(nonceList: nonceList, externalSources: srcList)
    }
    
    //MARK --- Helper
    
    private static func checkingScriptOrigin(originURL: String, scripts: [ScriptScanTarget], warnings: inout [SecurityWarning]) -> Int {
        var dataUriCounter = 0

        for script in scripts {
            guard let origin = script.origin else { continue }

            switch origin {
            case .httpExternal:
                warnings.append(SecurityWarning(
                    message: "External script loaded over HTTP. This is insecure and exposes users to injection risks.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: originURL,
                    source: .body
                ))

            case .dataURI:
                dataUriCounter += 1

            case .unknown:
                warnings.append(SecurityWarning(
                    message: "Script origin could not be determined. This may indicate cloaking or malformed attributes.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scriptUnknownOrigin,
                    url: originURL,
                    source: .body,
                    bitFlags: WarningFlags.BODY_SCRIPT_UNKNOWN_ORIGIN
                ))

            case .malformed:
                warnings.append(SecurityWarning(
                    message: "Malformed script tag or broken src attribute detected.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scriptMalformed,
                    url: originURL,
                    source: .body,
                    bitFlags: WarningFlags.BODY_SCRIPT_UNKNOWN_ORIGIN
                ))

            default:
                break
            }
        }

        return dataUriCounter
    }
    
    private static func computeInlineScriptBytes(_ scripts: [ScriptScanTarget]) -> Int {
        return scripts.reduce(0) { sum, script in
            guard script.findings == .inlineJS,
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
//        DEBUG
        print("📊 Inline JS Ratio: \(percent)% (\(scriptSize) bytes of \(htmlSize) HTML)")

        if htmlSize < 896 && percent >= 50 {
            warnings.append(SecurityWarning(
                message: "This page relies almost entirely on JavaScript to function, yet contains no visible content or fallback for non-JS environments. This is highly indicative of cloaked content or malicious redirection.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.scriptIs70Percent + 15,
                url: originURL,
                source: .body,
                bitFlags: WarningFlags.BODY_HIGH_JS_RATIO_SMALL_HTML
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
                bitFlags: smallHTMLBonus == 0 ? nil : WarningFlags.BODY_HIGH_JS_RATIO_SMALL_HTML
            ))
        case 50..<70:
            warnings.append(SecurityWarning(
                message: "Inline JS dominates \(percent)% of the HTML content. This suggests heavy client-side scripting. Modern frontend frameworks often inline JS, but excessive use can impact clarity, security, and maintainability.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.scriptIs5070Percent + smallHTMLBonus,
                url: originURL,
                source: .body,
                bitFlags: smallHTMLBonus == 0 ? nil : WarningFlags.BODY_HIGH_JS_RATIO_SMALL_HTML
            ))
        case 70...:
            warnings.append(SecurityWarning(
                message: "Inline JS makes up \(percent)% of the HTML. This is highly suspicious and may indicate obfuscation or cloaking. Modern frontend frameworks often inline JS, but excessive use can impact clarity, security, and maintainability.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.scriptIs70Percent + smallHTMLBonus,
                url: originURL,
                source: .body,
                bitFlags: smallHTMLBonus == 0 ? nil : WarningFlags.BODY_HIGH_JS_RATIO_SMALL_HTML
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
            if let nonce = script.nonceValue {
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
}
