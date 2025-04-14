//  scriptSecurityAnalyzer.swift
//  URLChecker
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation
struct ScriptSecurityAnalyzer {
    static func analyze(scripts: [ScriptScanTarget], body: Data, origin: String, htmlRange: Range<Int>, into warnings: inout [SecurityWarning]) -> ScriptSourceToMatchCSP {
        
        let totalInlineScriptBytes = computeInlineScriptBytes(scripts)
        //Cpmpute html to script ratio
        computeScriptsToHtmlRation(scriptSize: totalInlineScriptBytes, htmlRange: htmlRange, originURL: origin, into: &warnings)
        // Flag abnormal script origin
        checkingScriptOrigin(originURL: origin, scripts: scripts, warnings: &warnings)
        
        let (nonceList, srcList, internalCount) = extractScriptAttributes(from: scripts)
        
        checkScriptDensity(internalCount: internalCount, externalCount: srcList.count, htmlSize: htmlRange.count, originURL: origin, into: &warnings)
        
        ScriptInlineAnalyzer.analyze(scripts: scripts, body: body, origin: origin, into: &warnings)

        return ScriptSourceToMatchCSP(nonceList: nonceList, externalSources: srcList)
    }
    
    //MARK --- Helper
    
    private static func checkingScriptOrigin(originURL: String, scripts: [ScriptScanTarget], warnings: inout [SecurityWarning]) {
        for script in scripts {
            guard let origin = script.origin else { continue }

            switch origin {
            case .httpExternal:
                // 🚨 Insecure HTTP script
                warnings.append(SecurityWarning(
                    message: "❌ External script loaded over HTTP. This is insecure and exposes users to injection risks.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: originURL,
                    source: .body
                ))

            case .dataURI:
                warnings.append(SecurityWarning(
                    message: "⚠️ Script uses a data: URI. This is highly suspicious and often used for obfuscation.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scriptDataURI,
                    url: originURL,
                    source: .body
                ))

            case .unknown:
                warnings.append(SecurityWarning(
                    message: "⚠️ Script origin could not be determined. This may indicate cloaking or malformed attributes.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scriptUnknownOrigin,
                    url: originURL,
                    source: .body
                ))

            case .malformed:
                warnings.append(SecurityWarning(
                    message: "🛑 Malformed script tag or broken src attribute detected.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.scriptMalformed,
                    url: originURL,
                    source: .body
                ))

            default:
                // Other origins are not flagged (inline, relative, https, etc.)
                break
            }
        }
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
        
        let ratio = Double(scriptSize) / Double(htmlSize)
        let percent = Int(ratio * 100)
//        DEBUG
        print("📊 Inline JS Ratio: \(percent)% (\(scriptSize) bytes of \(htmlSize) HTML)")

        switch percent {
        case 0..<40:
            // no warning needed, but log for debug
            break
        case 40..<50:
            warnings.append(SecurityWarning(
                message: "⚠️ Inline JS makes up \(percent)% of the HTML content. This may indicate excessive inline scripting.",
                severity: .info,
                penalty: PenaltySystem.Penalty.informational,
                url: originURL,
                source: .body
            ))
        case 50..<70:
            warnings.append(SecurityWarning(
                message: "🚨 Inline JS dominates \(percent)% of the HTML content. This suggests heavy client-side scripting.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.scriptIs5070Percent,
                url: originURL,
                source: .body
            ))
        case 70...:
            warnings.append(SecurityWarning(
                message: "🛑 Inline JS makes up \(percent)% of the HTML. This is highly suspicious and may indicate obfuscation or cloaking.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.scriptIs70Percent,
                url: originURL,
                source: .body
            ))
        default:
            break
        }
    }
    
    private static func checkScriptDensity(internalCount: Int, externalCount: Int, htmlSize: Int, originURL: String, into warnings: inout [SecurityWarning]) {
        guard htmlSize > 0 else { return }

        let totalCount = internalCount + externalCount
        let ratio = Double(totalCount) / Double(htmlSize)
        let normalized = ratio * 1000
        let rounded = String(format: "%.3f", normalized)

        print("📏 Total script density: \(rounded) (total: \(totalCount), html size: \(htmlSize) bytes)")

        switch normalized {
        case 0..<0.05:
            break
        case 0.05..<0.1:
            warnings.append(SecurityWarning(
                message: "ℹ️ Script density is \(rounded). This may be typical of apps using moderate scripting.",
                severity: .info,
                penalty: 0,
                url: originURL,
                source: .body
            ))
        case 0.1..<0.2:
            warnings.append(SecurityWarning(
                message: "⚠️ Script density is \(rounded). This could indicate heavy client-side logic or potential cloaking.",
                severity: .suspicious,
                penalty: 10,
                url: originURL,
                source: .body
            ))
        case 0.2...:
            warnings.append(SecurityWarning(
                message: "🚨 High script density detected (\(rounded)). This is abnormal and may signal obfuscation or cloaked logic.",
                severity: .dangerous,
                penalty: 20,
                url: originURL,
                source: .body
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
