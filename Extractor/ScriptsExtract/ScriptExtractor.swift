//
//  ScriptExtractor.swift
//  URLChecker
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation

struct ScriptExtractor {
    static func extract(body : Data,
                        origin: String,
                        domainAndTLD: String,
                        htmlRange: Range<Int>,
                        warnings: inout [SecurityWarning]) -> ScriptExtractionResult?
    {
        let startTime = Date()
        let tagPositions = DataSignatures.extractAllTagMarkers(in: body, within: htmlRange)
        var headPos = 0
        var bodyPos = 0
        var headEndPos: Int? = nil
        var bodyEndPos: Int? = nil
        var closingScriptPositions: [Int] = []
        var scriptCandidates: [ScriptScanTarget] = []
        //populate the array of candidates
        ScriptHelperFunction.populateScriptTarget(&scriptCandidates, tagPositions: tagPositions)
        let t1 = Date()
        //Look for body tag and pre filter the scriptCandidate
        ScriptHelperFunction.checkForOpenAndCloseTags(in: body,
                                 headerPos: &headPos,
                                 bodyPos: &bodyPos,
                                 closingHeadPos: &headEndPos,
                                 closingBodyPos: &bodyEndPos,
                                 closingScriptPositions: &closingScriptPositions,
                                 scriptCandidates: &scriptCandidates)
        
        // guarding against malformed html
        guard headPos != 0, headEndPos != nil else {
            warnings.append(SecurityWarning(
                message: "Missing or malformed <head> tag.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: origin,
                source: .body
            ))
            return nil
        }

        guard bodyPos != 0, bodyEndPos != nil else {
            warnings.append(SecurityWarning(
                message: "Missing or malformed <body> tag.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: origin,
                source: .body
            ))
            return nil
        }

        guard headPos < bodyPos else {
            warnings.append(SecurityWarning(
                message: "<head> appears after <body>. Invalid document structure.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: origin,
                source: .body
            ))
            return nil
        }
        let t2 = Date()
        print("⏱️ Step 1 - Tag pre-filter took \(Int(t2.timeIntervalSince(t1) * 1000))ms")
        // flag script findings -> this need to be refactor, we only need to copy no need to check script again
//            var confirmedScripts = checkForScriptTags(body, scriptCandidates: &scriptCandidates, asciiToCompare: interestingPrefix.script, lookAhead: 8)
        var initialScripts = scriptCandidates.filter { $0.flag == true }
        let t3 = Date()
        print("⏱️ Step 2 - Script detection took \(Int(t3.timeIntervalSince(t2) * 1000))ms")
        // find the tag closure of the script and check if there is a self closing slash
        if initialScripts.count != closingScriptPositions.count {
            warnings.append(SecurityWarning(
                message: "Mismatch in script open/close tag count. HTML might be malformed or cloaked.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: origin,
                source: .body
            ))
            return nil
        }
        ScriptHelperFunction.lookForScriptTagEnd(in: body, confirmedScripts: &initialScripts, asciiToCompare: byteLetters.endTag, lookAhead: 512)
        // Step 2.5 - Match confirmed scripts with closing </script> tags
//            Ensure the pair are correct! If the closing tag is not found in 512 byt the dev is hotdogwater or a scam
        guard initialScripts.allSatisfy({ $0.end != nil }) && !closingScriptPositions.isEmpty else {
            warnings.append(SecurityWarning(
                message: "Script tag could not be closed within 512 bytes. This is highly unusual and may indicate malformed or suspicious HTML.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.scriptIsMoreThan512,
                url: origin,
                source: .body
            ))
            return nil
        }
        var confirmedScripts = initialScripts
        ScriptHelperFunction.pairScriptsWithClosings(scripts: &confirmedScripts, closingTags: closingScriptPositions, body: body)

        let t4 = Date()
        print("⏱️ Step 3 - Tag closure detection took \(Int(t4.timeIntervalSince(t3) * 1000))ms")
        // primary school math to find context
        ScriptHelperFunction.classifyContext(for: &confirmedScripts, headPos: headPos, bodyPos: bodyPos)
        let t5 = Date()
        print("⏱️ Step 4 - Context classification took \(Int(t5.timeIntervalSince(t4) * 1000))ms")
        // look for src
        ScriptHelperFunction.scanScriptSrc(in: body, scripts: &confirmedScripts)
        let t6 = Date()
        print("⏱️ Step 5 - Src position scan took \(Int(t6.timeIntervalSince(t5) * 1000))ms")
        // sort the scripts to their origin
        ScriptHelperFunction.assignScriptSrcOrigin(in: body, scripts: &confirmedScripts)
        let t7 = Date()
        print("⏱️ Step 6 - Script origin classification took \(Int(t7.timeIntervalSince(t6) * 1000))ms")
        //find nonce script and value
        ScriptHelperFunction.findNonceScript(in: body, scripts: &confirmedScripts)
        let t8 = Date()
        print("⏱️ Step 7 - Script find nonce took \(Int(t8.timeIntervalSince(t7) * 1000))ms")
        
        
        
        let duration = Date().timeIntervalSince(startTime)
        print("✅ Total scan completed in \(Int(duration * 1000))ms")
        print("📦 Summary of the \(confirmedScripts.count), with (\(closingScriptPositions.count)) closing position Script Findings:")
//        for script in confirmedScripts {
//            guard let endTag = script.endTagPos else { continue }
//            
//            let fullRange = script.start..<endTag
//            let fullSnippet = body[fullRange]
//            let type = script.findings == .inlineJS ? "Inline" : "External"
//            let context = script.context
//            let origin = script.origin?.rawValue ?? "unknown"
//            
//            print("📍 Script [\(type)] from \(script.start) to \(endTag) — origin: \(origin) in \(context?.rawValue)")
//            
//            if let fullDecoded = String(data: fullSnippet, encoding: .utf8) {
//                print("🔹 Full tag preview:")
//                if fullDecoded.count > 60 {
//                    print("...\(fullDecoded.prefix(30))\n...\(fullDecoded.suffix(30))")
//                } else {
//                    print(fullDecoded)
//                }
//            }
//            
//            if script.findings == .inlineJS, let start = script.end {
//                let jsStart = start
//                let jsEnd = endTag
//                let jsLength = jsEnd - jsStart
//
//                if jsLength > 0 {
//                    let firstBytes = body[jsStart..<min(jsStart + 20, jsEnd)]
//                    let lastBytes = body[max(jsEnd - 20, jsStart)..<jsEnd]
//
//                    let startPreview = String(data: firstBytes, encoding: .utf8) ?? ""
//                    let endPreview = String(data: lastBytes, encoding: .utf8) ?? ""
//
//                    print("💡 Inline content preview:\n...\(startPreview)...\n...\(endPreview)...")
//                } else {
//                    print("⚠️ Inline script has no content.")
//                }
//            } else {
//                let snippetStart = min(script.start + 20, endTag)
//                let snippetEnd = max(endTag - 20, snippetStart)
//                let outerSlice = body[snippetStart..<snippetEnd]
//                if let preview = String(data: outerSlice, encoding: .utf8) {
//                    print("🔗 External tag preview:\n...\(preview)...")
//                }
//            }
//            
//            print("---")
//        }
        return ScriptExtractionResult(scripts: confirmedScripts, htmlRange: htmlRange)

    }
}
    
    
