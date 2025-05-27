//
//  ScriptExtractor.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation

struct ScriptAndMetaExtractor {
    static func extract(body : Data,
                        origin: String,
                        domainAndTLD: String,
                        htmlRange: Range<Int>,
                        warnings: inout [SecurityWarning]) -> (ScriptExtractionResult?, metaCSP: Data?)
    {
        #if DEBUG
        let startTime = Date()
        #endif
        let tagPositions = DataSignatures.extractAllTagMarkers(in: body, within: htmlRange)
        var headPos = 0
        var bodyPos = 0
        var headEndPos: Int? = nil
        var bodyEndPos: Int? = nil
        var closingScriptPositions: [Int] = []
        var scriptCandidates: [ScriptScanTarget] = []
        //populate the array of candidates
        ScriptHelperFunction.populateScriptTarget(&scriptCandidates, tagPositions: tagPositions)
        #if DEBUG
        let t1 = Date()
        #endif
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
                source: .body,
                bitFlags: WarningFlags.SLOPPY_DEVELOPMENT
            ))
            return (nil, nil)
        }

        if bodyPos == 0 || bodyEndPos == nil {
            var missing: String = ""
            if bodyPos == 0{
                missing = "<body>"
            } else if bodyEndPos == nil {
                missing = "</body>"
            }
            warnings.append(SecurityWarning(
                message: "Missing or malformed \(missing) tag .",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.missingMalformedBodyTag,
                url: origin,
                source: .body,
                bitFlags: WarningFlags.SLOPPY_DEVELOPMENT
            ))
            // The next guard will safely exit. Still this should be enough to bail
//            return (nil, nil)
        }

        guard headPos < bodyPos else {
            warnings.append(SecurityWarning(
                message: "Invalid document structure <head> or <body> tag are not in the correct order or malformed.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: origin,
                source: .body
            ))
            return (nil, nil)
        }
        #if DEBUG
        let t2 = Date()
        print("Step 1 - Tag pre-filter took \(Int(t2.timeIntervalSince(t1) * 1000))ms")
        #endif
        // MARK: Look if some meta are injecting meta equiv CSP
        let metaCSP = CSPMetaExtractor.extract(from: body, tags:tagPositions, range: headPos..<headEndPos!)
//            var confirmedScripts = checkForScriptTags(body, scriptCandidates: &scriptCandidates, asciiToCompare: interestingPrefix.script, lookAhead: 8)
//        Can safely force unwrap there is a guard !
//        collect all start var from each scriptCandidate and store them in the [Int]
//        let headRange = 0..<headEndPos!
        var initialScripts = scriptCandidates.filter { $0.flag == true }
//        let tagToDismiss: [Int] = initialScripts.map { $0.start }
//        Todo: Finish the function, the goal is to retrive meta-http that override CSP to match again the CSP. And compare title to the domain
//        let headFindings = HTMLHeadAnalyzer.analyze(headContent: body[headRange], tagPos: tagPositions, tagPosToDismiss: tagToDismiss, warnings: &warnings, origin: origin)
        // guard if there are no script to analyze
        guard !initialScripts.isEmpty else { return (nil, nil) }
        #if DEBUG
        let t3 = Date()
        print("Step 2 - Script detection took \(Int(t3.timeIntervalSince(t2) * 1000))ms")
        #endif
        // find the tag closure of the script and check if there is a self closing slash
        
        if initialScripts.count != closingScriptPositions.count {
            warnings.append(SecurityWarning(
                message: "Mismatch in script open/close tag count. HTML might be malformed or cloaked.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: origin,
                source: .body
            ))
            return (nil, nil)
        }
        ScriptHelperFunction.lookForScriptTagEnd(in: body, confirmedScripts: &initialScripts, asciiToCompare: byteLetters.endTag, lookAhead: 3072)
//         Step 2.5 - Match confirmed scripts with closing </script> tags
//            Ensure the pair are correct! If the closing tag is not found in 512 byt the dev is hotdogwater or a scam
//        instgram closing tag is farther than 1024 fucking bytes
        
//        for script in initialScripts where script.end == nil {
//            let previewStart = script.start
//            let previewEnd = min(previewStart + 1024, body.count)
//            let previewData = body[previewStart..<previewEnd]
//            if let previewString = String(data: previewData, encoding: .utf8) {
//                print("Unclosed script tag at \(previewStart). First 1024 bytes:\n\(previewString)")
//            } else {
//                print("Unclosed script tag at \(previewStart). Unable to decode preview.")
//            }
//        }

        guard initialScripts.allSatisfy({ $0.end != nil }) && !closingScriptPositions.isEmpty else {
            warnings.append(SecurityWarning(
                message: "Script tag could not be closed within 3072 bytes. This is highly unusual and may indicate malformed or suspicious HTML. HTML body was not analyzed",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.scriptIsMoreThan512,
                url: origin,
                source: .body,
                bitFlags: WarningFlags.BODY_SCRIPT_END_NOT_FOUND
            ))
            return (nil, nil)
        }
        var confirmedScripts = initialScripts
        ScriptHelperFunction.pairScriptsWithClosings(scripts: &confirmedScripts, closingTags: closingScriptPositions, body: body)
        
        #if DEBUG
        let t4 = Date()
        print("Step 3 - Tag closure detection took \(Int(t4.timeIntervalSince(t3) * 1000))ms")
        #endif
        // primary school math to find context
        ScriptHelperFunction.classifyContext(for: &confirmedScripts, headPos: headPos, bodyPos: bodyPos)
        
        #if DEBUG
        let t5 = Date()
        print("Step 4 - Context classification took \(Int(t5.timeIntervalSince(t4) * 1000))ms")
        #endif
        // look for src
        ScriptHelperFunction.scanScriptSrc(in: body, scripts: &confirmedScripts)
        
        ScriptHelperFunction.scanScriptType(in: body, scripts: &confirmedScripts)
        
        //filter out js application data! no use anymore
//        ScriptHelperFunction.filterOutDataScripts(&confirmedScripts)
        #if DEBUG
        let t6 = Date()
        print("Step 5 - Src position scan took \(Int(t6.timeIntervalSince(t5) * 1000))ms")
        #endif
        // sort the scripts to their origin
        ScriptHelperFunction.assignScriptSrcOrigin(in: body, scripts: &confirmedScripts)
        
        #if DEBUG
        let t7 = Date()
        print("Step 6 - Script origin classification took \(Int(t7.timeIntervalSince(t6) * 1000))ms")
        #endif
        
        //find nonce script and value, data URI is useless nonce doesnt work on it, but many do the error?
        if confirmedScripts.contains(where: {
            $0.origin == .inline || $0.origin == .dataURI
        }) {
            ScriptHelperFunction.findNonceScript(in: body, scripts: &confirmedScripts)
        }
        
        //get integrityValue
        if confirmedScripts.contains(where: {
            $0.origin == .httpsExternal || $0.origin == .relative || $0.origin == .protocolRelative
        }) {
                ScriptHelperFunction.findIntegrityScript(in: body, scripts: &confirmedScripts)
        }
        
//        get module crossoriginValue
        if confirmedScripts.contains(where: { $0.isModule == true } ) {
            var crossOriginWarnings: [SecurityWarning] = []
            crossOriginWarnings = ScriptHelperFunction.findCrossOriginModuleValue(in: body, scripts: &confirmedScripts, origin: origin)
            if !crossOriginWarnings.isEmpty {
                warnings.append(contentsOf: crossOriginWarnings)
            }
        }
        
        #if DEBUG
        let t8 = Date()
        print("Step 7 - Script find nonce took \(Int(t8.timeIntervalSince(t7) * 1000))ms")
        
        
        let duration = Date().timeIntervalSince(startTime)
        print("Total scan completed in \(Int(duration * 1000))ms")
        print("Summary of the \(confirmedScripts.count), with (\(closingScriptPositions.count)) closing position Script Findings:")
        #endif
        //            DEBUG
//        for script in confirmedScripts {
//            guard let endTag = script.endTagPos else { continue }
//
//            let fullRange = script.start..<endTag
//            let fullSnippet = body[fullRange]
//            let type = script.findings == .inlineJS ? "Inline" : "External"
//            let context = script.context
//            let origin = script.origin?.rawValue ?? "unknown"

            
//            print("Script [\(type)] from \(script.start) to \(endTag) — origin: \(origin) in \(context?.rawValue)")
//
//            if let fullDecoded = String(data: fullSnippet, encoding: .utf8) {
//                print(" Full tag preview:")
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
//                    print("Inline content preview:\n...\(startPreview)...\n...\(endPreview)...")
//                } else {
//                    print("Inline script has no content.")
//                }
//            } else {
//                let snippetStart = min(script.start + 20, endTag)
//                let snippetEnd = max(endTag - 20, snippetStart)
//                let outerSlice = body[snippetStart..<snippetEnd]
//                if let preview = String(data: outerSlice, encoding: .utf8) {
//                    print("External tag preview:\n...\(preview)...")
//                }
//            }
//
//            print("---")
//        }
        return (ScriptExtractionResult(scripts: confirmedScripts, htmlRange: htmlRange), metaCSP)

    }
}
