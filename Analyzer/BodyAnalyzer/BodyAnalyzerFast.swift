//
//  BodyAnalyzerFast.swift
//  URLChecker
//
//  Created by Chief Hakka on 11/04/2025.
//

import Foundation

struct BodyAnalyzerFast {
    struct ScriptScanTarget {
        let start: Int
        var end: Int?
        var flag: Bool?
        var findings: ScanFlag?
        var context: ScriptContext?
        var srcPos: Int?
        
        enum ScriptContext: String {
            case inHead = "In Head"
            case inBody = "In Body"
            case unknown = "Unknown"
        }
    }
    
    enum ScanFlag {
        case scriptTag
        case inlineJS
        case suspectedObfuscation
    }
    
    
    static func analyze(body: Data, contentType: String, responseCode: Int, origin: String, domainAndTLD: String, into warnings: inout [SecurityWarning]) {
        guard responseCode == 200, contentType.contains("text/html") else { return }
        let startTime = Date()
        let bodySize: Int = body.count
        let htmlRange = DataSignatures.extractHtmlTagRange(in: body)
        guard let htmlRange else {
            warnings.append(SecurityWarning(message: "No HTML found in response.",
                                            severity: .critical,
                                            penalty: PenaltySystem.Penalty.critical,
                                            url: origin,
                                            source: .body))
            return
        }
        if bodySize > 900_000 {
            warnings.append(SecurityWarning(message: "Body too large for fast scan.", severity: .info, penalty: 0, url: origin, source: .body))
            return
        }
        else {
            let tagPositions = DataSignatures.extractAllTagMarkers(in: body, within: htmlRange)
            var headPos = 0
            var bodyPos = 0
            var scriptCandidates: [ScriptScanTarget] = []
            //populate the array of candidates
            populateScriptTarget(&scriptCandidates, tagPositions: tagPositions)
            //Look for body tag and pre filter the scriptCandidate
            checkForBodyAndHeadAndPreFilter(in: body, headerPos: &headPos, bodyPos: &bodyPos, scriptCandidates: &scriptCandidates)
            // flag script findings
            var confirmedScripts = checkForScriptTags(body, scriptCandidates: &scriptCandidates, asciiToCompare: interestingPrefix.script, lookAhead: 8)
            // find the tag closure of the script
            lookForScriptTagEnd(in: body, confirmedScripts: &confirmedScripts, asciiToCompare: byteLetters.endTag, lookAhead: 256)
            // primary school math to find context
            classifyContext(for: &confirmedScripts, headPos: headPos, bodyPos: bodyPos)
            // look for src
            headScriptSrcScan(in: body, scripts: &confirmedScripts)
            let duration2 = Date().timeIntervalSince(startTime)
            print("pre print Sacn completed in \(Int(duration2 * 1000))ms")
            for script in confirmedScripts {
                if let end = script.end {
                    let previewEnd = min(end + 1, body.count)
                    let preview = String(data: body[script.start..<previewEnd], encoding: .utf8) ?? "[unreadable]"
                    print("Script at \(script.start): \(preview)")
                } else {
                    let fallbackEnd = min(script.start + 20, body.count)
                    let preview = String(data: body[script.start..<fallbackEnd], encoding: .utf8) ?? "[unreadable]"
                    print("Script at \(script.start): \(preview)")
                }

                print(" → Context: \(script.context?.rawValue ?? "unknown")")

                if let srcPos = script.srcPos, srcPos != 0 {
                    let srcEnd = min(srcPos + 64, body.count)
                    let srcPreview = String(data: body[srcPos..<srcEnd], encoding: .utf8) ?? "[unreadable]"
                    print(" → src= preview: \(srcPreview)")
                }
            }
            let duration = Date().timeIntervalSince(startTime)
            print("post print Sacn completed in \(Int(duration * 1000))ms")
        }
    }
    private static func populateScriptTarget(_ target: inout [ScriptScanTarget], tagPositions: [Int]) -> Void {
        
        for pos in tagPositions {
            let candidate = ScriptScanTarget(
                start: pos,
                end: nil,
                findings: nil
            )
            target.append(candidate)
        }
    }
    
    private static func checkForScriptTags(
        _ body: Data,
        scriptCandidates: inout [ScriptScanTarget],
        asciiToCompare: [UInt8],
        lookAhead: Int
    ) -> [ScriptScanTarget] {
        var confirmed: [ScriptScanTarget] = []
        
        for i in 0..<scriptCandidates.count {
            if scriptCandidates[i].flag == false {
                continue
            }
            if DataSignatures.matchesAsciiTag(at: scriptCandidates[i].start, in: body, asciiToCompare: asciiToCompare, lookAheadWindow: lookAhead) {
                scriptCandidates[i].flag = true
                confirmed.append(scriptCandidates[i])
            }
        }
        
        return confirmed
    }
    
    private static func checkForBodyAndHeadAndPreFilter(
        in body: Data,
        headerPos: inout Int,
        bodyPos: inout Int,
        scriptCandidates: inout [ScriptScanTarget]
    ) -> Void {
        var headFound = false
        var bodyFound = false
        
        for i in 0..<scriptCandidates.count {
            let pos = scriptCandidates[i].start
            
            if !headFound && DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: interestingPrefix.head, lookAheadWindow: 8) {
                headerPos = pos
                headFound = true
            } else if !bodyFound && DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: interestingPrefix.body, lookAheadWindow: 8) {
                bodyPos = pos
                bodyFound = true
            } else {
                let hint = DataSignatures.fastScriptByteHint(at: pos, in: body, hint: [byteLetters.s, byteLetters.S])
                scriptCandidates[i].flag = hint
            }
        }
    }
    
    private static func scanSlice(_ body: Data, in range: Range<Int>, for pattern: [UInt8]) -> Bool {
        return body[range].containsBytes(of: pattern)
        
    }
    
    private static func classifyContext(
        for scripts: inout [ScriptScanTarget],
        headPos: Int,
        bodyPos: Int
    ) {
        for i in 0..<scripts.count {
            let pos = scripts[i].start
            
            if pos < headPos {
                scripts[i].context = .unknown
            } else if pos >= headPos && pos < bodyPos {
                scripts[i].context = .inHead
            } else if pos >= bodyPos {
                scripts[i].context = .inBody
            } else {
                scripts[i].context = .unknown
            }
        }
    }
    
    private static func headScriptSrcScan(in body: Data, scripts: inout [ScriptScanTarget], lookAhead: Int = 64, respectTagEnd: Bool = true) {
        for i in 0..<scripts.count {
            guard scripts[i].context == .inHead else { continue }

            let start = scripts[i].start

            guard respectTagEnd, let tagEnd = scripts[i].end else {
                let scanRange = start..<min(start + lookAhead, body.count)
                let (found, position) = body.containsBytesCaseInsensitive(of: interestingPrefix.src, startIndex: scanRange.lowerBound)
                if found {
                    scripts[i].srcPos = position
                } else {
                    scripts[i].findings = .inlineJS
                }
                continue
            }

            let scanRange = start..<min(tagEnd + 1, body.count)
            let (found, position) = body.containsBytesCaseInsensitive(of: interestingPrefix.src, startIndex: scanRange.lowerBound)
            if found {
                scripts[i].srcPos = position
            } else {
                scripts[i].findings = .inlineJS
            }
        }
    }
    
    private static func lookForScriptTagEnd(in body: Data, confirmedScripts: inout [ScriptScanTarget], asciiToCompare: UInt8, lookAhead: Int = 64) {
        for i in 0..<confirmedScripts.count {
            let start = confirmedScripts[i].start
            let searchRange = start..<min(start + lookAhead, body.count)
            let entagPos = DataSignatures.extractAllTagMarkers(in: body, within: searchRange, tag: asciiToCompare)
            
            if let first = entagPos.first {
                confirmedScripts[i].end = first
            } else {
                confirmedScripts[i].findings = .suspectedObfuscation
            }
        }
    }
}
