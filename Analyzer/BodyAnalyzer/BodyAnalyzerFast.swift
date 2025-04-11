import Foundation

struct BodyAnalyzerFast {
    enum ScriptOrigin: String {
        case relative = "relative"
        case protocolRelative = "protocolRelative"
        case dataURI = "dataURI"
        case httpExternal = "http protocol"
        case httpsExternal = "https External"
        case unknown = "unknown"
        case malformed = "malformed"
    }

    struct ScriptScanTarget {
        let start: Int
        var end: Int?
        var flag: Bool?
        var findings: ScanFlag?
        var context: ScriptContext?
        var srcPos: Int?
        var origin: ScriptOrigin?
        
        enum ScriptContext: String {
            case inHead = "In Head"
            case inBody = "In Body"
            case unknown = "Unknown"
        }
    }
    
    enum ScanFlag {
        case script
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
            let t1 = Date()
            //Look for body tag and pre filter the scriptCandidate
            checkForBodyAndHeadAndPreFilter(in: body, headerPos: &headPos, bodyPos: &bodyPos, scriptCandidates: &scriptCandidates)
            let t2 = Date()
            print("⏱️ Step 1 - Tag pre-filter took \(Int(t2.timeIntervalSince(t1) * 1000))ms")
            // flag script findings
            var confirmedScripts = checkForScriptTags(body, scriptCandidates: &scriptCandidates, asciiToCompare: interestingPrefix.script, lookAhead: 8)
            let t3 = Date()
            print("⏱️ Step 2 - Script detection took \(Int(t3.timeIntervalSince(t2) * 1000))ms")
            // find the tag closure of the script
            lookForScriptTagEnd(in: body, confirmedScripts: &confirmedScripts, asciiToCompare: byteLetters.endTag, lookAhead: 256)
            let t4 = Date()
            print("⏱️ Step 3 - Tag closure detection took \(Int(t4.timeIntervalSince(t3) * 1000))ms")
            // primary school math to find context
            classifyContext(for: &confirmedScripts, headPos: headPos, bodyPos: bodyPos)
            let t5 = Date()
            print("⏱️ Step 4 - Context classification took \(Int(t5.timeIntervalSince(t4) * 1000))ms")
            // look for src
            headScriptSrcScan(in: body, scripts: &confirmedScripts)
            let t6 = Date()
            print("⏱️ Step 5 - Src position scan took \(Int(t6.timeIntervalSince(t5) * 1000))ms")
            // sort the header script to their origin
            assignScriptSrcOrigin(in: body, scripts: &confirmedScripts)
            let t7 = Date()
            print("⏱️ Step 6 - Script origin classification took \(Int(t7.timeIntervalSince(t6) * 1000))ms")
            
            let duration = Date().timeIntervalSince(startTime)
            print("✅ Total scan completed in \(Int(duration * 1000))ms")
            print("📦 Summary of Script Findings:")
            for script in confirmedScripts {
                let ctx = script.context?.rawValue ?? "N/A"
                let origin = script.origin?.rawValue ?? "None"
                let finding = script.findings.map { "\($0)" } ?? "None"
                print("→ Script at \(script.start): context=\(ctx), origin=\(origin), findings=\(finding)")
            }
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
    
    private static func headScriptSrcScan(in body: Data, scripts: inout [ScriptScanTarget], lookAhead: Int = 96, respectTagEnd: Bool = true) {
        for i in 0..<scripts.count {
            guard scripts[i].context == .inHead else { continue }

            let start = scripts[i].start
            
            let earlyRange = start..<min(start + 32, body.count)
            let eqSigns = DataSignatures.extractAllTagMarkers(in: body, within: earlyRange, tag: UInt8(ascii: "="))
            guard let eq = eqSigns.first else {
                scripts[i].findings = .inlineJS
                continue
            }
            guard eq >= 3 else {
                scripts[i].findings = .inlineJS
                continue
            }

            let s = body[eq - 3] | 0x20
            let r = body[eq - 2] | 0x20
            let c = body[eq - 1] | 0x20

            guard s == UInt8(ascii: "s"),
                  r == UInt8(ascii: "r"),
                  c == UInt8(ascii: "c") else {
                scripts[i].findings = .inlineJS
                continue
            }

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
            if found, let pos = position, pos > start, pos < tagEnd {
                scripts[i].srcPos = pos
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
    
    private static func assignScriptSrcOrigin(in body: Data, scripts: inout [ScriptScanTarget]) {
        for i in 0..<scripts.count {
            guard let srcPos = scripts[i].srcPos, let tagEnd = scripts[i].end else { continue }
            let origin = classifyScriptSrc(in: body, from: srcPos, upTo: tagEnd)
            scripts[i].origin = origin
        }
    }

    private static func classifyScriptSrc(in body: Data, from srcPos: Int, upTo tagEnd: Int) -> ScriptOrigin {
        let scanLimit = min(tagEnd, body.count)
        let scanRange = srcPos..<scanLimit

        let quoteCandidates = DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "\"")) +
                              DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "'"))

        let sortedQuotes = quoteCandidates.sorted()
        guard sortedQuotes.count >= 2 else {
            return .malformed
        }

        let qStart = sortedQuotes[0]
        let qEnd = sortedQuotes[1]
        guard qEnd > qStart + 1 else {
            return .malformed
        }

        let valueRange = (qStart + 1)..<qEnd
        let value = body[valueRange]

        if value.starts(with: [UInt8(ascii: "/")]) {
            return .relative
        }
        if value.starts(with: [UInt8(ascii: "/"), UInt8(ascii: "/")]) {
            return .protocolRelative
        }
        if value.starts(with: Array("data:".utf8)) {
            return .dataURI
        }
        if value.starts(with: Array("http://".utf8)) {
            return .httpExternal
        }
        if value.starts(with: Array("https://".utf8)) {
            return .httpsExternal
        }

        return .unknown
    }
}
