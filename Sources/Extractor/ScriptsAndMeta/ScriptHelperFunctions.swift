//
//  HelperFunctions.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation

struct ScriptHelperFunction {
    static func pairScriptsWithClosings(scripts: inout [ScriptScanTarget], closingTags: [Int], body: Data) {
        guard scripts.count == closingTags.count else {
            //TODO: this is  redundnat there s a guard before the function call
#if DEBUG
            print("Cannot zip scripts with closings count mismatch.")
#endif
            return
        }
        
        for i in 0..<scripts.count {
            scripts[i].endTagPos = closingTags[i]
        }
    }
    
    static func populateScriptTarget(_ target: inout [ScriptScanTarget], tagPositions: [Int]) -> Void {
        
        for pos in tagPositions {
            let candidate = ScriptScanTarget(
                start: pos,
                end: nil,
                findings: nil
            )
            target.append(candidate)
        }
    }
    
    static func checkForScriptTags(
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
    
    static func checkForOpenAndCloseTags(
        in body: Data,
        headerPos: inout Int,
        bodyPos: inout Int,
        closingHeadPos: inout Int?,
        closingBodyPos: inout Int?,
        closingScriptPositions: inout [Int],
        scriptCandidates: inout [ScriptScanTarget]
    ) -> Void {
        var headFound = false
        var bodyFound = false
        var headEndFound = false
        var bodyEndFound = false
        
        
        for i in 0..<scriptCandidates.count {
            let pos = scriptCandidates[i].start
            guard pos + 1 < body.count else { continue }
            
            if body[pos + 1] == UInt8(ascii: "/") {
                //                 It's a closing tag
                if DataSignatures.matchesAsciiTag(at: pos + 1, in: body, asciiToCompare: InterestingPrefix.script, lookAheadWindow: 8) {
                    closingScriptPositions.append(pos - 1)
                } else if !headEndFound && closingHeadPos == nil && DataSignatures.matchesAsciiTag(at: pos + 1, in: body, asciiToCompare: InterestingPrefix.head, lookAheadWindow: 8) {
                    headEndFound = true
                    closingHeadPos = pos - 1
                } else if !bodyEndFound && closingBodyPos == nil && DataSignatures.matchesAsciiTag(at: pos + 1, in: body, asciiToCompare: InterestingPrefix.body, lookAheadWindow: 8) {
                    bodyEndFound = true
                    closingBodyPos = pos -  1
                }
            } else {
                // It's an opening tag
                if !headFound && DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: InterestingPrefix.head, lookAheadWindow: 8) {
                    headerPos = pos
                    headFound = true
                } else if !bodyFound && DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: InterestingPrefix.body, lookAheadWindow: 8) {
                    bodyPos = pos
                    bodyFound = true
                } else {
                    if DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: InterestingPrefix.script, lookAheadWindow: 8) {
                        scriptCandidates[i].flag = true
                    } else {
                        scriptCandidates[i].flag = false
                    }
                }
            }
        }
    }
    
    // TODO: Double check if this is not a duplicate
    static func scanSlice(_ body: Data, in range: Range<Int>, for pattern: [UInt8]) -> Bool {
        return body[range].containsBytes(of: pattern)
        
    }
    
    static func classifyContext(
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
    
    static func scanScriptSrc(in body: Data, scripts: inout [ScriptScanTarget], lookAhead: Int = 16, respectTagEnd: Bool = true) {
        for i in 0..<scripts.count {
            let start = scripts[i].start
            
            // Scan for "=" from start up to tagEnd if available, else up to start+lookAhead
            let earlyRange: Range<Int>
            if respectTagEnd, let tagEnd = scripts[i].end {
                earlyRange = start..<min(tagEnd + 1, body.count)
            } else {
#if DEBUG
                print("THIS SHOULD NOT HAPPEN ALALALALALALAALALALALALALALLAALLALALALAALLALALALALALA THIS IS IN SCANSCRIPT AFTER THE ENDTAG LOOKING FOR THE RANGE OF THE SRC")
#endif
                earlyRange = start..<min(start + lookAhead, body.count)
            }
            let eqSigns = DataSignatures.extractAllTagMarkers(in: body, within: earlyRange, tag: UInt8(ascii: "="))
            var foundSrc = false
            
            for eq in eqSigns {
                // look src attribute
                if let srcPos = matchAttribute(body, at: eq, key: "src", expectedValue: "", endTag: scripts[i].endTagPos) {
                    scripts[i].srcPos = srcPos
                    foundSrc = true
                    // If it's src or type=module, let's not waste CPU pretending it might secretly be both ????
                    // schrodinger attribute parsing is canceled. you're welcome.
                    // 2 ~ 5 ms diff....... !!!!! !fjr;eifhejrkb
                    continue
                }
//                #if DEBUG
//                let debugStart = eq
//                let debugEnd = min(eq + 8, body.count)
//                let debugRange = debugStart..<debugEnd
//                let debugString = String(data: body[debugRange], encoding: .utf8) ?? "<non-utf8>"
//                print("ICI MEME: \(debugString)")
//                #endif
                
                if let typePos = matchAttribute(body, at: eq, key: "type", expectedValue: "", endTag: scripts[i].endTagPos) {
                    scripts[i].typePos = typePos
                    continue
                }
            }
            if !foundSrc {
                scripts[i].findings = .inlineJS
            }
        }
    }
    
    /// Checks if a given "=" position in body corresponds to an attribute with a specific key and value (case-insensitive).
    /// If expectedValue is "", will only match the key.
    static func matchAttribute(_ body: Data, at eq: Int, key: String, expectedValue: String, endTag: Int? = nil) -> Int? {
        let keyBytes = Array(key.lowercased().utf8)
        let valueBytes = Array(expectedValue.lowercased().utf8)

        // Usual guard to not segfault
        guard eq >= keyBytes.count else { return nil }

        for i in 0..<keyBytes.count {
            let bodyChar = body[eq - keyBytes.count + i] | 0x20
            if bodyChar != keyBytes[i] {
                return nil
            }
        }

        if expectedValue.isEmpty {
            // Bypass when key match not required
            return eq - keyBytes.count
        }

        // Look forward for the value after the =
        let tagBoundary = endTag ?? (body[eq...].firstIndex(of: UInt8(ascii: ">")) ?? min(eq + 64, body.count))
        let forwardRange = eq..<min(tagBoundary, body.count)
        let slice = body[forwardRange]

        // Find quotes
        let quoteCandidates = DataSignatures.extractAllTagMarkers(in: body, within: forwardRange, tag: UInt8(ascii: "\"")) +
        DataSignatures.extractAllTagMarkers(in: body, within: forwardRange, tag: UInt8(ascii: "'"))

        let quotePositions = quoteCandidates.sorted()

        guard quotePositions.count >= 2 else { return nil }

        let start = quotePositions[0] + 1
        let end = quotePositions[1]

        guard start < end, end - start <= slice.count else { return nil }

        let valueSlice = body[start..<end].map { $0 | 0x20 }
        if Array(valueSlice) == valueBytes {
            return eq - keyBytes.count
        }
        return nil
    }
    
    // kick the data app
    static func filterOutDataScripts(_ scripts: inout [ScriptScanTarget]) {
        scripts.removeAll { $0.findings == .dataScript }
    }
    
    //    babylon js bs
    static func containsApplicationDataType(in body: Data, eq: Int) -> Bool {
        var typeCheck = [UInt8]()
        var offset = eq - 1
        
        while offset >= 0 && typeCheck.count < 4 {
            let char = body[offset]
            if char != UInt8(ascii: " ") && char != UInt8(ascii: "\t") && char != UInt8(ascii: "\n") {
                typeCheck.append(char | 0x20) // Lowercase
            }
            offset -= 1
        }
        
        if typeCheck.reversed() == [UInt8(ascii: "t"), UInt8(ascii: "y"), UInt8(ascii: "p"), UInt8(ascii: "e")] {
            // After '=', look forward for known safe application/* data types
            let typeStart = eq + 1
            let lookahead = min(typeStart + 64, body.count)
            let typeSlice = body[typeStart..<lookahead]
            
            let safeDataTypes = [
                "application/json",
                "application/ld+json"
            ]
            
            for safeType in safeDataTypes {
                if typeSlice.range(of: Data(safeType.utf8)) != nil {
                    return true
                }
            }
        }
        return false
    }
    
    static func findNonceScript(in body: Data, scripts: inout [ScriptScanTarget], lookAhead: Int = 64, respectTagEnd: Bool = true) -> Void {
        for i in 0..<scripts.count {
            //TODO:  data uri is sometimes a nonce even thought it is useless ????? -> wat to do
            guard scripts[i].findings == .inlineJS || scripts[i].origin == .dataURI else { continue }
            guard let tagEnd = scripts[i].end else { continue }
            
            let start = scripts[i].start
            let scanRange: Range<Int>
            if respectTagEnd {
                scanRange = start..<min(tagEnd, body.count)
            } else {
                scanRange = start..<min(start + lookAhead, body.count)
            }
            
            let eqSigns = DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "="))
            
            for eq in eqSigns {
                if eq < 5 { continue }
                
                // Use matchAttribute helper to check for "nonce" attribute (case-insensitive)
                if matchAttribute(body, at: eq, key: "nonce", expectedValue: "", endTag: tagEnd) != nil {
                    scripts[i].noncePos = eq
                    
                    // Look for surrounding quote marks
                    let quoteCandidates = DataSignatures.extractAllTagMarkers(in: body, within: eq..<scanRange.upperBound, tag: UInt8(ascii: "\"")) +
                    DataSignatures.extractAllTagMarkers(in: body, within: eq..<scanRange.upperBound, tag: UInt8(ascii: "'"))
                    
                    let sortedQuotes = quoteCandidates.sorted()
                    guard sortedQuotes.count >= 2 else { continue }
                    
                    let qStart = sortedQuotes[0]
                    let qEnd = sortedQuotes[1]
                    guard qEnd > qStart + 1 else { continue }
                    
                    let valueRange = (qStart + 1)..<qEnd
                    let nonceValue = body[valueRange]
                    if let decoded = String(data: nonceValue, encoding: .utf8) {
                        scripts[i].nonceValue = decoded
                    }
                    break // Found one nonce, no need to keep scanning this script
                }
            }
        }
    }
    
    // Maybe merge both function into one?
    static func findIntegrityScript(in body: Data, scripts: inout [ScriptScanTarget], lookAhead: Int = 64, respectTagEnd: Bool = true) {
        for i in 0..<scripts.count {
            
            guard let tagEnd = scripts[i].end else { continue }
            guard scripts[i].origin == .httpsExternal ||
                    scripts[i].origin == .protocolRelative ||
                    scripts[i].origin == .relative else { continue }
            
            let start = scripts[i].start
            let scanRange: Range<Int>
            if respectTagEnd {
                scanRange = start..<min(tagEnd, body.count)
            } else {
                scanRange = start..<min(start + lookAhead, body.count)
            }
            
            let eqSigns = DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "="))
            
            for eq in eqSigns {
                if eq < 9 { continue }
                
                // Check for "integrity" (case-insensitive)
                let chars = (0..<9).map { body[eq - 9 + $0] | 0x20 }
                if chars == Array("integrity".utf8.map { $0 | 0x20 }) {
                    scripts[i].integrityPos = eq
                    
                    // Extract quote-wrapped value
                    let quoteCandidates = DataSignatures.extractAllTagMarkers(in: body, within: eq..<scanRange.upperBound, tag: UInt8(ascii: "\"")) +
                    DataSignatures.extractAllTagMarkers(in: body, within: eq..<scanRange.upperBound, tag: UInt8(ascii: "'"))
                    
                    let sortedQuotes = quoteCandidates.sorted()
                    guard sortedQuotes.count >= 2 else { continue }
                    
                    let qStart = sortedQuotes[0]
                    let qEnd = sortedQuotes[1]
                    guard qEnd > qStart + 1 else { continue }
                    
                    let valueRange = (qStart + 1)..<qEnd
                    let integrityValue = body[valueRange]
                    if let decoded = String(data: integrityValue, encoding: .utf8) {
                        scripts[i].integrityValue = decoded
                    }
                    break
                }
            }
        }
    }
    
    static func lookForScriptTagEnd(in body: Data, confirmedScripts: inout [ScriptScanTarget], asciiToCompare: UInt8, lookAhead: Int = 64) {
        for i in 0..<confirmedScripts.count {
            let start = confirmedScripts[i].start
            let searchRange = start..<min(start + lookAhead, body.count)
            let entagPos = DataSignatures.extractAllTagMarkers(in: body, within: searchRange, tag: asciiToCompare)
            
            if let first = entagPos.first {
                // Check if the tag is self-closing (i.e. ends with "/>")
                if first > confirmedScripts[i].start {
                    let preEndByte = body[first - 1]
                    if preEndByte == UInt8(ascii: "/") {
                        confirmedScripts[i].isSelfClosing = true
                    }
                }
                confirmedScripts[i].end = first
            } else {
                confirmedScripts[i].findings = .suspectedObfuscation
            }
        }
    }
    
    static func assignScriptSrcOrigin(in body: Data, scripts: inout [ScriptScanTarget]) {
        for i in 0..<scripts.count {
            if scripts[i].findings == .inlineJS {
                scripts[i].origin = .inline
                continue
            }
            
            guard let srcPos = scripts[i].srcPos, let tagEnd = scripts[i].end else { continue }
            let (origin, extracted) = classifyScriptSrc(in: body, from: srcPos, upTo: tagEnd)
            scripts[i].origin = origin
            scripts[i].extractedSrc = extracted
        }
    }
    
    static func classifyScriptSrc(in body: Data, from srcPos: Int, upTo tagEnd: Int) -> (ScriptOrigin, String?) {
        let scanLimit = min(tagEnd, body.count)
        let scanRange = srcPos..<scanLimit
        
        let quoteCandidates = DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "\"")) +
        DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "'"))
        
        let sortedQuotes = quoteCandidates.sorted()
        guard sortedQuotes.count >= 2 else {
            return (.malformed, nil)
        }
        
        let qStart = sortedQuotes[0]
        let qEnd = sortedQuotes[1]
        guard qEnd > qStart + 1 else {
            return (.malformed, nil)
        }
        
        let valueRange = (qStart + 1)..<qEnd
        let value = body[valueRange]
        
        //        we are in the quotes after a src, so this is meaningless for Swift
        var lowercased = Data(value)
        for i in 0..<lowercased.count {
            let b = lowercased[i]
            if b >= 65 && b <= 90 { // ASCII 'A' to 'Z'
                lowercased[i] = b | 0x20
            }
        }
        
        // Inverted and explicit logic tree for script src classification
        if lowercased.starts(with: Array("http://".utf8)) {
            return (.httpExternal, String(data: value, encoding: .utf8))
            
        } else if lowercased.starts(with: Array("https://".utf8)) {
            return (.httpsExternal, String(data: value, encoding: .utf8))
            
            
            // TODO: Protocol-relative script detected.
            // These should be verified for integrity (SRI). Without it, they are risky due to ambiguous protocol handling.
            // Async SRI hash validation should be scheduled if SRI is present.
        } else if lowercased.starts(with: [UInt8(ascii: "/"), UInt8(ascii: "/")]) {
            return (.protocolRelative, String(data: value, encoding: .utf8))
            
        } else if lowercased.starts(with: Array("data:".utf8)) {
            return (.dataURI, String(data: value, encoding: .utf8))
            
        } else if looksLikeRelativePath(quoteRange: lowercased) {
            return (.relative, String(data: value, encoding: .utf8))
            
        } else {
            return (.unknown, String(data: value, encoding: .utf8))
        }
    }
    
    private static func looksLikeRelativePath(quoteRange: Data) -> Bool {
        guard !quoteRange.isEmpty else {
            return false
        }
        
        var foundNonSpecialChar = false
        var index = 0
        
        while index < quoteRange.count {
            let byte = quoteRange[index]
            // Alpha num + all the funky char that may prefix a path.
            if byte.isAlnum || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "@") || byte == UInt8(ascii: "~") || byte == UInt8(ascii: "+") {
                foundNonSpecialChar = true
                index += 1
            } else if byte == UInt8(ascii: "/") {
                index += 1
            } else {
                break
            }
        }
        
        if foundNonSpecialChar {
            // Strip query or fragment if present
            let pathOnly: Data
            if let queryIndex = quoteRange.firstIndex(of: UInt8(ascii: "?")) ?? quoteRange.firstIndex(of: UInt8(ascii: "#")) {
                pathOnly = quoteRange.prefix(upTo: queryIndex)
            } else {
                pathOnly = quoteRange
            }
            
            // Case 1: Conventional JS file extensions
            if pathOnly.suffix(3) == Array(".js".utf8) || pathOnly.suffix(4) == Array(".mjs".utf8) {
                return true
            }
            
            // Case 2: No extension, but ends with path or endpoint and contains query
            //TODO: Mark this, this is bad, no fingerprinting name, the content can be dynamic depending on user, and we are in a "non' logged state. It evades CSP if CSP is not strict? Need to dig, this is bad
            let hasQuery = quoteRange.contains(UInt8(ascii: "?"))
            let noExtension = !pathOnly.contains(UInt8(ascii: ".")) && hasQuery
            if noExtension {
                return true
            }
        }
        
        return false
    }
    
    
    public static func findCrossOriginModuleValue(in body: Data, scripts: inout [ScriptScanTarget]) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []

        for i in 0..<scripts.count {
            guard scripts[i].isModule, let tagEnd = scripts[i].end else { continue }

            let scanRange = scripts[i].start..<min(tagEnd, body.count)
            let attributeSlice = body[scanRange]

            let attributes = attributeSlice.split(separator: UInt8(ascii: " "))

            for attr in attributes {
//                fkcnin cRoSoRiGin
                var lowered = safeAsciiLowercase(Array(attr))
                lowered = safeAsciiLowercase(lowered)
                if lowered.starts(with: Array("crossorigin".utf8)) {
                    if lowered.count == 10 {
                        // `crossorigin` present without value
                        scripts[i].crossOriginValue = ""
                        break
                    } else if lowered.count > 11, lowered[10] == UInt8(ascii: "=") {
                        let rawValue = lowered.dropFirst(11).map { Character(UnicodeScalar($0)) }
                        let value = String(rawValue).trimmingCharacters(in: .init(charactersIn: "\"' ")).lowercased()

                        if value == "anonymous" || value == "use-credentials" {
                            scripts[i].crossOriginValue = value
                        } else {
                            warnings.append(SecurityWarning(
                                message: "Script module has unrecognized crossorigin value: '\(value)'",
                                severity: .suspicious,
                                penalty: PenaltySystem.Penalty.moduleCrossoriginUnknownValue,
                                url: scripts[i].extractedSrc ?? "unknown",
                                source: .body
                            ))
                        }
                        break
                    } else {
                        warnings.append(SecurityWarning(
                            message: "Malformed crossorigin attribute (no `=` or invalid format).",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.moduleCrossoriginMalformed,
                            url: scripts[i].extractedSrc ?? "unknown",
                            source: .body
                        ))
                    }
                }
            }
        }

        return warnings
    }
    
    static public func scanScriptType(in body: Data, scripts: inout [ScriptScanTarget]) {
        for i in 0..<scripts.count {
            guard let typeEq = scripts[i].typePos,
                  let tagEnd = scripts[i].end else { continue }

            // Scan for quotes after '='
            let scanRange = typeEq..<min(tagEnd, body.count)
            let quotes = DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "\"")) +
                         DataSignatures.extractAllTagMarkers(in: body, within: scanRange, tag: UInt8(ascii: "'"))

            let sorted = quotes.sorted()
            guard sorted.count >= 2 else { continue }

            let valueRange = (sorted[0] + 1)..<sorted[1]
            let typeValue = body[valueRange]
            let lowered = safeAsciiLowercase(Array(typeValue))

            if lowered == InterestingPrefix.moduleKeyword {
                scripts[i].isModule = true
            } else if lowered == InterestingPrefix.jsonKeyword || lowered == InterestingPrefix.ldJsonKeyword {
                scripts[i].findings = .dataScript
                scripts[i].origin = .dataScript
            }
        }
    }
    
    //Much needed a bit late after 3 month
    static public func safeAsciiLowercase(_ input: [UInt8]) -> [UInt8] {
        let asciiRange: ClosedRange<UInt8> = 0x41...0x5A
        return input.map { asciiRange.contains($0) ? ($0 | 0x20) : $0 }
    }
}
