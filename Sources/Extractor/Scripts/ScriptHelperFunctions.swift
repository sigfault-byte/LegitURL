//
//  HelperFunctions.swift
//  URLChecker
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation

struct ScriptHelperFunction {
    static func pairScriptsWithClosings(scripts: inout [ScriptScanTarget], closingTags: [Int], body: Data) {
        guard scripts.count == closingTags.count else {
            //TODO:            this is  redundnat there s a guard before the function call
            print("Cannot zip scripts with closings count mismatch.")
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
        
        
        for i in 0..<scriptCandidates.count {
            let pos = scriptCandidates[i].start
            guard pos + 1 < body.count else { continue }
            
            if body[pos + 1] == UInt8(ascii: "/") {
                //                 It's a closing tag
                if DataSignatures.matchesAsciiTag(at: pos + 1, in: body, asciiToCompare: interestingPrefix.script, lookAheadWindow: 8) {
                    closingScriptPositions.append(pos - 1)
                } else if closingHeadPos == nil && DataSignatures.matchesAsciiTag(at: pos + 1, in: body, asciiToCompare: interestingPrefix.head, lookAheadWindow: 8) {
                    closingHeadPos = pos - 1
                } else if closingBodyPos == nil && DataSignatures.matchesAsciiTag(at: pos + 1, in: body, asciiToCompare: interestingPrefix.body, lookAheadWindow: 8) {
                    closingBodyPos = pos -  1
                }
            } else {
                // It's an opening tag
                if !headFound && DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: interestingPrefix.head, lookAheadWindow: 8) {
                    headerPos = pos
                    headFound = true
                } else if !bodyFound && DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: interestingPrefix.body, lookAheadWindow: 8) {
                    bodyPos = pos
                    bodyFound = true
                } else {
                    if DataSignatures.matchesAsciiTag(at: pos, in: body, asciiToCompare: interestingPrefix.script, lookAheadWindow: 8) {
                        scriptCandidates[i].flag = true
                    } else {
                        scriptCandidates[i].flag = false
                    }
                }
            }
        }
    }
    
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
                print("THIS SHOULD NOT HAPPEN ALALALALALALAALALALALALALALLAALLALALALAALLALALALALALA THIS IS IN SCANSCRIPT AFTER THE ENDTAG LOOKING FOR THE RANGE OF THE SRC")
                earlyRange = start..<min(start + lookAhead, body.count)
            }
            let eqSigns = DataSignatures.extractAllTagMarkers(in: body, within: earlyRange, tag: UInt8(ascii: "="))
            var foundSrc = false
            var eqMatchedDataScript = false

            for eq in eqSigns {
                if eq >= 3 {
                    // look backward for "src"
                    let s = body[eq - 3] | 0x20
                    let r = body[eq - 2] | 0x20
                    let c = body[eq - 1] | 0x20
                    if s == UInt8(ascii: "s"), r == UInt8(ascii: "r"), c == UInt8(ascii: "c") {
                        let scanRange: Range<Int>
                        if respectTagEnd, let tagEnd = scripts[i].end {
                            scanRange = start..<min(tagEnd + 1, body.count)
                        } else {
                            scanRange = start..<min(start + lookAhead, body.count)
                        }
                        let (found, position) = body.containsBytesCaseInsensitive(of: interestingPrefix.src, startIndex: scanRange.lowerBound)
                        if found, let pos = position, pos > start, pos < scanRange.upperBound {
                            scripts[i].srcPos = pos
                            foundSrc = true
                            break
                        }
                    }
                }
            }
            //TODO:  There is something i do not understand or lacking knowledge regarding data type
            if !foundSrc {
                for eq in eqSigns {
                    if ScriptHelperFunction.containsApplicationDataType(in: body, eq: eq) {
                        scripts[i].findings = .dataScript
                        eqMatchedDataScript = true
                        break
                    }
                }
                if !eqMatchedDataScript {
                    scripts[i].findings = .inlineJS
                }
            }
        }
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
// data uri can also be anonce
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
                
                // Check for "nonce" (case-insensitive) before "="
                let n0 = body[eq - 5] | 0x20
                let n1 = body[eq - 4] | 0x20
                let n2 = body[eq - 3] | 0x20
                let n3 = body[eq - 2] | 0x20
                let n4 = body[eq - 1] | 0x20
                
                if n0 == UInt8(ascii: "n"),
                   n1 == UInt8(ascii: "o"),
                   n2 == UInt8(ascii: "n"),
                   n3 == UInt8(ascii: "c"),
                   n4 == UInt8(ascii: "e") {
                    
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
}
