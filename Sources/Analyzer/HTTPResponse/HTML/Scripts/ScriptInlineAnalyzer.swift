//  ScriptInlineAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on ??/04/2025.
//
//TODO: Refactor the whole loop especially the findings / findings for UI logic, separate the functions, stop using let every 3 lines. Soup should be a struct, and carries the range of the script, to easily attached the findings
// TODO: If script contains document.write and scriptIs80Percent → escalate to critical
// TODO: Track setItem() behavior across redirect hops → score as tracking
// TODO: Extract URL from window.open(...) → check domain reputation and target TLD

import Foundation

//TODO: d.innerHTML = "window.__CF$cv$params={ ->  fake cloudfare challenge injectedin inline js
struct ScriptInlineAnalyzer {
    
    static func analyze(scripts: inout ScriptExtractionResult, body: Data, origin: String, into warnings: inout [SecurityWarning], jsHTMLRatio: Int) {
        //        let start = Date()
        var setterDetected = false
        //        Debug
        //        Too early !
        //        let isNonce = scripts.scripts.contains(where: { $0.nonceValue != nil })
        //        if isNonce {
        //            for i in scripts.scripts.indices {
        //                if scripts.scripts[i].origin == .inline && scripts.scripts[i].nonceValue == nil {
        //                    scripts.scripts[i].findings4UI = (scripts.scripts[i].findings4UI ?? []) + [("Inline Script Missing nonce Value", .info)]
        //                }
        //            }
        //        }
        
        // Build one contiguous Data buffer that contains every inline script.
        let (soupData, byteRangesByScript) = generateInlineSoup(from: scripts.scripts, in: body)
        guard !soupData.isEmpty else { return }
        
        // Locate suspicious byte patterns
        let parenPositions = DataSignatures.extractAllTagMarkers(in: soupData, within: 0..<soupData.count, tag: UInt8(ascii: "("))
        let dotPositions = DataSignatures.extractAllTagMarkers(in: soupData, within: 0..<soupData.count, tag: UInt8(ascii: "."))
        
        // pre filter by looking at the ( position -1 it's the letter of possible bad js function
        // TODO: Optimize by analyzing leading bytes before `(` to narrow down which keywords can still be matched
        let suspiciousCalls = filterSuspiciousJSCalls(
            in: soupData,
            parenPositions: parenPositions,
            offset: -1,
            suspiciousBytes: BadJSFunctions.suspiciousLastBytes
        )
        let suspiciousAncestors = filterSuspiciousAncestor(
            in: soupData,
            dotPositions: dotPositions,
            offset: 1,
            suspiciousBytes: SuspiciousJSAccessors.accessorsFirstBytes
        )
        // second pass with pos -2 on the second letter of bad js function
        //        Debug
        //        print("\(suspiciousCalls.count)  JS calls found from \(parenPositions.count) ")
        //        print("\(suspiciousAncestors.count) JS accessors calls found from \(dotPositions.count) ")
        
        let suspiciousCalls2 = filterSuspiciousJSCalls(
            in: soupData,
            parenPositions: suspiciousCalls,
            offset: -2,
            suspiciousBytes: BadJSFunctions.suspiciousSecondLastBytes
        )
        let suspiciousAncestors2 = filterSuspiciousAncestor(
            in: soupData,
            dotPositions: suspiciousAncestors,
            offset: 2,
            suspiciousBytes: SuspiciousJSAccessors.accessorsSecondBytes
        )
        //        third pass because lots of .co .lo .se
        let suspiciousAncestors3 = filterSuspiciousAncestor(
            in: soupData,
            dotPositions: suspiciousAncestors2,
            offset: 3,
            suspiciousBytes: SuspiciousJSAccessors.accessorsThirdBytes
        )
        
        //        let start1 = Date()
        matchConfirmedBadJSCalls(in: soupData,
                                 positions: suspiciousCalls2,
                                 origin: origin,
                                 into: &warnings,
                                 setterDetected: &setterDetected,
                                 scripts: &scripts,
                                 byteRangesByScript: byteRangesByScript,
                                 jsHTMLRatio: jsHTMLRatio)
        
        matchConfirmedJsAccessors(in: soupData,
                                  position: suspiciousAncestors3,
                                  origin: origin,
                                  into: &warnings,
                                  setterDetected: setterDetected,
                                  scripts: &scripts,
                                  byteRangesByScript: byteRangesByScript)
        
        checkInlineScriptSize(scripts: &scripts, into: &warnings, origin: origin)
        
        
        
        //        let timing = Date().timeIntervalSince(start1)
        //        let duration = Date().timeIntervalSince(start)
        //        print("gather the data took: ", duration, "filtering took: ", timing)
    }
    
    private static func checkInlineScriptSize(scripts: inout ScriptExtractionResult, into: inout [SecurityWarning], origin: String) {
        var countOverThreshold = 0
        for (index, script) in scripts.scripts.enumerated() {
            guard script.origin == .inline else { continue }
            let start = script.start
            let end = script.endTagPos ?? 0
            if end != 0 {
                let size = end - start
                if size >= 100_000 {
                    countOverThreshold += 1
                    let current = scripts.scripts[index].findings4UI ?? []
                    scripts.scripts[index].findings4UI = current + [("Inline script exceeds 100kB", .suspicious, 0)]
                }
            }
        }

        if countOverThreshold > 0 {
            into.append(SecurityWarning(
                message: "\(countOverThreshold) inline script(s) exceed 100kB, which is unusually large.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.inlineMore100kB * countOverThreshold,
                url: origin,
                source: .body
            ))
        }
    }
    
    
    /// Concatenates all inline `<script>` blocks into a single `Data` buffer, separated by '\n'.
    /// Also returns the byte ranges of each inline block *within that buffer* for later mapping.
    private static func generateInlineSoup(from scripts: [ScriptScanTarget],
                                           in body: Data) -> (soup: Data, ranges: [(range: Range<Int>, scriptIndex: Int)]) {
        var ranges: [(range: Range<Int>, scriptIndex: Int)] = []
        var soup = Data()
        var currentStart = 0
        
        for (index, script) in scripts.enumerated() {
            guard script.origin == .inline,
                  let start = script.end,
                  let end = script.endTagPos,
                  start < end, end <= body.count else { continue }
            
            let slice = body[start..<end]
            soup.append(slice)
            soup.append(contentsOf: [0x0A])          // newline separator
            
            let length = slice.count + 1
            let range = currentStart ..< (currentStart + length)
            ranges.append((range, index))
            currentStart += length
        }
        
        return (soup, ranges)
    }
    
    static func filterSuspiciousJSCalls(in soupData: Data, parenPositions: [Int], offset: Int = -1, suspiciousBytes: Set<UInt8>) -> [Int] {
        var matches = [Int]()
        for pos in parenPositions {
            let checkPos = pos + offset
            guard checkPos >= 0 && checkPos < soupData.count else { continue }
            let byte = soupData[checkPos] | 0x20
            if suspiciousBytes.contains(byte) {
                matches.append(pos)
            }
        }
        return matches
    }
    
    static func filterSuspiciousAncestor( in soupData: Data, dotPositions: [Int], offset: Int = 1,suspiciousBytes: Set<UInt8>) -> [Int] {
        var matches = [Int]()
        for pos in dotPositions {
            let checkPos = pos + offset
            guard checkPos <= soupData.count else { continue }
            let byte = soupData[checkPos] | 0x20
            if suspiciousBytes.contains(byte) {
                matches.append(pos)
            }
        }
        return matches
    }
    
    private static func matchConfirmedBadJSCalls(in soupData: Data,
                                                 positions: [Int],
                                                 origin: String,
                                                 into warnings: inout [SecurityWarning],
                                                 setterDetected: inout Bool,
                                                 scripts: inout ScriptExtractionResult,
                                                 byteRangesByScript: [(range: Range<Int>, scriptIndex: Int)],
                                                 jsHTMLRatio: Int) {
        
        let knownPatterns = BadJSFunctions.suspiciousJsFunctionBytes
        var matchCounts: [String: Int] = [:]
        
        for pos in positions {
            for (name, bytes) in knownPatterns {
                let start = pos - bytes.count
                let end = pos
                guard start >= 0, end <= soupData.count else { continue }
                
                let slice = soupData[start..<end]
                if slice.elementsEqual(bytes) {
                    if name == "atob" {
                        let leadStart = max(0, start - 20)
                        let contextSlice = soupData[leadStart..<end]
                        if let contextStr = String(data: contextSlice, encoding: .utf8),
                           contextStr.contains("JSON.parse") {
                            //                            if let match = byteRangesByScript.first(where: { $0.range.contains(pos) }) {
                            //                                let index = match.scriptIndex
                            //                                let scriptRange = match.range
                            //                                let posInScript = pos - scriptRange.lowerBound
                            //                                let current = scripts.scripts[index].findings4UI ?? []
                            //                                scripts.scripts[index].findings4UI = current + [("JSON decoding via atob", .dangerous, posInScript)]
                            //                            }
                            warnings.append(SecurityWarning(
                                message: "Inline JavaScript is decoding a base64 blob with `atob()` directly after `JSON.parse(...)`. This is highly suspicious.",
                                severity: .dangerous,
                                penalty: PenaltySystem.Penalty.atobJSONparserCombo,
                                url: origin,
                                source: .body,
                                bitFlags: WarningFlags.BODY_JS_JSON_ATOB_CHAIN
                            ))
                        }
                    }
                    if ["eval", "atob", "setItem", "btoa", "Function"].contains(name) {
                        setterDetected = true
                    }
                    if name == "getElementById" {
                        let submit = DataSignatures.matchesAsciiTag(at: pos, in: soupData, asciiToCompare: BadJSFunctions.submit, lookAheadWindow: 48)
                        if let match = byteRangesByScript.first(where: { $0.range.contains(pos) }) {
                            let index = match.scriptIndex
                            let scriptRange = match.range
                            let posInScript = pos - scriptRange.lowerBound
                            let current = scripts.scripts[index].findings4UI ?? []
                            scripts.scripts[index].findings4UI = current + [("Auto Submit detected", .critical, posInScript)]
                        }
                        if submit {
                            warnings.append(SecurityWarning(
                                message: "JS function: \(name)(...) detected inline followed by 'submit'.",
                                severity: .critical,
                                penalty: PenaltySystem.Penalty.critical,
                                url: origin,
                                source: .body
                            ))
                        }
                        continue
                    }
                    
                    matchCounts[name, default: 0] += 1
                    let (_, severity) = PenaltySystem.getPenaltyAndSeverity(name: name)
                    if let match = byteRangesByScript.first(where: { $0.range.contains(pos) }) {
                        let index = match.scriptIndex
                        let scriptRange = match.range
                        let posInScript = pos - scriptRange.lowerBound
                        let current = scripts.scripts[index].findings4UI ?? []
                        scripts.scripts[index].findings4UI = current + [("\(name.capitalized) call detected", severity, posInScript)]
                        // TODO: Couldnt test in the wild. Logic of this is if script ratio is above 80% and document.write is presnet -> bail
                        if name == "document.write" {
                            scripts.scripts[index].findings4UI?.append(("DOM manipulation via document.write()", .dangerous, posInScript))
                        }
                    }
                }
            }
        }
        
        for (name, count) in matchCounts {
            
            let (penalty, severity) = PenaltySystem.getPenaltyAndSeverity(name: name)
            if name == "document.write" && jsHTMLRatio > 70 {
                warnings.append(SecurityWarning(
                    message: "High script density inline block using `document.write()` suggests dynamic document manipulation — high risk of cloaked behavior.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: origin,
                    source: .body
                ))
                continue
            }
            warnings.append(SecurityWarning(
                message: "Suspicious JS function: \(name)(...) detected inline \(count) time(s).",
                severity: severity,
                penalty: penalty,
                url: origin,
                source: .body
            ))
        }
    }
    
    private static func matchConfirmedJsAccessors(in soupData: Data,
                                                  position: [Int],
                                                  origin: String,
                                                  into warnings: inout [SecurityWarning],
                                                  setterDetected: Bool,
                                                  scripts: inout ScriptExtractionResult,
                                                  byteRangesByScript: [(range: Range<Int>, scriptIndex: Int)]) {
        // Refactored: setcookie and readcookie are now scoped per-script, not global
        // Wrap the main logic in a loop over scripts
        for (scriptRange, scriptIndex) in byteRangesByScript {
            var matchCounts: [String: Int] = [:]
            var setcookie = false
            var readcookie = false
            // Only consider positions that are within this script's range
            let positionsInScript = position.filter { scriptRange.contains($0) }
            for pos in positionsInScript {
                for (name, bytes) in SuspiciousJSAccessors.all {
                    guard pos + bytes.count <= soupData.count else { continue }
                    let accessorStart = pos + 1
                    let accessorEnd = accessorStart + bytes.count
                    let slice = soupData[accessorStart..<accessorEnd]
                    
                    if slice.elementsEqual(bytes) {
                        let equalSignPos = accessorEnd - 1
                        let isAssignment = DataSignatures.fastScriptByteHint(at: equalSignPos, in: soupData, hint: [byteLetters.equalSign])
                        //Debug
                        //                    if let preview = String(data: soupData[max(0, pos - 40)..<min(soupData.count, pos + 60)], encoding: .utf8) {
                        //                        print(" Detected document.cookie context:\n\(preview)\n")
                        //                    }
                        
                        //                        // Print debugging for document.cookie=
                        //                        if name == "cookie" {
                        //                            let contextStart = max(0, pos - 40)
                        //                            let contextEnd = min(soupData.count, pos + 60)
                        //                            if let contextStr = String(data: soupData[contextStart..<contextEnd], encoding: .utf8) {
                        //                                print("Cookie context near position \(pos):\n\(contextStr)")
                        //                                print("isAssignment:", isAssignment)
                        //                            }
                        //                        }
                        
                        let isSetter = name == "cookie" && isAssignment
                        
                        if name == "cookie" && isAssignment && !setcookie {
                            // Only add finding once per script
                            let current = scripts.scripts[scriptIndex].findings4UI ?? []
                            scripts.scripts[scriptIndex].findings4UI = current + [("Getting / Setting cookies", .suspicious, 0)]
                            //TODO:  If the accessor is followed by '=':
                            //   - If the next non 0x20 byte is a quote (`"` OR `'`) -> setter
                            //   - If the next bytes look like parsing logic (e.g. `.split`, `.match`, regex, or variables) ->  getter
                            //   - ~20–40 bytes ahead from '=' if nothing -> getter
                            //   - May also check for presence of `;` (cookie chunk split) in the forward window ??
                            setcookie = true
                            warnings.append(SecurityWarning(
                                message: "JavaScript is editing or creating a cookie using `document.cookie = ...`. There are very few legitimate reasons to do this. (e.g., fingerprinting, reload, or cookie clearing or to silently track user behavior).",
                                severity: .suspicious,
                                penalty: PenaltySystem.Penalty.jsSetEditCookie,
                                url: origin,
                                source: .body,
                                bitFlags: WarningFlags.BODY_JS_SET_EDIT_COOKIE
                            ))
                            // TODO: Extract full JS block `{}` surrounding this write for context display in body view.
                            // This could help users understand the surrounding logic — e.g., fingerprinting, reload, cookie clearing.
                        } else if name == "cookie" && !isSetter && !readcookie {
                            // Only add finding once per script
                            let current = scripts.scripts[scriptIndex].findings4UI ?? []
                            scripts.scripts[scriptIndex].findings4UI = current + [("Reading cookies", .info, 0)]
                            readcookie = true
                            warnings.append(SecurityWarning(
                                message: "JavaScript is reading cookies via `document.cookie`. May be used for user tracking, or legitimate reasons.",
                                severity: .info,
                                penalty: PenaltySystem.Penalty.informational,
                                url: origin,
                                source: .body,
                                bitFlags: WarningFlags.BODY_JS_READ_COOKIE
                            ))
                        }
                        
                        let displayName: String
                        if name == "cookie" {
                            displayName = isSetter ? "document.cookie=" : "document.cookie"
                        } else {
                            displayName = name
                        }
                        matchCounts[displayName, default: 0] += 1
                        let scriptPos = pos - scriptRange.lowerBound
                        let current = scripts.scripts[scriptIndex].findings4UI ?? []
                        scripts.scripts[scriptIndex].findings4UI = current + [("'\(displayName)'", isSetter ? .suspicious : .info, scriptPos)]
                    }
                }
            }
            for (displayName, count) in matchCounts {
                let baseName = displayName
                //temp hack
                guard baseName != "document.cookie" else { continue }
                let (penalty, severity): (Int, SecurityWarning.SeverityLevel) = {
                    switch baseName {
                        case "document.cookie=":
                            return (PenaltySystem.Penalty.jsCookieAccess, .suspicious)
                        case "localStorage":
                            return (PenaltySystem.Penalty.jsStorageAccess, .suspicious)
                        case "setItem":
                            return (PenaltySystem.Penalty.jsSetItemAccess, .suspicious)
                        case "WebAssembly":
                            return (PenaltySystem.Penalty.jsWebAssembly, .dangerous)
                        default:
                            return (-10, .suspicious)
                    }
                }()
                
                let adjustedSeverity = setterDetected ? SecurityWarning.SeverityLevel.dangerous : severity
                
                var message: String = "Suspicious JS accessor: .\(displayName) detected inline \(count) time(s)."
                if setterDetected {
                    message =  "Suspicious JS setter function with \(displayName) detected inline. Critical signal of obfuscation."
                }
                warnings.append(SecurityWarning(
                    message: message,
                    severity: adjustedSeverity,
                    penalty: /*count * */penalty, // cant multiply, several signal in the same spot doesnt make a bigger signal!
                    url: origin,
                    source: .body
                ))
            }
        }
    }
    
    //    //TODO: TEST function for window.opener
    //    private static func detectOpenerNull(in soup: Data, byteRanges: [(range: Range<Int>, scriptIndex: Int)], into scripts: inout ScriptExtractionResult) -> Bool {
    //        let openerBytes: [UInt8] = Array("opener".utf8)
    //        let nullBytes: [UInt8] = Array("null".utf8)
    //
    //        var found = false
    //
    //        for (range, scriptIndex) in byteRanges {
    //            let data = soup[range]
    //            guard data.count > 12 else { continue }  // too small
    ////            locate all '=' using extractAllTagMarkers
    //            // either loop over or grab 10B aournd each side of it
    //
    //
    //        }
    //            return found
    //        }
}
