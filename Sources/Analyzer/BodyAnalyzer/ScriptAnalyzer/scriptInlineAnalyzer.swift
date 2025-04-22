import Foundation



////TODO d.innerHTML = "window.__CF$cv$params={ -> detet fake cloudfare challenge injectedin inline js
struct ScriptInlineAnalyzer {
    
    static func analyze(scripts: [ScriptScanTarget], body: Data, origin: String, into warnings: inout [SecurityWarning]) {
        let start = Date()
        var hotDogWaterJSSoup: String?
        var setterDetected = false
        //        join all inline to a js soup
        hotDogWaterJSSoup = generateInlineSoup(from: scripts, in: body)
        //        print("soup is :", hotDogWaterJSSoup!.count)
        // fin all possible funtion call by locating the ( find all js accessor looking for .
        guard let soup = hotDogWaterJSSoup else { return }
        let soupData = Data(soup.utf8)
        let parenPositions = DataSignatures.extractAllTagMarkers(in: soupData, within: 0..<soupData.count, tag: UInt8(ascii: "("))
        let dotPositions = DataSignatures.extractAllTagMarkers(in: soupData, within: 0..<soupData.count, tag: UInt8(ascii: "."))
        
        // pre filter by looking at the ( position -1 is its a letter of the bad js function
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
        //        print("\(suspiciousCalls.count) Suspicious JS calls found from \(parenPositions.count) ")
        //        print("\(suspiciousAncestors.count) Suspicious JS accessors calls found from \(dotPositions.count) ")
        
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
        
        let start1 = Date()
        matchConfirmedBadJSCalls(in: soupData, positions: suspiciousCalls2, origin: origin, into: &warnings, setterDetected: &setterDetected)
        matchConfirmedJsAccessors(in: soupData, position: suspiciousAncestors3, origin: origin, into: &warnings, setterDetected: setterDetected)
        
        
        let timing = Date().timeIntervalSince(start1)
        let duration = Date().timeIntervalSince(start)
        print("gather the data took: ", duration, "filtering took: ", timing)
    }
    
    private static func generateInlineSoup(from scripts: [ScriptScanTarget], in body: Data) -> String {
        let inlineChunks = scripts.compactMap { script -> String? in
            guard script.findings == .inlineJS,
                  let start = script.end,
                  let end = script.endTagPos,
                  let jsContent = String(data: body[start..<end], encoding: .utf8)
            else { return nil }
            return jsContent
        }
        return inlineChunks.joined(separator: "\n")
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
    
    private static func matchConfirmedBadJSCalls(in soupData: Data, positions: [Int], origin: String, into warnings: inout [SecurityWarning], setterDetected: inout Bool) {
        let knownPatterns: [(name: String, bytes: [UInt8])] = BadJSFunctions.suspiciousJsFunction.map {
            ($0, Array($0.utf8))
        }
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
                    if ["eval", "atob", "setItem", "btoa"].contains(name) {
                        setterDetected = true
                    }
                    if name == "getElementById" {
                        let submit = DataSignatures.matchesAsciiTag(at: pos, in: soupData, asciiToCompare: BadJSFunctions.submit, lookAheadWindow: 32)
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
                }
            }
        }
        
        for (name, count) in matchCounts {
            let (penalty, severity) = PenaltySystem.getPenaltyAndSeverity(name: name)
            warnings.append(SecurityWarning(
                message: "Suspicious JS function: \(name)(...) detected inline \(count) time(s).",
                severity: severity,
                penalty: penalty,
                url: origin,
                source: .body
            ))
        }
    }
    
    private static func matchConfirmedJsAccessors(in soupData: Data, position: [Int], origin: String, into warnings: inout [SecurityWarning], setterDetected: Bool) {
        var matchCounts: [String: Int] = [:]
        var setcookie = false
        var readcookie = false
        
        for pos in position {
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
//                        print("🍪 Detected document.cookie context:\n\(preview)\n")
//                    }

                    if name == "cookie" && isAssignment && !setcookie {
                        setcookie = true
                        warnings.append(SecurityWarning(
                            message: "JavaScript is modifying a cookie using `document.cookie = ...`",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.jsSetEditCookie,
                            url: origin,
                            source: .body,
                            bitFlags: WarningFlags.BODY_JS_SET_EDIT_COOKIE
                        ))
                        // TODO: Extract full JS block `{}` surrounding this write for context display in body view.
                        // This could help users understand the surrounding logic — e.g., fingerprinting, reload, cookie clearing.
                    } else if name == "cookie" && !readcookie {
                        readcookie = true
                        warnings.append(SecurityWarning(
                            message: "JavaScript is reading cookies via `document.cookie`. May be used for user tracking.",
                            severity: .tracking,
                            penalty: 0,
                            url: origin,
                            source: .body,
                            bitFlags: WarningFlags.BODY_JS_READ_COOKIE
                        ))
                    }

                    let displayName = (name == "cookie") ? "document.cookie" : name
                    matchCounts[displayName, default: 0] += 1
                }
            }
        }
        
        for (displayName, count) in matchCounts {
            let baseName = displayName.replacingOccurrences(of: "document.", with: "")
            let (penalty, severity): (Int, SecurityWarning.SeverityLevel) = {
                switch baseName {
                case "cookie":
                    return (PenaltySystem.Penalty.jsCookieAccess, .dangerous)
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
