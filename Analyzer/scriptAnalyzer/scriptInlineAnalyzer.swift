import Foundation
struct ScriptInlineAnalyzer {
    
    static func analyze(scripts: [ScriptScanTarget], body: Data, origin: String, into warnings: inout [SecurityWarning]) {
        let start = Date()
        var hotDogWaterJSSoup: String?
//        join all inline to a js soup
        hotDogWaterJSSoup = generateInlineSoup(from: scripts, in: body)
//        print("soup is :", hotDogWaterJSSoup!.count)
        // fin all possible funtion call by locating the (
        guard let soup = hotDogWaterJSSoup else { return }
        let soupData = Data(soup.utf8)
        let parenPositions = DataSignatures.extractAllTagMarkers(in: soupData, within: 0..<soupData.count, tag: UInt8(ascii: "("))
        // pre filter by looking at the ( position -1 is its a letter of the bad js function
        // TODO: Optimize by analyzing leading bytes before `(` to narrow down which keywords can still be matched
        let suspiciousCalls = filterSuspiciousJSCalls(
            in: soupData,
            parenPositions: parenPositions,
            offset: -1,
            suspiciousBytes: BadJSFunctions.suspiciousLastBytes
        )
        // second pass with pos -2 on the second letter of bad js function
        print("\(suspiciousCalls.count) Suspicious JS calls found from \(parenPositions.count) ")
        let suspiciousCalls2 = filterSuspiciousJSCalls(
            in: soupData,
            parenPositions: suspiciousCalls,
            offset: -2,
            suspiciousBytes: BadJSFunctions.suspiciousSecondLastBytes
        )
        print("\(suspiciousCalls2.count) Suspicious JS calls found from \(suspiciousCalls.count)")
//        for pos in suspiciousCalls2 {
//            let previewStart = max(pos - 10, 0)
//            let preview = soupData[previewStart..<pos]
//            let context = String(decoding: preview, as: UTF8.self)
//            print("...before `(` at \(pos): \(context)")
//        }
        
        let start1 = Date()
        matchConfirmedBadJSCalls(in: soupData, positions: suspiciousCalls2, origin: origin, into: &warnings)

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

    private static func matchConfirmedBadJSCalls(in soupData: Data, positions: [Int], origin: String, into warnings: inout [SecurityWarning]) {
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
                    break
                }
            }
        }

        for (name, count) in matchCounts {
            warnings.append(SecurityWarning(
                message: "Suspicious JS function: \(name)(...) detected inline \(count)x.",
                severity: .dangerous,
                penalty: count * PenaltySystem.Penalty.badJSCallInline,
                url: origin,
                source: .body
            ))
        }
    }

}
