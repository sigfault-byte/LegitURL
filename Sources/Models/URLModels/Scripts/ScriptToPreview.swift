//
//  ScriptToView.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//

import Foundation

struct ScriptPreview: Identifiable {
    var id: UUID { UUID() }
    let origin: ScriptOrigin?
    let isInline: Bool
    let context: ScriptScanTarget.ScriptContext?
    let contentPreview: String
    let findings: [(message: String, severity: SecurityWarning.SeverityLevel, pos: Int?)]?
    let extractedSrc: String?
    let nonce: String?
    let integrity: String?
    let isModule: Bool?
    let crossOriginValue: String?
    let size: Int
    let focusedSnippets: [String]?
}

struct ScriptToPreview {
    static func prepareScriptPreviews(for scripts: [ScriptScanTarget], body: Data) -> [ScriptPreview] {
        var previews: [ScriptPreview] = []

        // Step 1: Collect the bytes
        var byteSlices: [(index: Int, data: Data, script: ScriptScanTarget, wasTruncated: Bool, size: Int)] = []
        
        for (i, script) in scripts.enumerated() {
            guard let end = script.endTagPos else { continue }
            let start = script.start
            guard end > start else { continue }

            let rawSlice = body[start..<end]
            let scriptSize = rawSlice.count
            let truncated: Data
            let wasTruncated: Bool
            if rawSlice.count > 3072 {
                truncated = rawSlice.prefix(3072)
                wasTruncated = true
            } else {
                //+ 10 to display </script> because endTag is exclusive '<'
                let softCap = min(end + 10, body.count)
                truncated = body[start..<softCap]
                wasTruncated = false
            }

            byteSlices.append((i, truncated, script, wasTruncated, scriptSize))
        }

        // Step 2: Decde the bytes
        let decodedStrings = byteSlices.map { slice -> String in
            String(data: slice.data, encoding: .utf8) ?? "Unable to decode script content."
        }

        // Step 3: create preview
        for (i, decoded) in decodedStrings.enumerated() {
            let script = byteSlices[i].script
            let findings = script.findings4UI?.map { (message, severity, pos) in (message: message, severity: severity, pos) } ?? []

            //Useless with the .size atrr
//            if script.origin == .inline && byteSlices[i].wasTruncated {
//                findings.append((
//                    message: "Truncated preview (3072 bytes)",
//                    severity: .info,
//                    pos: 0
//                ))
//            }
            //MARK: LAST CRASH ON SCRIPT FOR CROSSORIGIN ATTR IN MODULE SCRIPT
            var snippets: [String] = []
            if let findings4UI = script.findings4UI {
                for (_, _, position) in findings4UI {
                    if let pos = position, pos != 0 {
                        let proposedStart = script.start + pos - 200
                        let startIndex = proposedStart >= script.start ? proposedStart : script.start

                        let proposedEnd = script.start + pos + 200
                        let endIndex: Int
                        if let endTagPos = script.endTagPos, proposedEnd > endTagPos {
                            endIndex = endTagPos
                        } else {
                            endIndex = min(proposedEnd, body.count)
                        }

                        guard startIndex < endIndex else { continue }

                        let snippetData = body[startIndex..<endIndex]
                        let snippetString = String(data: snippetData, encoding: .utf8) ?? "⚠️ Unable to decode snippet."
                        snippets.append(snippetString)
                    }
                }
            }

            let preview = ScriptPreview(
                origin: script.adjustedOrigin,
                isInline: script.origin == .inline,
                context: script.context,
                contentPreview: decoded,
                findings: findings,
                extractedSrc: script.extractedSrc,
                nonce: script.nonceValue,
                integrity: script.integrityValue,
                isModule: script.isModule,
                crossOriginValue: script.crossOriginValue,
                size: byteSlices[i].size,
                focusedSnippets: snippets.isEmpty ? nil : snippets
            )
            previews.append(preview)
        }

        return previews
    }
}
