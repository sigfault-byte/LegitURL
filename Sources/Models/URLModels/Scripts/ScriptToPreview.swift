//
//  ScriptToView.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//

import Foundation

struct ScriptPreview {
    let origin: ScriptOrigin?
    let isInline: Bool
    let context: ScriptScanTarget.ScriptContext?
    let contentPreview: String
    let findings: [(message: String, severity: SecurityWarning.SeverityLevel)]?
}

struct ScriptToPreview {
    static func prepareScriptPreviews(for scripts: [ScriptScanTarget], body: Data) -> [ScriptPreview] {
        var previews: [ScriptPreview] = []

        // Step 1: Collect the bytes
        var byteSlices: [(index: Int, data: Data, script: ScriptScanTarget)] = []

        for (i, script) in scripts.enumerated() {
            guard let end = script.endTagPos else { continue }
            let start = script.start
            guard end > start else { continue }
            

            let rawSlice = body[start..<end]
            let truncated: Data
            if rawSlice.count > 1024 {
                    truncated = rawSlice.prefix(1024)
            } else {
                truncated = rawSlice
            }

            byteSlices.append((i, truncated, script))
        }

        // Step 2: Decde the bytes
        let decodedStrings = byteSlices.map { slice -> String in
            String(data: slice.data, encoding: .utf8) ?? "⚠️ Unable to decode script content."
        }

        // Step 3: create preview
        for (i, decoded) in decodedStrings.enumerated() {
            let script = byteSlices[i].script
            let preview = ScriptPreview(
                origin: script.origin,
                isInline: script.origin == .inline,
                context: script.context,
                contentPreview: decoded,
                findings: script.findings4UI
            )
            previews.append(preview)
        }

        return previews
    }
}
