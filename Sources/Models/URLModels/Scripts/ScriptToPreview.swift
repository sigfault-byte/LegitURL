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
    let findings: [(message: String, severity: SecurityWarning.SeverityLevel)]?
}

struct ScriptToPreview {
    static func prepareScriptPreviews(for scripts: [ScriptScanTarget], body: Data) -> [ScriptPreview] {
        var previews: [ScriptPreview] = []

        // Step 1: Collect the bytes
        var byteSlices: [(index: Int, data: Data, script: ScriptScanTarget, wasTruncated: Bool)] = []

        for (i, script) in scripts.enumerated() {
            guard let end = script.endTagPos else { continue }
            let start = script.start
            guard end > start else { continue }
            

            let rawSlice = body[start..<end]
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

            byteSlices.append((i, truncated, script, wasTruncated))
        }

        // Step 2: Decde the bytes
        let decodedStrings = byteSlices.map { slice -> String in
            String(data: slice.data, encoding: .utf8) ?? "⚠️ Unable to decode script content."
        }

        // Step 3: create preview
        for (i, decoded) in decodedStrings.enumerated() {
            let script = byteSlices[i].script
            var findings = script.findings4UI ?? []

            if script.origin == .inline && byteSlices[i].wasTruncated {
                findings.append((
                    message: "Truncated (>3072 bytes)",
                    severity: .info
                ))
            }

            let preview = ScriptPreview(
                origin: script.origin,
                isInline: script.origin == .inline,
                context: script.context,
                contentPreview: decoded,
                findings: findings
            )
            previews.append(preview)
        }

        return previews
    }
}
