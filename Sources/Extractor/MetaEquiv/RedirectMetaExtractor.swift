//
//  RedirectMetaExtractor.swift
//  LegitURL
//
//  Created by Chief Hakka on 19/06/2025.
//
import Foundation

struct RedirectMetaExtractor {

    @inline(__always)
    private static func toLower(_ b: UInt8) -> UInt8 { b | 0x20 }

    /// Returns the first URL found in a `<meta http‑equiv="refresh" ...>` tag located in `range`.
    /// The scan window is capped at 8192 bytes for performance and stops at the first valid match.
    static func extract(from html: Data,
                        tags: [Int],
                        range: Range<Int>,
                        htmlSize: Int) -> String? {

        // -------- Preconditions --------
        precondition(!tags.isEmpty, "RedirectMetaExtractor: 'tags' must list all tag offsets")
        guard htmlSize > 0, !range.isEmpty else { return nil }

        // Cap the scan window to 8 KiB past range.lowerBound
        let upperCap = min(range.upperBound, range.lowerBound + 8_192)
        let scanRange = range.lowerBound ..< upperCap

        // Candidate '<' positions inside the scan window
        let tagCandidates = tags.filter { scanRange.contains($0) }
        guard !tagCandidates.isEmpty else { return nil }

        // -------- Byte‑level scan --------
        return html.withUnsafeBytes { rawBuf -> String? in
            let bytes = rawBuf.bindMemory(to: UInt8.self)
            let hardCap = 512
            
            #if DEBUG
            let startTime = DispatchTime.now()
            #endif
            
            for start in tagCandidates {
               
                // 1. Quick check "<meta"
                guard start + 4 < upperCap else { continue }
                if toLower(bytes[start + 1]) != 0x6d { continue }      // 'm'
                if toLower(bytes[start + 2]) != 0x65 { continue }      // 'e'
                if toLower(bytes[start + 3]) != 0x74 { continue }      // 't'
                if toLower(bytes[start + 4]) != 0x61 { continue }      // 'a'

                // 2. Find the closing '>' into the cap
                
                var end = start + 5
                let limit = min(end + hardCap, upperCap)
                while end < limit && bytes[end] != 0x3e { end += 1 }   // 0x3e == '>'
                guard end < limit, bytes[end] == 0x3e else { continue }
                // 3. Convert that tiny slice to String (≤512 B → cheap)
                let sliceLen = end - start + 1
                let tagData = Data(bytes: bytes.baseAddress! + start, count: sliceLen)
                let tag = String(decoding: tagData, as: UTF8.self).lowercased()

                // 4. Must contain both “http‑equiv="refresh"” and “content=”
                guard tag.contains("http-equiv=\"refresh\"") ||
                      tag.contains("http-equiv='refresh'") else { continue }
                guard let contentRange = tag.range(of: #"content\s*=\s*['"][^'"]+['"]"#,
                                                   options: .regularExpression)
                else { continue }
                let contentValue = tag[contentRange]
                // 5. Inside content, look for "url="
                guard let firstQuote = contentValue.firstIndex(where: { $0 == "\"" || $0 == "'" }) else { continue }
                let quoteChar = contentValue[firstQuote]
                let afterQuote = contentValue[contentValue.index(after: firstQuote)...]
                guard let closingQuote = afterQuote.firstIndex(of: quoteChar) else { continue }
                let inner = afterQuote[..<closingQuote]

                let parts = inner.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2 else { continue }
                var target = parts[1].trimmingCharacters(in: .whitespaces)

                if target.lowercased().hasPrefix("url=") {
                    target = target.dropFirst(4).trimmingCharacters(in: .whitespaces)
                }

                var url = String(target)

                // Strip trailing quotes or semicolon
                if url.hasSuffix("\"") || url.hasSuffix("'") { url.removeLast() }
                if url.hasSuffix(";") { url.removeLast() }

                // Unescape common entity
                url = url.replacingOccurrences(of: "&amp;", with: "&")
                #if DEBUG
                let endTime = DispatchTime.now()
                let elapsed = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000
                #endif
                return url.isEmpty ? nil : String(url)
            }
            
            #if DEBUG
            let endTime = DispatchTime.now()
            let elapsed = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000
            print("RedirectMetaExtractor took \(elapsed) µs")
            #endif
            
            return nil
        }
    }
}
