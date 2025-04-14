//  DataSignatures.swift
//  URLChecker
//
//  Created by Chief Hakka on 11/04/2025.
//
import Foundation
struct DataSignatures {
//    public static func extractHtmlBodyRange(from body: Data) -> Range<Int>? {
//        guard let htmlOpen = body.range(of: Data("<html".utf8), options: .caseInsensitive),
//              let htmlClose = body.range(of: Data("</html>".utf8), options: .caseInsensitive, in: htmlOpen.lowerBound..<body.count) else {
//            return nil
//        }
//
//        return htmlOpen.lowerBound..<htmlClose.upperBound
//    }
    
    public static func extractAllTagMarkers(in body: Data, within range: Range<Int>, tag: UInt8 = 60) -> [Int] {
        var tagPositions: [Int] = []
        var currentIndex = range.lowerBound

        while currentIndex < range.upperBound {
            if body[currentIndex] == tag {
                tagPositions.append(currentIndex)
            }
            currentIndex += 1
        }

        return tagPositions
    }
//    Need to "fallBack" to end of document is </html> is not found , this is for later! Because it needs to ripple to the warnings etc
    public static func extractHtmlTagRange(in body: Data) -> Range<Int>? {
        let prefixRange = body.startIndex..<min(500, body.count)
        let suffixRange = max(body.count - 500, 0)..<body.count

        let htmlOpenTag = Data("<html".utf8)
        let htmlCloseTag = Data("</html>".utf8)

        guard let openRange = body.range(of: htmlOpenTag, options: [], in: prefixRange),
              let closeRange = body.range(of: htmlCloseTag, options: [], in: suffixRange) else {
            return nil
        }

        return openRange.lowerBound..<closeRange.upperBound
    }

    public static func matchesAsciiTag(at position: Int, in body: Data, asciiToCompare: [UInt8], lookAheadWindow: Int = 24) -> Bool {
        let maxLookahead = min(position + lookAheadWindow, body.count)
        let slice = body[position..<maxLookahead]

        var index = slice.startIndex + 1
        while index < slice.endIndex && (slice[index] == 0x20 || slice[index] == 0x09 || slice[index] == 0x0A || slice[index] == 0x0D) {
            index += 1
        }

        let remaining = slice[index..<slice.endIndex]
        guard remaining.count >= asciiToCompare.count else { return false }

        for i in 0..<asciiToCompare.count {
            let char = remaining[remaining.startIndex + i]
            if char | 0x20 != asciiToCompare[i] {
                return false
            }
        }

        return true
    }
    
    public static func fastScriptByteHint(at position: Int, in body: Data, hint: [UInt8], range: Int = 4) -> Bool {
        let end = min(position + range + 1, body.count)
        var index = position + 1

        while index < end {
            let byte = body[index]
            
            // Check for match against either of the hint characters (e.g. 's' or 'S')
            if byte == hint[0] || byte == hint[1] {
                return true
            }
            
            // Skip ASCII whitespace: space, tab, newline, carriage return
            if byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D {
                index += 1
                continue
            }

            // Non-matching, non-whitespace byte ends the search
            return false
        }

        return false
    }
}
