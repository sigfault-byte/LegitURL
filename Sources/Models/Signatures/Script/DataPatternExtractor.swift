//  DataSignatures.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/04/2025.
//
import Foundation
struct DataSignatures {

    public static func extractAllTagMarkers(in body: Data, within range: Range<Int>, tag: UInt8 = 60) -> [Int] {
        var tagPositions: [Int] = []

        // Access the raw bytes of the Data buffer
        // 'withUnsafeBytes' gives direct access to memory
        // The closure takes a single argument: UnsafeRawBufferPointer
        // 'in indicates a "lambda / anonymous function "
        body.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) -> Void in
            // Safely get the base pointer from the buffer
            guard let rawBase = rawBuffer.baseAddress else { return }

            // Assume the raw memory is composed of UInt8 bytes ...
            let base = rawBase.assumingMemoryBound(to: UInt8.self)
            let start = base + range.lowerBound
            let end = base + range.upperBound

            // Scan from the beginning of the range using a ptr
            var ptr = UnsafeRawPointer(start)

            // While not at the end
            while ptr < UnsafeRawPointer(end) {
                // Search for byte matching 'tag' using memchr
                // Only the lowest 8 bits of 'Int32(tag)' are used <--- thanks AI
                if let match = memchr(ptr, Int32(tag), end - ptr.assumingMemoryBound(to: UInt8.self)) {
                    // Calculate the offset from the base pointer
                    let offset = UnsafeRawPointer(match) - UnsafeRawPointer(base)
                    tagPositions.append(offset)

                    // Move the pointer forward to continue scanning
                    ptr = UnsafeRawPointer(match).advanced(by: 1)
                } else {
                    break
                }
            }
        }
        return tagPositions
    }

    /// Returns the byte offset of the first occurrence of `tag` within `range`, or nil if not found.
    public static func extractFirstTagMarker(in body: Data,
                                             within range: Range<Int>,
                                             tag: UInt8 = 60) -> Int? {
        var foundOffset: Int?
        body.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            let startPtr = base + range.lowerBound
            let length = range.upperBound - range.lowerBound
            if let match = memchr(startPtr, Int32(tag), length) {
                // Compute offset from beginning of body
                let offset = UnsafeRawPointer(match) - UnsafeRawPointer(base)
                foundOffset = offset
            }
        }
        return foundOffset
    }

    /// Returns the byte range that spans from the first “<html” tag
    public static func extractHtmlTagRange(in body: Data) -> (Range<Int>, htmlClosed: Bool)? {

        // Need at least "<html" = 5 bytes to proceed.
        guard body.count >= 5 else { return nil }

        //first ≤ 500 B
        let prefixLimit = min(500, body.count)
        var openStart: Int? = nil
        var i = body.startIndex
        while i <= prefixLimit - 5 {               // need 5 bytes: "<html"
            if body[i] == 0x3C {                   // '<'
                let h = body[i+1] | 0x20           // fold to lowercase
                let t = body[i+2] | 0x20
                let m = body[i+3] | 0x20
                let l = body[i+4] | 0x20
                if h == 0x68 && t == 0x74 && m == 0x6D && l == 0x6C {
                    openStart = i
                    break                          // found it – stop scanning prefix
                }
            }
            i &+= 1 // <- because you never know
        }
        guard let start = openStart else { return nil }

        // last ≤ 500 B
        let suffixStartIdx = max(body.count - 500, 0)
        var closeEnd: Int? = nil
        var j = suffixStartIdx
        while j <= body.count - 6 {                // need 6 bytes: "</html"
            if body[j] == 0x3C && body[j+1] == 0x2F { // '<' '/'
                let h = body[j+2] | 0x20
                let t = body[j+3] | 0x20
                let m = body[j+4] | 0x20
                let l = body[j+5] | 0x20
                if h == 0x68 && t == 0x74 && m == 0x6D && l == 0x6C {
                    // skip to the next '>'
                    var k = j + 6
                    while k < body.count && body[k] != 0x3E { k &+= 1 }
                    closeEnd = min(k + 1, body.count)
                    break
                }
            }
            j &+= 1
        }

        let end = closeEnd ?? body.endIndex
        return (start ..< end, closeEnd != nil)
    }

    
    public static func matchesAsciiTag(at position: Int,
                                       in body: Data,
                                       asciiToCompare: [UInt8],
                                       lookAheadWindow: Int = 24) -> Bool {
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
            if char | 0x20 != asciiToCompare[i] { // <- smooth operator
                return false
            }
        }

        return true
    }
    
    public static func fastScriptByteHint(at position: Int,
                                          in body: Data,
                                          hint: [UInt8],
                                          range: Int = 4) -> Bool {
        let end = min(position + range + 1, body.count)
        var index = position + 1
        while index < end {
            let byte = body[index]
            
            if hint.count == 1 {
                if byte == hint[0] {
                    return true
                }
            } else if hint.count >= 2 {
                if byte == hint[0] || byte == hint[1] {
                    return true
                }
            }
            // Ski garbage empty space
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
