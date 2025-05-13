//
//  DataExtensions.swift
//  LegitURL
//
//  Created by Chief Hakka on 22/04/2025.
//
import Foundation

extension Data {
    func containsBytes(of pattern: [UInt8]) -> Bool {
        guard pattern.count > 0, self.count >= pattern.count else { return false }
        
        return self.withUnsafeBytes { dataPtr in
            for i in 0...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                if window.elementsEqual(pattern) {
                    return true
                }
            }
            return false
        }
    }
    
    func containsBytesCaseInsensitive(of pattern: [UInt8]) -> (found: Bool, position: Int?) {
        guard pattern.count > 0, self.count >= pattern.count else { return (false, nil) }
        
        return self.withUnsafeBytes { dataPtr in
            for i in 0...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                let windowLower = window.map { ($0 >= 65 && $0 <= 90) ? $0 + 32 : $0 }
                if windowLower.elementsEqual(pattern) {
                    return (true, i)
                }
            }
            return (false, nil)
        }
    }
    
    func containsBytesCaseInsensitive(of pattern: [UInt8], startIndex: Int = 0) -> (found: Bool, position: Int?) {
        guard pattern.count > 0, self.count >= startIndex + pattern.count else { return (false, nil) }
        
        return self.withUnsafeBytes { dataPtr in
            for i in startIndex...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                let windowLower = window.map { ($0 >= 65 && $0 <= 90) ? $0 + 32 : $0 }
                if windowLower.elementsEqual(pattern) {
                    return (true, i)
                }
            }
            return (false, nil)
        }
    }
}

extension Data {
    func longestPrintableASCIISequence() -> Data {
        var longest = Data()
        var current = Data()
        
        for byte in self {
            if byte >= 32 && byte <= 126 {
                current.append(byte)
            } else {
                if current.count > longest.count {
                    longest = current
                }
                current = Data()
            }
        }
        if current.count > longest.count {
            longest = current
        }
        return longest
    }
}

extension UInt8 {
    var isAZ: Bool { self | 0x20 >= 97 && self | 0x20 <= 122 }
    var is09: Bool { self >= 48 && self <= 57 }
    var isAlnum: Bool { isAZ || is09 }
}


