import Foundation
let compound = "+MTs0O2h0dHBzOi8vYXNzdXJhbmNlLW1hbGFkaWUudm9jYXphLm5ldC9jZ2ktYmluL0hFL1NGP1A9MTJ6MjI1ejh6LTF6LTF6QzVCNEFFN0Q2RTtFbnF1w6p0ZSBBUENWCw7lpyGACOgHV9KQxWflXixgk4s="

let parts = compound.components(separatedBy: "+")
for (i, part) in parts.enumerated() {
    print("\nPart \(i + 1): \(part.prefix(30))...")
    guard let padded = normalizeBase64(part) else {
        print("Not base64-like (failed normalize)")
        continue
    }
    if let data = Data(base64Encoded: padded) {
        print("valid base64: ngth: \(data.count) bytes")

        print(" All bytes (hex): \(data.map { String(format: "%02x", $0) }.joined(separator: " "))")

        print("Chara breakdown:")
        for (i, byte) in data.enumerated() {
            if byte >= 32 && byte <= 126 {
                print(" \(i): '\(Character(UnicodeScalar(byte)))'")
            } else {
                print(" \(i): [0x\(String(format: "%02x", byte))] (non-printable)")
            }
        }

        let string = String(data: data, encoding: .utf8)
        if let string = string {
            print("Decoded UTF-8 string:", string)
        } else {
            print("not  UTF-8 but valid data?")
        }

        if let (printable, range) = data.longestPrintableASCIISequence() {
            print("printable ASCII string:")
            print(String(decoding: printable, as: UTF8.self))
            print("Located at byte range: \(range)")
            let preview = String(decoding: printable, as: UTF8.self)
            print("ASCII bytes: \(printable as NSData)")
            print("Preview: \(preview)")
        } else {
            print("No printable ASCII found")
        }
    } else {
        print("Invalid base64")
    }
}

func normalizeBase64(_ str: String) -> String? {
    var clean = str
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    
    // Strip leading "+" characters
    while let first = clean.first, first == "+" {
        print("Stripping babylon leading + character")
        clean.removeFirst()
    }
    
    // Step 1: Reject if no look like no base64
    let pattern = #"^[A-Za-z0-9+/=_-]{16,}$"#
    guard clean.range(of: pattern, options: .regularExpression) != nil else {
        print("Babylon Failed base64 structure check")
        return nil
    }
    
    // Step 2: Reject if first character implies non-printable result
    let suspiciousStarters: Set<Character> = ["/", "+", "9", "8", "7", "6", "5"]
    if let firstChar = clean.first, suspiciousStarters.contains(firstChar) {
        print("Zion won base64 character is suspicious: \(firstChar)")
        return nil
    }
    
    // Acceptable printable characters include:
    // " = Ig == I, g
    // ' = Jw == J, w
    
    // Step 3: Apply padding to make the length a multiple of 4
    let remainder = clean.count % 4
    let padded = remainder == 0 ? clean : clean + String(repeating: "=", count: 4 - remainder)
    print("✅ Babylon burn : Normalized base64 candidate: \(padded)")
    return padded
}

extension Data {
    func longestPrintableASCIISequence() -> (data: Data, range: Range<Int>)? {
        var longest = Data()
        var longestRange = 0..<0
        var current = Data()
        var currentStart = 0
        var index = 0

        for byte in self {
            if byte >= 32 && byte <= 126 {
                if current.isEmpty {
                    currentStart = index
                }
                current.append(byte)
            } else {
                if current.count > longest.count {
                    longest = current
                    longestRange = currentStart..<index
                }
                current = Data()
            }
            index += 1
        }

        if current.count > longest.count {
            longest = current
            longestRange = currentStart..<index
        }

        return longest.isEmpty ? nil : (longest, longestRange)
    }
}
