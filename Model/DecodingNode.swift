//
//  DecodingNode.swift
//  URLChecker
//
//  Created by Chief Hakka on 24/03/2025.
//
import Foundation

class DecodedNode {
    let id: String = UUID().uuidString
    let value: String                 // Original string (input or sub-part)
    var decoded: String?             // Decoded version (if any)
    var method: String?              // "base64", "hex", "percent", etc
    var depth: Int                   // How deep into the decoding tree
    weak var parent: DecodedNode?   // Optional reference to parent node
    var children: [DecodedNode] = []// Subparts or decoded paths
    var shouldStop: Bool = false     // Flag to prevent further decoding

    init(value: String, depth: Int, parent: DecodedNode? = nil) {
        self.value = value
        self.depth = depth
        self.parent = parent
    }
}

extension DecodedNode {
    // Helper for debug display
    func printTree(indent: String = "") {
        let methodLabel = method ?? "raw"
        print("\(indent)↳ [\(methodLabel)] \(value)")
        for child in children {
            child.printTree(indent: indent + "  ")
        }
    }

    // Optional: full path from root
    func fullPath() -> [DecodedNode] {
        var path: [DecodedNode] = [self]
        var current = self
        while let parent = current.parent {
            path.insert(parent, at: 0)
            current = parent
        }
        return path
    }
}

extension DecodedNode {
    func methodPath() -> [String] {
        var path: [String] = []
        var current: DecodedNode? = self
        while let node = current {
            if let m = node.method {
                path.insert(m, at: 0)
            }
            current = node.parent
        }
        return path
    }
}

extension String {
    var isMostlyPrintable: Bool {
        let threshold: Double = 0.85
        let printable = self.filter { $0.isASCII && $0.isPrintable }
        return Double(printable.count) / Double(self.count) >= threshold
    }
}

extension String {
    func mimeDecoded() throws -> String {
        let decoded = try NSMutableAttributedString(
            data: Data("=?utf-8?Q?\(self)?=".utf8),
            options: [.documentType: NSAttributedString.DocumentType.html],
            documentAttributes: nil
        ).string
        return decoded
    }

    func decodedUnicodeEscapes() -> String? {
        let transformed = applyingTransform(.init("Any-Hex/Java"), reverse: false)
        return transformed
    }
}

extension Character {
    var isPrintable: Bool {
        guard let scalar = unicodeScalars.first else { return false }
        return scalar.isASCII && scalar.value >= 32 && scalar.value < 127
    }
}

extension Data {
    init?(hexString: String) {
        let length = hexString.count
        var data = Data(capacity: length / 2)
        var index = hexString.startIndex

        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard nextIndex <= hexString.endIndex else { return nil }
            let byteString = hexString[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }
}
