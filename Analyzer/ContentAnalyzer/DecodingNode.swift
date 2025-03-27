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
    
    // Adding some var for analysinsg while building the node
    var findings: [NodeFinding] = [] // Collected findings like UUIDs, URLs, etc.
    var wasRelevant: Bool = false         // True if any interesting value was found
    
    //enum to store the different possible findings
    enum NodeFinding: Hashable {
        case url(String)
        case uuid(DecodingTools.UUIDAnalysisResult)
        case scamWord(String)
        case phishingWord(String)
        case entropy(score: Double, value: String)
        case longEntropyLike(value: String)
        case isIPv4(String)
        case isIPv6(String)
        case email([String])
        
        var shortLabel: String {
            switch self {
            case .url: return "URLFound"
            case .uuid: return "UUIDFound"
            case .scamWord: return "ScamWord"
            case .phishingWord: return "PhishingWord"
            case .entropy: return "HighEntropy"
            case .longEntropyLike: return "LongEntropyLike"
            case .isIPv4: return "IPv4"
            case .isIPv6: return "IPv6"
            case .email: return "email"
            }
        }
    }
    
    init(value: String, decoded: String? = nil, method: String? = nil, depth: Int, parent: DecodedNode? = nil) {
        self.value = value
        self.decoded = decoded
        self.method = method
        self.depth = depth
        self.parent = parent
        self.findings = []
        self.wasRelevant = false
        self.shouldStop = false
    }
    
    
    func runAllAnalyses() {
        let target = decoded ?? value
        var findingsList: [DecodedNode.NodeFinding] = []
        
        
        let ipv4 = NodeAnalyzer.checkIfIp4(target)
        if let ipv4 = ipv4 {
            findingsList.append(.isIPv4(ipv4))
        }
        
        let ipv6 = NodeAnalyzer.checkIfIPv6(target)
        if let ipv6 = ipv6 {
            findingsList.append(.isIPv6(ipv6))
        }
        
        if let emailMatches = NodeAnalyzer.detectEmail(target), !emailMatches.isEmpty {
            findingsList.append(.email(emailMatches))

        // Don't run URL detection if we already have email
        } else if ipv4 == nil, ipv6 == nil {
            if let url = NodeAnalyzer.detectURL(target) {
                findingsList.append(.url(url))
            }
        }
        
        let uuids = NodeAnalyzer.detectUUIDs(from: target)
        for uuid in uuids {
            findingsList.append(.uuid(uuid))
        }
        
        if let scam = NodeAnalyzer.detectScanWords(target) {
            findingsList.append(.scamWord(scam))
        }
        
        if let phishing = NodeAnalyzer.detectPhishingWords(target) {
            findingsList.append(.phishingWord(phishing))
        }
        let skipEntropy = !findingsList.isEmpty || !children.isEmpty
        if let entropyFinding = NodeAnalyzer.checkIfRealWordAndEntropy(target, skip: skipEntropy) {
            findingsList.append(entropyFinding)
        }
        
        for finding in findingsList {
            findings.append(finding)  // simple map for now
        }
        
        wasRelevant = !findingsList.isEmpty
    }
    
    func hasDeepDescendant(minDepth: Int = 2) -> Bool {
        return children.contains { $0.depth >= minDepth || $0.hasDeepDescendant(minDepth: minDepth) }
    }
}

extension DecodedNode {
    // Helper for debug display
    func printTree(indent: String = "") {
        let methodLabel = method ?? "raw"
        print("\(indent)↳ [\(methodLabel)] \(value)")
        
        for finding in findings {
            switch finding {
            case .url(let url):
                print("\(indent)  🔍 URL Found: \(url)")
            case .uuid(let result):
                let uuidText = result.formatted ?? result.original
                print("\(indent)  🔍 UUID Found: \(uuidText) (\(result.classification))")
            case .scamWord(let word):
                print("\(indent)  ⚠️ Scam Word: \(word)")
            case .phishingWord(let word):
                print("\(indent)  ⚠️ Phishing Word: \(word)")
            case .entropy(let score, let value):
                print("\(indent)  🧪 High Entropy: \(value) ≈ \(String(format: "%.2f", score))")
            case .longEntropyLike(let value):
                print("\(indent)  🧪 Long suspicious blob: \(value)")
            case .isIPv4(let value):
                print("\(indent)  IPv4 Found: \(value)")
            case .isIPv6(let value):
                print("\(indent)  IPv6 Found: \(value)")
            case .email(let value):
                print("\(indent)  Email Found: \(value)")
            }
        }
        print("-----EndOfNode--------------------")
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
