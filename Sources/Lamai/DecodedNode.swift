//  DecodingNode.swift
//  LegitURL
//
//  Created by Chief Hakka on 24/03/2025.
//
import Foundation

class DecodedNode: Identifiable {
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
        case json(keys: [String])
        case brandExact(String) // New case for brand exact match
        case brandContained(String) // New case for brand contained
        case brandSimilar(String) // New case for brand similar
        
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
            case .json: return "JSON" // Updated shortLabel for JSON
            case .brandExact: return "BrandExact" // Short label for brand exact
            case .brandContained: return "BrandContained" // Short label for brand contained
            case .brandSimilar: return "BrandSimilar" // Short label for brand similar
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
    
    // Need new one : Is this a "normal word" correct text ect !!!!
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
        
        // New check for JSON keys
        if let keys = NodeAnalyzer.detectJSONKeys(target), !keys.isEmpty {
            findingsList.append(.json(keys: keys))
        }
        
        // New check for brand impersonation
        if let match = NodeAnalyzer.detectBrandMatch(target) {
            switch match {
            case .exact(let brand):
                findingsList.append(.brandExact(brand))
            case .contained(let brand):
                findingsList.append(.brandContained(brand))
            case .similar(let brand):
                findingsList.append(.brandSimilar(brand))
            }
        }
        
        findings.append(contentsOf: findingsList)
        wasRelevant = !findingsList.isEmpty
    }
    
    func checkEntropy() {
        let target = decoded ?? value
        if let entropyFinding = NodeAnalyzer.checkIfRealWordAndEntropy(target) {
            findings.append(entropyFinding)
            wasRelevant = true
        }
    }
    
    func hasDeepDescendant(minDepth: Int = 1) -> Bool {
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
                print("\(indent)  URL Found: \(url)")
            case .uuid(let result):
                let uuidText = result.formatted ?? result.original
                print("\(indent)  UUID Found: \(uuidText) (\(result.classification))")
            case .scamWord(let word):
                print("\(indent)   Scam Word: \(word)")
            case .phishingWord(let word):
                print("\(indent)   Phishing Word: \(word)")
            case .entropy(let score, let value):
                print("\(indent)   High Entropy: \(value) ≈ \(String(format: "%.2f", score))")
            case .longEntropyLike(let value):
                print("\(indent)   Long suspicious blob: \(value)")
            case .isIPv4(let value):
                print("\(indent)  IPv4 Found: \(value)")
            case .isIPv6(let value):
                print("\(indent)  IPv6 Found: \(value)")
            case .email(let value):
                print("\(indent)  Email Found: \(value)")
            case .json(let keys): // Display JSON findings
                print("\(indent)   JSON Found with keys: \(keys.joined(separator: ", "))")
            case .brandExact(let brand): // Display brand exact match
                print("\(indent)   Brand Exact Match: \(brand)")
            case .brandContained(let brand): // Display brand contained
                print("\(indent)   Brand Contained: \(brand)")
            case .brandSimilar(let brand): // Display brand similar
                print("\(indent)   Brand Similar: \(brand)")
            }
        }
        print("-----------------------------EndOfNode-------------------------------")
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
    
    func hasUniqueFinding(against cache: inout Set<String>) -> Bool {
        for finding in findings {
            let key = finding.shortLabel + ":" + finding.hashValue.description
            if cache.contains(key) { return false }
            cache.insert(key)
        }
        return true
    }
}

extension Array where Element == DecodedNode.NodeFinding {
    var onlyContainsEntropy: Bool {
        return !isEmpty && allSatisfy {
            if case .entropy = $0 { return true }
            if case .longEntropyLike = $0 { return true }
            return false
        }
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

extension NodeAnalyzer {
    enum BrandMatch {
        case exact(String)
        case contained(String)
        case similar(String)
    }
}
