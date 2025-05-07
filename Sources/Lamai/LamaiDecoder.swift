//  LamaiDecoding.swift
//  LegitURL
//
//  Created by Chief Hakka on 24/03/2025.
//
//
// TODO: Adapt Lamai for Set-Cookie analysis context.
// - Most cookie values are percent or base64 encoded blobs
// - Some are delimited flags or IDs, ideal for split heuristics
// - A few may require binary/base64 tolerance (avoid UTF-8-only decoding assumptions)
// - Consider skipping full tree generation unless wasRelevant=true or looksLikeToken()
import Foundation

struct LamaiDecoder {
    
    static func decode(input: String, maxDepth: Int = 4) -> DecodedNode {
        let root = DecodedNode(value: input, depth: 0)
        decodeNode(root, maxDepth: maxDepth)
        
        if !root.wasRelevant, root.children.isEmpty {
            root.runAllAnalyses()
            if !root.wasRelevant {
                root.checkEntropy()
            }
            
        }
        root.printTree(indent: "")
        return root
    }
    
    
    internal static func decodeNode(_ node: DecodedNode, maxDepth: Int) {
        guard !node.shouldStop, node.depth < maxDepth else { return }
        
        let current = node.value
        
        // Step 1: Single step percent decoding
        if let decoded = current.removingPercentEncoding,
           decoded != current {
            LamaiCoordinator.handleDecodedChild(value: decoded, method: "percent", under: node, maxDepth: maxDepth)
        }
        
        // Step 2: Try base64
        let currentBase64 = current
        if let padded = DecodingTools.normalizeBase64(currentBase64) {
            
            if let data = Data(base64Encoded: padded) {
                if let b64Str = String(data: data, encoding: .utf8) {
                    LamaiCoordinator.handleDecodedChild(value: b64Str, method: "base64", under: node, maxDepth: maxDepth)
                } else if let rawData = padded.data(using: .utf8),
                          let recovered = decodeUntilItStopsMakingSense(encodedBlob: rawData) {
                    LamaiCoordinator.handleDecodedChild(value: recovered, method: "base64:shrunk", under: node, maxDepth: maxDepth)
                }
            }
        }
        
        // Step 3: Try hex decoding
        if current.count % 2 == 0,
           let hexData = Data(hexString: current),
           let hexStr = String(data: hexData, encoding: .utf8) {
            LamaiCoordinator.handleDecodedChild(value: hexStr, method: "hex", under: node, maxDepth: maxDepth)
        }
        
        // Step 4: Try MIME (quoted-printable)
        if looksLikeMime(current),
           let mimeStr = try? current.mimeDecoded(),
           mimeStr != current {
            LamaiCoordinator.handleDecodedChild(value: mimeStr, method: "mime", under: node, maxDepth: maxDepth)
        }
        
        // Step 5: Unicode escape decoding (e.g. \\u003d)
        if looksLikeUnicode(current),
           let unicodeStr = current.decodedUnicodeEscapes(),
           unicodeStr != current {
            LamaiCoordinator.handleDecodedChild(value: unicodeStr, method: "unicode", under: node, maxDepth: maxDepth)
        }
        
        
        // Step 6: Future steps — Add more decoding strategies as needed
    }
    
    private static func decodeUntilItStopsMakingSense(encodedBlob: Data) -> String? {
        guard let fullString = String(data: encodedBlob, encoding: .utf8) else {
            return nil
        }
        
        for i in stride(from: fullString.count, through: 4, by: -1) {
            let index = fullString.index(fullString.startIndex, offsetBy: i)
            let slice = String(fullString[..<index])
            let padded = slice + String(repeating: "=", count: (4 - slice.count % 4) % 4)
            
            if let decoded = Data(base64Encoded: padded),
               let utf8 = String(data: decoded, encoding: .utf8) {
                return utf8
            }
        }
        return nil
    }
    
    private static func looksLikeMime(_ str: String) -> Bool {
        let lower = str.lowercased()
        //TODO: Look for a better logic
        return lower.contains("=?utf-8?q?") || lower.contains("=?utf-8?b?")
    }
    
    private static func looksLikeUnicode(_ str: String) -> Bool {
        //TODO: Look for a better logic
        return str.contains("\\u003") || str.contains("\\u00") || str.contains("&#x")
    }
}

