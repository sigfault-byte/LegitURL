//
//  LamaiDecoding.swift
//  URLChecker
//
//  Created by Chief Hakka on 24/03/2025.
//

import Foundation

struct LamaiDecoding {
    
    static func decode(input: String, maxDepth: Int = 4) -> DecodedNode {
        let root = DecodedNode(value: input, depth: 0)
        decodeNode(root, maxDepth: maxDepth)
        if !root.hasDeepDescendant() {
            root.runAllAnalyses()
        }
        print(root.printTree())
        return root
    }
    
    private static func decodeNode(_ node: DecodedNode, maxDepth: Int) {
        guard !node.shouldStop, node.depth < maxDepth else { return }
        
        let current = node.value
        let depth = node.depth
        
        // Step 1: Single step percent decoding
        if let decoded = current.removingPercentEncoding,
           decoded != current,
           decoded.isMostlyPrintable {
            let child = DecodedNode(value: decoded, depth: depth + 1, parent: node)
            child.method = "percent"
            child.decoded = decoded
            child.runAllAnalyses()
            if child.wasRelevant {
                child.shouldStop = true
            }
            node.children.append(child)
            // First try to extract query parameters before splitting on delimiters
            extractQueryParams(from: decoded, under: child, maxDepth: maxDepth)
            extractDelimitedParts(from: decoded, under: child, maxDepth: maxDepth)
            decodeNode(child, maxDepth: maxDepth)
        }
        
        // Step 2: Try base64
        let currentBase64: String
        if let andIndex = current.firstIndex(of: "&") {
            let afterAnd = current[andIndex...]
            if let eqIndex = afterAnd.firstIndex(of: "="),
               afterAnd.distance(from: andIndex, to: eqIndex) < 32 {
                currentBase64 = String(current[..<andIndex])
            } else {
                currentBase64 = current
            }
        } else {
            currentBase64 = current
        }
        let padded = normalizeBase64(currentBase64)
        if let data = Data(base64Encoded: padded),
           let b64Str = String(data: data, encoding: .utf8),
           b64Str.count >= 6,
           b64Str.isMostlyPrintable {
            let child = DecodedNode(value: b64Str, depth: depth + 1, parent: node)
            child.method = "base64"
            child.decoded = b64Str
            child.runAllAnalyses()
            if child.wasRelevant {
                child.shouldStop = true
            }
            node.children.append(child)
            // First try to extract query parameters before splitting on delimiters
            extractQueryParams(from: b64Str, under: child, maxDepth: maxDepth)
            extractDelimitedParts(from: b64Str, under: child, maxDepth: maxDepth)
            decodeNode(child, maxDepth: maxDepth)
        }
        
        // Step 3: Try hex decoding
        if current.count % 2 == 0,
           let hexData = Data(hexString: current),
           let hexStr = String(data: hexData, encoding: .utf8),
           hexStr.isMostlyPrintable {
            let child = DecodedNode(value: hexStr, depth: depth + 1, parent: node)
            child.method = "hex"
            child.decoded = hexStr
            child.runAllAnalyses()
            if child.wasRelevant {
                child.shouldStop = true
            }
            node.children.append(child)
            // First try to extract query parameters before splitting on delimiters
            extractQueryParams(from: hexStr, under: child, maxDepth: maxDepth)
            extractDelimitedParts(from: hexStr, under: child, maxDepth: maxDepth)
            decodeNode(child, maxDepth: maxDepth)
        }
        
        // Step 4: Try MIME (quoted-printable)
        if looksLikeMime(current),
           let mimeStr = try? current.mimeDecoded(),
           mimeStr != current,
           mimeStr.isMostlyPrintable {
            let child = DecodedNode(value: mimeStr, depth: depth + 1, parent: node)
            child.method = "mime"
            child.decoded = mimeStr
            child.runAllAnalyses()
            if child.wasRelevant {
                child.shouldStop = true
            }
            node.children.append(child)
            // First try to extract query parameters before splitting on delimiters
            extractQueryParams(from: mimeStr, under: child, maxDepth: maxDepth)
            extractDelimitedParts(from: mimeStr, under: child, maxDepth: maxDepth)
            decodeNode(child, maxDepth: maxDepth)
        }
        
        // Step 5: Unicode escape decoding (e.g. \\u003d)
        if looksLikeUnicode(current),
           let unicodeStr = current.decodedUnicodeEscapes(),
           unicodeStr != current,
           unicodeStr.isMostlyPrintable {
            let child = DecodedNode(value: unicodeStr, depth: depth + 1, parent: node)
            child.method = "unicode"
            child.decoded = unicodeStr
            child.runAllAnalyses()
            if child.wasRelevant {
                child.shouldStop = true
            }
            node.children.append(child)
            // First try to extract query parameters before splitting on delimiters
            extractQueryParams(from: unicodeStr, under: child, maxDepth: maxDepth)
            extractDelimitedParts(from: unicodeStr, under: child, maxDepth: maxDepth)
            decodeNode(child, maxDepth: maxDepth)
        }
        
        // Step 6: Future steps — Add more decoding strategies as needed
    }
    
    private static func extractDelimitedParts(from string: String, under parent: DecodedNode, maxDepth: Int) {
        let delimiters = ["|", ".", "_", "~", ":"]
        
        for delimiter in delimiters where string.contains(delimiter) {
            let parts = string.split(separator: Character(delimiter))
            for part in parts {
                let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
                guard trimmed.count >= 6 else { continue }
                
                let padded = normalizeBase64(trimmed)
                let isBase64 = Data(base64Encoded: padded) != nil
                let isHex = Data(hexString: trimmed) != nil
                guard isBase64 || isHex else { continue }
                
                let child = DecodedNode(value: trimmed, depth: parent.depth + 1, parent: parent)
                child.method = "split-\(delimiter)"
                parent.children.append(child)
                child.runAllAnalyses()
                if child.wasRelevant {
                    child.shouldStop = true
                }
                decodeNode(child, maxDepth: maxDepth)
            }
        }
    }
    
    private static func extractQueryParams(from string: String, under parent: DecodedNode, maxDepth: Int) {
        let components = string.split(separator: "&")
        for comp in components {
            let kv = comp.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            
            let key = kv[0]
            let value = kv[1]
            
            // Skip if key and value are the same
            guard value != key else { continue }
            
            let cleanValue = value.trimmingCharacters(in: CharacterSet(charactersIn: "=?\""))
            // Skip if value looks like junk (e.g., just pipes, equals, or quotes)
            let isJustSymbols = cleanValue.range(of: #"^[\|\=\"]+$"#, options: .regularExpression) != nil
            guard !isJustSymbols else { continue }
            guard cleanValue.count >= 4,
                  cleanValue.isMostlyPrintable,
                  !isJustSymbols else { continue }
            
            let child = DecodedNode(value: cleanValue, depth: parent.depth + 1, parent: parent)
            child.method = "query-param"
            parent.children.append(child)
            child.runAllAnalyses()
            if child.wasRelevant {
                child.shouldStop = true
            }
            decodeNode(child, maxDepth: maxDepth)
        }
    }
    
    private static func normalizeBase64(_ str: String) -> String {
        let clean = str.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let remainder = clean.count % 4
        return remainder == 0 ? clean : clean + String(repeating: "=", count: 4 - remainder)
    }
    
    private static func looksLikeMime(_ str: String) -> Bool {
        let lower = str.lowercased()
        return lower.contains("=?utf-8?q?") || lower.contains("=?utf-8?b?")
    }
    
    private static func looksLikeUnicode(_ str: String) -> Bool {
        return str.contains("\\u003") || str.contains("\\u00") || str.contains("&#x")
    }
}
