//  LamaiAnalyzerHub.swift
//  URLChecker
//
//  Created by Chief Hakka on 27/03/2025.
//

struct LamaiAnalyzerHub {
    
    internal static func handleDecodedChild(value: String, method: String, under parent: DecodedNode, maxDepth: Int) {
        let child = DecodedNode(value: value, depth: parent.depth + 1, parent: parent)
        child.method = method
        child.decoded = value

        // Run all non-entropy analyses first
        child.runAllAnalyses()

        // Run splits first if nothing obvious was found
        if !child.wasRelevant {
            speculativeSplitStrategies(from: value, under: child, maxDepth: maxDepth)
        }
        
        // If still not relevant AND no good children -> fallback to entropy
        if !child.wasRelevant, child.children.isEmpty {
                child.checkEntropy()
        }
        
        if child.wasRelevant {
            child.shouldStop = true
        }

        parent.children.append(child)

        if !child.shouldStop {
            LamaiDecoding.decodeNode(child, maxDepth: maxDepth)
        }
    }

    private static func speculativeSplitStrategies(from string: String, under parent: DecodedNode, maxDepth: Int) {
        // Strategy 1: full query pairs (e.g. a=b&c=d)
        let queryCandidates = string.components(separatedBy: "&").filter { $0.contains("=") }
        if queryCandidates.count >= 2 {
            let queryPairs = queryCandidates.compactMap { pair in
                pair.components(separatedBy: "=").last
            }.filter { $0.count >= 4 }

            var children: [DecodedNode] = []
            for value in queryPairs {
                let node = DecodedNode(value: value, depth: parent.depth + 1, parent: parent)
                node.method = "query-pair"
                node.decoded = value
                node.runAllAnalyses()
                if !node.shouldStop {
                    LamaiDecoding.decodeNode(node, maxDepth: maxDepth)
                }
                children.append(node)
            }

            if children.contains(where: { $0.wasRelevant }) {
                parent.children.append(contentsOf: children)
                return
            }
        }

        // Strategy 2: single key=value
        if string.contains("="), !string.contains("&") {
            let parts = string.components(separatedBy: "=")
            if parts.count == 2, parts[1].count >= 6 {
                let value = parts[1]
                let node = DecodedNode(value: value, depth: parent.depth + 1, parent: parent)
                node.method = "kv-pair"
                node.decoded = value
                node.runAllAnalyses()

                if !node.shouldStop {
                    LamaiDecoding.decodeNode(node, maxDepth: maxDepth)
                }
                if node.wasRelevant {
                    parent.children.append(node)
                    return
                }
            }
        }

        // Strategy 3: token delimiters
        let delimiters = ["|",
                          ".",
                          ";" ,
                          "_",
                          "~",
                          ":"]
        var bestChildren: [DecodedNode] = []
        
        for delimiter in delimiters {
            let count = string.filter { $0 == Character(delimiter) }.count
            if count < 2 { continue }
            print("YES YLLAH 2")
            let parts = string.components(separatedBy: String(delimiter)).filter { $0.count >= 4 }
            var children: [DecodedNode] = []
            for part in parts {
                let node = DecodedNode(value: part, depth: parent.depth + 1, parent: parent)
                node.method = "split:\(delimiter)"
                node.decoded = part
                node.runAllAnalyses()
                print("YES YLLAH3")
                if node.wasRelevant {
                    print("YES")
                    
                }
                if !node.shouldStop {
                    LamaiDecoding.decodeNode(node, maxDepth: maxDepth)
                }
                children.append(node)
            }

            if children.contains(where: { $0.wasRelevant }) {
                bestChildren = children
                break
            }
        }

        if !bestChildren.isEmpty {
            parent.children.append(contentsOf: bestChildren)
        }
    }
    
}
