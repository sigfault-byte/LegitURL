//
//  CSPUtils.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//

import Foundation

struct ClassifiedCSPResult {
    var structuredCSP: [String: [Data: CSPValueType]]
    var directiveBitFlags: [String: Int32]
    var directiveSourceTraits: [String: DirectiveSourceInfo]
}

struct DirectiveSourceInfo {
    var urlCount: Int
    var hasHTTP: Bool
    var hasWildcard: Bool
    var onlySelf: Bool
}

struct CSPUtils {
    static func cleaningCSPSlice(slice: Range<Int>, in data: Data) -> Data {
        var start = slice.startIndex
        var end = slice.endIndex
        
        // Step 1: Trim leading spaces
        while start < end, data[start] == HeadHeaderByteSignatures.space {
            start = data.index(after: start)
        }
        
        // Step 2: Trim trailing spaces and semicolons
        while end > start {
            let previous = data.index(before: end)
            let byte = data[previous]
            if byte == HeadHeaderByteSignatures.space || byte == HeadHeaderByteSignatures.semicolon {
                end = previous
            } else {
                break
            }
        }
        
        // Step 3: Return cleaned slice
        return data[start..<end]
    }
    
    static func exploseCSPSlicesOnSpace(in data: Data) -> [Data] {
        var arrayOfSlices: [Data] = []
        var lastStart = data.startIndex
        
        for index in data.indices {
            if data[index] == HeadHeaderByteSignatures.space {
                if lastStart < index { // Prevent empty slices
                    let slice = cleaningCSPSlice(slice: lastStart..<index, in: data)
                    arrayOfSlices.append(slice)
                }
                lastStart = data.index(after: index)
            }
        }
        
        // Handle the last piece (after the last space)
        if lastStart < data.endIndex {
            let slice = cleaningCSPSlice(slice: lastStart..<data.endIndex, in: data)
            arrayOfSlices.append(slice)
        }
        
        return arrayOfSlices
    }
    
    static func parseDirectiveSlice(_ slice: Data) -> [Data: [Data]]? {
        //  TODO: Without a second cleaning some crashes occurs, need to investigate
        let cleanedSlice = cleaningCSPSlice(slice: slice.startIndex..<slice.endIndex, in: slice)
        let parts = exploseCSPSlicesOnSpace(in: cleanedSlice)
        
        // Safety: must have at least 1 part (the directive)
        guard !parts.isEmpty else {
            return nil
        }
        
        let directive = parts[0]
        let values = Array(parts.dropFirst())
        
        return [directive: values]
    }
    
    static func classifyCSPValue(_ value: Data) -> CSPValueType {
        if value.first == HeadHeaderByteSignatures.singleQuote,
           value.last == HeadHeaderByteSignatures.singleQuote {
            if value.starts(with: safeCSPValue.nonce){
                return .nonce
            }
            return .keyword
        } else if value.starts(with: dangerousCSPValues.data) || value.starts(with: dangerousCSPValues.blob) {
            return .scheme
        } else if value == "*".data(using: .utf8) {
            return .wildcard
        } else {
            return .url
        }
    }
}

enum CSPValueType {
    case keyword
    case scheme
    case url
    case wildcard
    case nonce
    case unknown
}

extension CSPValueType {
    var description: String {
        switch self {
        case .keyword: return "keyword"
        case .url: return "url"
        case .scheme: return "scheme"
        case .wildcard: return "wildcard"
        case .nonce: return "nonce"
        case .unknown: return "unknown"
        }
    }
}
