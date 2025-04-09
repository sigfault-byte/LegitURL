//
//  ExtractKeyValuePair.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

import Foundation

struct KeyValuePairExtract {
    
////Query can have duplicating keys. This does not work. BUT, it could be usefull for context analysis later
//    static func extractAsDictionary(from input: String) -> [String: String] {
//        var keyValuePairs: [String: String] = [:]
//        
//        let pairs = input.split(separator: "&")
//        for pair in pairs {
//            // Split on the first "=".
//            let keyValue = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
//            if keyValue.count == 2 {
//                let key = String(keyValue[0])
//                let value = String(keyValue[1])
//                keyValuePairs[key] = value
//            }
//        }
//        return keyValuePairs
//    }
    
//    / Extracts key-value pairs from a querylike string
//    / Returns arrays of keys and values
    static func extractAsArray(from input: String) -> (keys: [String], values: [String]) {
        var keys = [String]()
        var values = [String]()
        
        let pairs = input.split(separator: "&")
        for pair in pairs {
            // Split on the first "=".
            let keyValue = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if keyValue.count == 2 {
                let key = String(keyValue[0])
                let value = String(keyValue[1])
                keys.append(key)
                values.append(value)
            }
        }
        
        return (keys, values)
    }

}
