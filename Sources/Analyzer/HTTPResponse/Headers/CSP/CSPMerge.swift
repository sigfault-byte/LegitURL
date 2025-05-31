//
//  CSPMerge.swift
//  LegitURL
//
//  Created by Chief Hakka on 31/05/2025.
//
import Foundation

struct CSPMerge{
    /// Merges two CSP dictionaries, returning merged CSP and lists of added and merged directives.
    public static func merge(
        headerCSP: [String: [Data: CSPValueType]],
        httpEquivCSP: [String: [Data: CSPValueType]]
    ) -> (
        merged: [String: [Data: CSPValueType]],
        addedDirectives: [String],
        mergedDirectives: [String]
    ) {
        var mergedCSP: [String: [Data: CSPValueType]] = [:]
        var addedDirectives: [String] = []
        var mergedDirectives: [String] = []

        for (directive, metaSources) in httpEquivCSP {
            guard !metaSources.isEmpty else { continue }

            if let headerSources = headerCSP[directive] {
                // merge if meta is not more permissive, according to Mozilla, the rule is more source = more permissive?
                if metaSources.count > headerSources.count {
                    continue // Skip overly permissive meta directive
                }

                // Merge only missing values
                var mergedSources = headerSources
                var didMerge = false
                for (key, type) in metaSources where mergedSources[key] == nil {
                    mergedSources[key] = type
                    didMerge = true
                }
                if didMerge {
                    mergedDirectives.append(directive)
                }
                mergedCSP[directive] = mergedSources
            } else {
                // missing directive, accept from meta
                mergedCSP[directive] = metaSources
                addedDirectives.append(directive)
            }
        }

        // Include any headerCSP directives that were not handled above
        for (directive, headerSources) in headerCSP {
            if mergedCSP[directive] == nil {
                mergedCSP[directive] = headerSources
            }
        }
        return (merged: mergedCSP, addedDirectives: addedDirectives, mergedDirectives: mergedDirectives)
    }
    
    public static func logMergedSignal(addedDirectives: [String]?, mergedDirective: [String]?, oginUrl: String) -> [SecurityWarning] {
        var warnings: [SecurityWarning] = []
        let added = addedDirectives ?? []
        let merged = mergedDirective ?? []
        
        if !added.isEmpty {
                warnings.append(SecurityWarning(
                    message: "CSP directives added from <meta http-equiv>: \(added.joined(separator: ", "))",
                    severity: .info,
                    penalty: 0,
                    url: oginUrl,
                    source: .header,
//                    bitFlags: [.HEADERS_CSP_META_USED] // TODO: Could be used for futur signal like "weird config / old config ?
                ))
            }

            if !merged.isEmpty {
                warnings.append(SecurityWarning(
                    message: "CSP directives merged with <meta http-equiv>: \(merged.joined(separator: ", "))",
                    severity: .info,
                    penalty: 0,
                    url: oginUrl,
                    source: .header,
//                    bitFlags: [.HEADERS_CSP_META_USED]
                ))
            }
        return warnings
    }
}
