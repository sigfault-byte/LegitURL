//
//  SecurityWarningTriage.swift
//  LegitURL
//
//  Created by Chief Hakka on 03/06/2025.
//
struct SecurityWarningTriage {
    static func getRelevantSecurityWarnings(for urlInfo: URLInfo,
                                            with sources: [SecurityWarning.SourceType]) -> [[String: String]] {
        
        // use only relevant / related source and filter out info to prevent noise
        let relevant = urlInfo.warnings.filter {
            sources.contains($0.source.normalizedType)
            && $0.severity != .info
        }
        
        let mapped: [[String: String]] = relevant.map {
            [
                // this sucks
                "01_signal": $0.machineMessage.isEmpty ? $0.message : $0.machineMessage,
                "02_source": $0.source.displayLabel.lowercased()
            ]
        }
        return mapped.isEmpty ? [] : mapped
    }
    
    public static func generateWarningJson(urls: URLQueue) -> [String: Any] {
        var urlKeyMap: [String: String] = [:]
        var findingsByUrl: [String: [String: [String]]] = [:]

        for (index, url) in urls.offlineQueue.enumerated() {
            guard let coreURL = url.components.fullURL else { continue }
            let key = "url\(index + 1)"
            urlKeyMap[key] = coreURL

            let relevantFindings = url.warnings
                .filter { $0.severity != .info }
                .sorted { $0.penalty > $1.penalty }

            guard !relevantFindings.isEmpty else { continue }

            var grouped: [String: [String]] = [:]
            for warning in relevantFindings {
                let sourceKey = warning.source.displayLabel.lowercased()
                grouped[sourceKey, default: []].append(warning.message)
            }

            findingsByUrl[key] = grouped
        }

        return [
            "idMap": urlKeyMap,
            "findingsByUrls": findingsByUrl
        ]
    }
}
