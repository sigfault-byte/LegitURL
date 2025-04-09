//
//  URLMain.swift
//  URLChecker
//
//  Created by Chief Hakka on 08/04/2025.
//
import Foundation

struct URLInfo: Identifiable {
    let id = UUID()
    var components: URLComponentsInfo
    var warnings: [SecurityWarning]
    var processed: Bool = false
    var processedOnline = false
    var processingNow: Bool = false
    
    public init(components: URLComponentsInfo, warnings: [SecurityWarning]) {
        self.components = components
        self.warnings = warnings
    }
    
    var onlineInfo: OnlineURLInfo? {
        get { URLQueue.shared.onlineQueue.first { $0.id == self.id } }
        set {
            if let newValue = newValue {
                if let index = URLQueue.shared.onlineQueue.firstIndex(where: { $0.id == newValue.id }) {
                    URLQueue.shared.onlineQueue[index] = newValue
                } else {
                    URLQueue.shared.onlineQueue.append(newValue)
                }
            }
        }
    }
}

extension URLInfo {
    var domain: String? { components.extractedDomain }
    var tld: String? { components.extractedTLD }
    var host: String? { components.host }
}

extension URLInfo {
    static var placeholder: URLInfo {
        URLInfo(
            components: URLComponentsInfo(fullURL: "https://placeholder.url"),
            warnings: []
        )
    }
}
