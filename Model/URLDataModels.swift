//  URLDataModels.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import Foundation
import SwiftUI

/// **Holds all structured data models for URL processing**
class URLQueue: ObservableObject {
    @Published var offlineQueue: [URLInfo] = []
    @Published var onlineQueue: [OnlineURLInfo] = []
    @Published var LegitScore: Int = 100
    
    /// Dynamically updates with all warnings from `offlineQueue`
    var allWarnings: [SecurityWarning] {
        offlineQueue.flatMap { $0.warnings }
    }
    
    static let shared = URLQueue() // ✅ Singleton to use it globally
}

/// **Holds structured URL components + associated warnings**
struct URLInfo: Identifiable {
    let id = UUID()
    var components: URLComponentsInfo
    var warnings: [SecurityWarning]
    var processed: Bool = false
    var processedOnline = false
}

/// **Holds extracted URL parts**

struct URLComponentsInfo {
    var fullURL: String?
    var scheme: String?
    var userinfo: String?
    var userPassword: String?
    var host: String?
    var punycodeHostDecoded: String? // Punycode → Unicode
    var punycodeHostEncoded: String? // ASCII → Punycode
    var port: String?
    var path: String?
    var pathEncoded: String? // True path with proper encoding, handled by urlcomponent
    var query: String?
    var rawQuery: String?
    var queryKeys: [String?] = []
    var queryValues: [String?] = []
    var fragment: String?
    var rawFragment: String?
    var fragmentKeys: [String?] = []
    var fragmentValues: [String?] = []
    
    var extractedDomain: String?
    var punyCodeEncodedExtractedDomain: String?
    var punyCodeDecodedExtractedDomain: String?
    var extractedTLD: String?
    var punycodeEncodedExtractedTLD: String?
    var subdomain: String?
}

struct OnlineURLInfo: Identifiable {
    let id: UUID
    var serverResponseCode: Int?
    var certificateAuthority: String?
    var sslValidity: Bool = false
    var finalRedirectURL: String?
    var responseHeaders: [String: String]?
    
    var formattedHeaders: String {
        responseHeaders?.map { "\($0.key): \($0.value)" }.joined(separator: "\n") ?? "No headers available"
    }

    init(from urlInfo: URLInfo, responseCode: Int? = nil, cert: String? = nil, sslValid: Bool = false, redirect: String? = nil, headers: [String: String]? = nil) {
        self.id = urlInfo.id
        self.serverResponseCode = responseCode
        self.certificateAuthority = cert
        self.sslValidity = sslValid
        self.finalRedirectURL = redirect
        self.responseHeaders = headers
    }
}
