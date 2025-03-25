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

extension URLQueue {
    func addWarning(to urlID: UUID, warning: SecurityWarning) {
        DispatchQueue.main.async {
            if let index = self.offlineQueue.firstIndex(where: { $0.id == urlID }) {
                self.offlineQueue[index].warnings.append(warning)
            } else {
                print("❌ Could not find URLInfo with ID \(urlID) to add warning")
            }
        }
    }
}

/// **Holds structured URL components + associated warnings**
struct URLInfo: Identifiable {
    let id = UUID()
    var components: URLComponentsInfo
    var warnings: [SecurityWarning]
    var processed: Bool = false
    var processedOnline = false
    
    public init(components: URLComponentsInfo, warnings: [SecurityWarning]) {
        self.components = components
        self.warnings = warnings
    }
    
    /// ✅ No private var! We store everything in `URLQueue.shared.onlineQueue`
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
    var isPathEndpointLike: Bool = false
    var query: String?
    var rawQuery: String?
    var queryKeys: [String?] = []
    var queryValues: [String?] = []
    var fragment: String?
    var rawFragment: String?
    var fragmentKeys: [String?] = []
    var fragmentValues: [String?] = []
    
    var extractedDomain: String?
    var idnaEncodedExtractedDomain: String?
    var idnaDecodedExtractedDomain: String?
    var extractedTLD: String?
    var punycodeEncodedExtractedTLD: String?
    var subdomain: String?
    
    var lamaiTrees: [LamaiComponent: DecodedNode] = [:]
    
    
    enum LamaiComponent: String {
        case queryKey
        case queryValue
        case fragmentKey
        case fragmentValue
        case malformedQuery
        case malformedFragment
    }
}

struct OnlineURLInfo: Identifiable {
    let id: UUID
    var httpVersion: String?  // ✅ Store HTTP/1.1, HTTP/2, etc.
    var serverResponseCode: Int?
    var statusText: String?  // ✅ Store "OK", "Not Found", etc.
    var normalizedHeaders: [String: String]?
    var parsedHeaders: ParsedHeaders?  // ✅ Store structured headers
    var responseBody: Data?  // ✅ Store raw response body
    var normalizedCertificate: [String:String] = [:]
    var parsedCertificate: ParsedCertificate?
    var certificateAuthority: String?
    var sslValidity: Bool = false
    var finalRedirectURL: String?
    
    //    Need to be either analysed, or cleaned because it can be way too big!
    var formattedBody: String {
        guard let data = responseBody else { return "No body available" }
        return String(data: data, encoding: .utf8) ?? "⚠️ Unable to decode body"
    }
    
    init(from urlInfo: URLInfo,
         responseCode: Int? = nil,
         statusText: String? = nil,
         normalizedHeaders: [String: String]? = nil,
         parsedHeaders: ParsedHeaders? = nil,  // ✅ New structured headers
         body: Data? = nil,
         certificateAuthority: String? = nil,
         sslValidity: Bool = false,
         finalRedirectURL: String? = nil)
    {
        self.id = urlInfo.id
        self.serverResponseCode = responseCode
        self.statusText = statusText
        self.normalizedHeaders = normalizedHeaders
        self.parsedHeaders = parsedHeaders
        self.responseBody = body
        self.certificateAuthority = certificateAuthority
        self.sslValidity = sslValidity
        self.finalRedirectURL = finalRedirectURL
    }
}

struct ParsedHeaders {
    var securityHeaders: [String: String] = [:]
    var trackingHeaders: [String: String] = [:]
    var serverHeaders: [String: String] = [:]
    var otherHeaders: [String: String] = [:]
}

struct ParsedCertificate {
    var commonName: String?
    var organization: String?
    var issuerCommonName: String?
    var issuerOrganization: String?
    var notBefore: Date?
    var notAfter: Date?
    var publicKeyAlgorithm: String?
    var keyUsage: String?
    var publicKeyBits: Int?
    var extendedKeyUsage: String?
    var isSelfSigned: Bool = false
}
