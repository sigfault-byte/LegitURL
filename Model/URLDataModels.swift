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
    @Published var isAnalysisComplete: Bool = false
//    @Published var finalSnapshot: FinalAnalysisSnapshot? = nil
    
    @Published var finalCompletionReached: Bool = false
    // i am sorry alan turing
    @Published var activeAsyncCount: Int = 0
    
    /// Dynamically updates with all warnings from `offlineQueue`
    var allWarnings: [SecurityWarning] {
        offlineQueue.flatMap { $0.warnings }
    }
//
    var allWarningsDebug: String {
        offlineQueue
            .flatMap { $0.warnings }
            .map { "• [\($0.severity.rawValue.uppercased())] \($0.message)" }
            .joined(separator: "\n")
    }
    
    var criticalAndFetchErrorWarnings: [SecurityWarning] {
        allWarnings.filter { $0.severity == .critical || $0.severity == .fetchError }
    }
    
    static let shared = URLQueue() // ✅ Singleton to use it globally
}

extension URLQueue {
    // Ensure safe update from the background
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
    
    var lamaiTrees: [TreeType: [DecodedNode]] = [:]
    
    
    enum TreeType: String {
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
    var humanReadableBody: String? = nil
    var humanBodySize: Int? = 0
    var normalizedCertificate: [String:String] = [:]
    var parsedCertificate: ParsedCertificate?
    var certificateAuthority: String?
    var sslValidity: Bool = false
    var finalRedirectURL: String?
    var cookies: [String: String] = [:]
    var cookiesForUI: [CookieAnalysisResult?] = []
    
//    //    Need to be either analysed, or cleaned because it can be way too big!
//    var formattedBody: String {
//        guard let data = responseBody else { return "No body available" }
//        return String(data: data, encoding: .utf8) ?? "⚠️ Unable to decode body"
//    }
    
    init(from urlInfo: URLInfo,
         responseCode: Int? = nil,
         statusText: String? = nil,
         normalizedHeaders: [String: String]? = nil,
         parsedHeaders: ParsedHeaders? = nil,
         body: Data? = nil,
         humanReadableBody: String? = nil,
         humanBodySize: Int? = 0,
         certificateAuthority: String? = nil,
         sslValidity: Bool = false,
         finalRedirectURL: String? = nil,
         cookies: [String:String] = [:],
         cookiesForUI: [CookieAnalysisResult?] = []
    )
    {
        self.id = urlInfo.id
        self.serverResponseCode = responseCode
        self.statusText = statusText
        self.normalizedHeaders = normalizedHeaders
        self.parsedHeaders = parsedHeaders
        self.responseBody = body
        self.humanReadableBody = humanReadableBody
        self.humanBodySize = humanBodySize
        self.certificateAuthority = certificateAuthority
        self.sslValidity = sslValidity
        self.finalRedirectURL = finalRedirectURL
        self.cookies = cookies
        self.cookiesForUI = cookiesForUI
    }
}

struct ParsedHeaders {
    var securityHeaders: [String: String] = [:]
    var trackingHeaders: [String: String] = [:]
    var serverHeaders: [String: String] = [:]
    var otherHeaders: [String: String] = [:]
}

struct ParsedEKU {
    let oid: String
    let shortDescription: String
    let description: String
    let severity: SecurityWarning.SeverityLevel
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
    var extendedKeyUsageOID: String?
    var extendedKeyUsageString: [ParsedEKU]?
    var certificatePolicyOIDs: String?
    var isSelfSigned: Bool = false
    var subjectAlternativeNames: [String]?
    
    var inferredValidationLevel: CertificateValidationLevel {
        guard let oids = certificatePolicyOIDs?.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) else {
            return .unknown
        }
        
        if oids.contains("2.23.140.1.1") {
            return .ev
        } else if oids.contains("2.23.140.1.2.2") {
            return .ov
        } else if oids.contains("2.23.140.1.2.1") {
            return .dv
        } else {
            return .unknown
        }
    }
    
    var mainCertificatePolicy: String? {
        let knownPolicies: [String: String] = [
            "2.23.140.1.1": "Extended Validation",
            "2.23.140.1.2.2": "Organization Validation",
            "2.23.140.1.2.1": "Domain Validation"
        ]

        guard let oids = certificatePolicyOIDs?.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) else {
            return nil
        }

        for oid in oids {
            if let known = knownPolicies[oid] {
                return "\(known) [\(oid)]"
            }
        }

        return oids.first
    }
}

enum CertificateValidationLevel: String {
    case ev = "Extended Validation"
    case ov = "Organization Validation"
    case dv = "Domain Validation"
    case unknown = "Unknown"
}

extension ParsedCertificate {
    var formattedEKU: String? {
        guard let ekuList = extendedKeyUsageString else { return nil }
        return ekuList.map { "\($0.shortDescription) [\($0.oid)]" }.joined(separator: "\n")
    }
}
