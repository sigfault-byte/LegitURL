//  SecurityWarnings.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/03/2025.
//
/// **Represents a security warning associated with a URL**
import Foundation
import SwiftUI

struct SecurityWarning: Identifiable{
    let id: UUID
    var message: String
    var severity: SeverityLevel
    var penalty: Int
    var url: String
    var source: SourceType
    var bitFlags: WarningFlags
    
    init(message: String, severity: SeverityLevel, penalty: Int, url: String, source: SourceType, bitFlags: WarningFlags? = nil) {
        self.id = UUID()
        self.message = message
        self.severity = severity
        self.penalty = penalty
        self.url = url
        self.source = source
        self.bitFlags = bitFlags ?? []
        }

    /// **Represents severity levels for warnings**
    enum SeverityLevel: String {
        case info = "INFO"
        case tracking = "TRACKING"
        case suspicious = "SUSPICIOUS"
        case scam = "SCAM"
        case dangerous = "DANGEROUS"
        case critical = "CRITICAL"
        case fetchError = "FETCH_ERROR"
        
        /// Returns a color for UI representation
        var color: Color {
            switch self {
            case .info: return Color.blue
            case .tracking: return Color.purple
            case .suspicious: return Color.orange
            case .scam: return Color(red: 0.6, green: 0, blue: 0.2)
            case .dangerous: return Color.red
            case .critical: return Color(red: 0.4, green: 0, blue: 0)
            case .fetchError: return Color.black
            }
        }
    }
    
    enum SourceType: Hashable {
        case host
        case path
        case pathSub(label: String)
        case query
        case fragment
        case cookie
        case header
        case body
        case tls
        case getError
        case redirect
        case responseCode
    }
}
// ✅ Update SeverityLevel to support sorting & icons
extension SecurityWarning.SeverityLevel: CaseIterable {
    static var allWarnings: [SecurityWarning.SeverityLevel] {
        return [.critical, .dangerous, .scam, .suspicious, .tracking, .info, .fetchError]
    }
}

extension SecurityWarning.SeverityLevel {
    var iconName: String {
        switch self {
        case .info:
            return "info.circle"
        case .tracking:
            return "dot.radiowaves.left.and.right"
        case .suspicious:
            return "exclamationmark.circle"
        case .scam:
            return "xmark.octagon"
        case .dangerous:
            return "exclamationmark.triangle"
        case .critical:
            return "exclamationmark.triangle.fill"
        case .fetchError:
            return "questionmark.circle"
        }
    }

    var iconColor: Color {
        return self.color
    }
}

extension SecurityWarning.SourceType {
    var normalizedType: SecurityWarning.SourceType {
        switch self {
        case .pathSub: return .path
        default: return self
        }
    }
}

/// Struct for the view
struct WarningDomainGroup: Identifiable {
    let id = UUID()
    let domain: String
    let sources: [WarningSourceGroup]
}

struct WarningSourceGroup: Identifiable {
    let id = UUID()
    let source: SecurityWarning.SourceType
    let severityMap: [SecurityWarning.SeverityLevel: [SecurityWarning]]
}

extension SecurityWarning.SourceType {
    var displayLabel: String {
        switch self {
        case .host: return "Host"
        case .path: return "Path"
        case .pathSub(let label): return "Path (\(label))"
        case .query: return "Query"
        case .fragment: return "Fragment"
        case .cookie: return "Cookie"
        case .header: return "Header"
        case .body: return "Body"
        case .tls: return "TLS"
        case .getError: return "Fetch Error"
        case .redirect: return "Redirect"
        case .responseCode: return "Response Code"
        }
    }
    
    var glossaryID: String {
            switch self {
            case .host: return "host"
            case .path, .pathSub: return "path"
            case .query: return "query"
            case .fragment: return "fragment"
            case .cookie: return "cookie"
            case .header: return "header"
            case .body: return "body"
            case .tls: return "tls"
            case .getError: return "getError"
            case .redirect: return "redirect"
            case .responseCode: return "responseCode"
            }
        }
}
