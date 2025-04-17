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
            case .tracking: return Color.gray
            case .suspicious: return Color.orange
            case .scam: return Color.purple
            case .dangerous: return Color.red
            case .critical: return Color.red.opacity(0.8)
            case .fetchError: return Color.black
            }
        }
    }
    
    enum SourceType: Hashable {
        case host
        case path
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
