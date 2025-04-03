//
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
    var url: String
    var source: SourceType
    
    init(message: String, severity: SeverityLevel, url: String, source: SourceType) {
            self.id = UUID()
            self.message = message
            self.severity = severity
            self.url = url
            self.source = source
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
        case offlineAnalysis
        case onlineAnalysis
        case redirectedURL(hop: Int)
    }
}
// ✅ Update SeverityLevel to support sorting & icons
extension SecurityWarning.SeverityLevel: CaseIterable {
    static var allWarnings: [SecurityWarning.SeverityLevel] {
        return [.critical, .dangerous, .scam, .suspicious, .tracking, .info, .fetchError]
    }
}
