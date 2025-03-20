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
    let id: UUID = UUID()
    var message: String
    var severity: SeverityLevel
    var url: String?
    
    /// **Represents severity levels for warnings**
    enum SeverityLevel: String {
        case info = "INFO"
        case suspicious = "SUSPICIOUS"
        case dangerous = "DANGEROUS"
        case critical = "CRITICAL"
        case urlGetFail = "GETFAILED"
        
//        TODO REFACTOR:
//        enum SeverityLevel: String {
//            case info = "INFO"               // ✅ Stays the same
//            case tracking = "TRACKING"       // 🔍 NEW: For tracking/fingerprinting
//            case phishingScam = "SCAM"       // 🔍 NEW: For phishing & scam detection
//            case dangerous = "DANGEROUS"      // ✅ Stays the same
//            case critical = "CRITICAL"        // ✅ Stays the same, includes failed GETs
//        }
        
        /// Returns a color for UI representation
        var color: Color {
            switch self {
            case .info: return Color.blue
            case .suspicious: return Color.orange
            case .dangerous: return Color.red
            case .critical: return Color.red.opacity(0.8)
            case .urlGetFail: return Color.red
            }
        }
    }
}
