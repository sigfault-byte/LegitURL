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
        
        /// Returns a color for UI representation
        var color: Color {
            switch self {
            case .info: return Color.blue
            case .suspicious: return Color.orange
            case .dangerous: return Color.red
            case .critical: return Color.red.opacity(0.8)
            }
        }
    }
}
