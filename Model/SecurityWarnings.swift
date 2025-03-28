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
//            case info = "INFO"
//            case tracking = "TRACKING"
//            case scam = "SCAM"
//            case suspicious = "SUSPICIOUS"
//            case dangerous = "DANGEROUS"
//            case critical = "CRITICAL"
//            case urlGetFail = "GETFAILED"
//        }
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


// MARK: - TODO: Better Warning Structure & UX

/*
1. Add a `source` field to `SecurityWarning`:
    enum SourceType {
        case offlineAnalysis
        case onlineHeaders
        case redirectedURL(hop: Int)
    }

2. In the UI, group warnings based on source:
    - Offline Findings
    - Online Findings
    - Redirect 1 → ...
    - Final Destination

3. Update the GET explanation on the URL component view:
    - "GET requests are made without query or fragment for privacy."

4. Optional (later): Expand SeverityLevel
    - Add `.tracking`, `.scam`, maybe `.sslIssue`

5. Visualize the full redirect chain with GET target highlighted.

This will drastically improve clarity for both average users and security folks.
*/
