//
//  WarningsViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

class WarningsViewModel: ObservableObject {
    @Published var warnings: [SecurityWarning] = []
    
    // warning view
    @Published var showWarningsSheet: Bool = false
    
    // warning details
    @Published var expandedDomains: Set<String> = []
    @Published var expandedSections: Set<String> = []
    
    var groupedByDomain: [String: [SecurityWarning]] {
        Dictionary(grouping: warnings, by: { $0.url })
    }
        
    init(warnings: [SecurityWarning]) {
        self.warnings = warnings
        print("🧠 WarningsViewModel INIT — count: \(warnings.count)")
            warnings.forEach {
                print(" - [\($0.url)] \($0.message)")
            }
    }
    
    static var allSeverityLevels: [SecurityWarning.SeverityLevel] {
        return [.critical, .dangerous, .scam, .suspicious, .tracking, .info, .fetchError]
    }
    
    func sourceDescription(_ source: SecurityWarning.SourceType) -> String {
        switch source {
        case .offlineAnalysis:
            return "Offline"
        case .onlineAnalysis:
            return "Online"
        case .redirectedURL(let hop):
            return "Redirected (Hop \(hop + 1))"
        }
    }
    
    func sortWarningSourceTypes(_ lhs: SecurityWarning.SourceType, _ rhs: SecurityWarning.SourceType) -> Bool {
        switch (lhs, rhs) {
        case (.offlineAnalysis, .onlineAnalysis), (.offlineAnalysis, .redirectedURL):
            return true
        case (.onlineAnalysis, .redirectedURL):
            return true
        case (.redirectedURL(let lHop), .redirectedURL(let rHop)):
            return lHop < rHop
        default:
            return false
        }
    }
}

