//  WarningsViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

class WarningsViewModel: ObservableObject {
    let groupedByURL: [URLWarningGroup]
    
    // warning view
    @Published var showWarningsSheet: Bool = false
    @Published var groupedWarnings: [GroupedWarningViewModel] = []
    // warning details
    @Published var expandedDomains: Set<String> = []
    @Published var expandedSections: Set<String> = []
    
    init(groupedByURL: [URLWarningGroup]) {
        self.groupedByURL = groupedByURL
        self.groupedWarnings = Self.buildGroupedWarnings(from: groupedByURL)
    }
    
    func sourceDescription(_ source: SecurityWarning.SourceType) -> String {
        switch source {
        case .host: return "Host"
        case .path: return "Path"
        case .query: return "Query"
        case .fragment: return "Fragment"
        case .cookie: return "Cookie"
        case .header: return "Header"
        case .body: return "Body"
        case .tls: return "TLS"
        case .getError: return "Connection Error"
        case .redirect: return "Redirect"
        case .responseCode: return "Response Code"
        }
    }
    
    private static func buildGroupedWarnings(from groups: [URLWarningGroup]) -> [GroupedWarningViewModel] {
        groups.map { group in
            let groupedBySource = Dictionary(grouping: group.warnings, by: { $0.source })
            
            let sourceGroups = groupedBySource.map { (source, warningsForSource) in
                let groupedBySeverity = Dictionary(grouping: warningsForSource, by: { $0.severity })
                
                let severityGroups = groupedBySeverity.map { (severity, warningsInGroup) in
                    GroupedWarningViewModel.SeverityGroup(
                        severity: severity,
                        warnings: warningsInGroup
                    )
                }.sorted(by: { $0.severity.rawValue > $1.severity.rawValue })
                
                return GroupedWarningViewModel.SourceGroup(
                    source: source,
                    severities: severityGroups
                )
            }.sorted { (lhs: GroupedWarningViewModel.SourceGroup, rhs: GroupedWarningViewModel.SourceGroup) in
                let order: [SecurityWarning.SourceType] = [
                    .host, .path, .query, .fragment, .cookie, .header, .body, .tls, .responseCode, .redirect, .getError
                ]
                return (order.firstIndex(of: lhs.source) ?? Int.max) < (order.firstIndex(of: rhs.source) ?? Int.max)
            }
            
            return GroupedWarningViewModel(
                url: group.urlInfo.components.coreURL ?? "",
                sources: sourceGroups
            )
        }
    }
    
    func sortWarningSourceTypes(_ lhs: SecurityWarning.SourceType, _ rhs: SecurityWarning.SourceType) -> Bool {
        let order: [SecurityWarning.SourceType] = [
            .host, .path, .query, .fragment, .cookie, .header, .body, .tls, .responseCode, .redirect, .getError
        ]
        return (order.firstIndex(of: lhs) ?? Int.max) < (order.firstIndex(of: rhs) ?? Int.max)
    }
}
struct GroupedWarningViewModel: Identifiable {
    let id = UUID()
    let url: String
    let sources: [SourceGroup]

    struct SourceGroup: Identifiable {
        let id = UUID()
        let source: SecurityWarning.SourceType
        let severities: [SeverityGroup]
    }

    struct SeverityGroup: Identifiable {
        let id = UUID()
        let severity: SecurityWarning.SeverityLevel
        let warnings: [SecurityWarning]
    }
}

struct URLWarningGroup: Identifiable {
    let id = UUID()
    let urlInfo: URLInfo
    let warnings: [SecurityWarning]
}
