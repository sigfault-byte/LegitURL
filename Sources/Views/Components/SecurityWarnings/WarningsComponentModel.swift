//  WarningsViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

class WarningsComponentModel: ObservableObject {

    @Published var grouped: [WarningDomainGroup]
    @Published var severityCounts: [SecurityWarning.SeverityLevel: Int] = [:]
    @Published var showingWarningsSheet: Bool = false

    func showWarningsSheet() {
        showingWarningsSheet = true
    }

    init(preGrouped: [WarningDomainGroup]) {
        self.grouped = preGrouped
        computeSeverityCounts()
    }

    
    private func computeSeverityCounts() {
        severityCounts = grouped
            .flatMap { $0.sources }
            .flatMap { $0.severityMap }
            .reduce(into: [:]) { result, entry in
                result[entry.key, default: 0] += entry.value.count
            }
    }
}
