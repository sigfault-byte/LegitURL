//
//  HotDogWaterViewModel.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//
import Foundation
import SwiftUI

struct FindingSummary {
    let message: String
    let count: Int
    let color: Color
}

func summarizeFindings(_ findings: [(message: String, severity: SecurityWarning.SeverityLevel)]) -> [FindingSummary] {
    var summaryDict: [String: (count: Int, color: Color)] = [:]

    for finding in findings {
        let message = finding.message
        let color = finding.severity.color

        if let existing = summaryDict[message] {
            summaryDict[message] = (existing.count + 1, color)
        } else {
            summaryDict[message] = (1, color)
        }
    }

    return summaryDict.map { key, value in
        FindingSummary(message: key, count: value.count, color: value.color)
    }
}
