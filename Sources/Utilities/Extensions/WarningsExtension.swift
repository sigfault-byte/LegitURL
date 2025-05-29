//
//  WarningsExtension.swift
//  LegitURL
//
//  Created by Chief Hakka on 29/05/2025.
//
extension SecurityWarning.SeverityLevel {
    var sortRank: Int {
        switch self {
        case .critical: return 0
        case .dangerous: return 1
        case .scam: return 2
        case .suspicious: return 3
        case .tracking: return 4
        case .good: return 5
        case .info: return 6
        case .fetchError: return 7
        }
    }
}
