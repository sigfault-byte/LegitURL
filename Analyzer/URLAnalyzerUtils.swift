//
//  URLAnalyzerUtils.swift
//  URLChecker
//
//  Created by Chief Hakka on 09/04/2025.
//
struct URLAnalyzerUtils {
    static func computeFinalScore(for urlInfos: [URLInfo]) -> Int {
        let warnings = urlInfos.flatMap { $0.warnings }
        let penaltyDetails = warnings.map { "Source: \($0.source) - Penalty: \($0.penalty)" }
        print("Penalty details: \(penaltyDetails)")
        let totalPenalty = warnings.map(\.penalty).reduce(0, +)
        print("Total penalty: \(totalPenalty)")
        return max(0, 100 - totalPenalty)
    }

    static func finalizeAnalysis() {
        let finalScore = computeFinalScore(for: URLQueue.shared.offlineQueue)
        URLQueue.shared.legitScore.score = finalScore
        URLQueue.shared.legitScore.analysisCompleted = true
    }
}
