//  URLAnalyzerUtils.swift
//  URLChecker
//
//  Created by Chief Hakka on 09/04/2025.
//
struct URLAnalyzerUtils {
    static func computeFinalScore(for urlInfos: [URLInfo]) -> Int {
        let warnings = urlInfos.flatMap { $0.warnings }
//        let penaltyDetails = warnings.map { "Source: \($0.source) - Penalty: \($0.penalty)" }

        let totalPenalty = warnings.map { $0.penalty }.reduce(0, +)
        
        var newScore = 100 + totalPenalty
        if newScore < 0 {
            newScore = 0
        } else if newScore > 100 {
            newScore = 100
        }
        let score = newScore
        return score
    }

    static func finalizeAnalysis() {
        let finalScore = computeFinalScore(for: URLQueue.shared.offlineQueue)
        URLQueue.shared.legitScore.score = finalScore
//        URLQueue.shared.legitScore.analysisCompleted = true
    }
}
