//
//  AnalysisContextManager.swift
//  URLChecker
//
//  Created by Chief Hakka on 20/04/2025.
//
struct AnalysisStateReset {
    static func reset() {
        URLQueue.shared.cookiesSeenByRedirectChain.removeAll()
        URLQueue.shared.offlineQueue.removeAll()
        URLQueue.shared.onlineQueue.removeAll()
        URLQueue.shared.groupedWarnings.removeAll()
        
        URLQueue.shared.legitScore.score = 100
        TLSCertificateAnalyzer.resetMemory()
        
        AnalysisEngine.hasManuallyStopped = false
        AnalysisEngine.hasFinalized = false
    }
}


//   Reset Checklist
// - All queues: offlineQueue, onlineQueue
// - Score + flags: legitScore.score, legitScore.analysisCompleted
// - Warnings: groupedWarnings -> pure UI
// - Cookie memory: cookiesSeenByRedirectChain
// - TLS cache: TLSCertificateAnalyzer.resetMemory()
// - Async flags: hasManuallyStopped, hasFinalized
