//
//  AnalysisContextManager.swift
//  URLChecker
//
//  Created by Chief Hakka on 20/04/2025.
//
struct AnalysisContextManager {
    static func reset() {
        URLQueue.shared.cookiesSeenByRedirectChain.removeAll()
        URLQueue.shared.offlineQueue.removeAll()
        URLQueue.shared.onlineQueue.removeAll()
        URLQueue.shared.legitScore.score = 100
        TLSCertificateAnalyzer.resetMemory()
//        LegitRedirectMemory.reset()
//        LegitTimingContext.reset()
        
        URLAnalyzer.hasManuallyStopped = false
        URLAnalyzer.hasFinalized = false
    }
}
//public static func resetQueue() {
//    URLQueue.shared.cookiesSeenByRedirectChain.removeAll()
//    URLQueue.shared.offlineQueue.removeAll()
//    URLQueue.shared.onlineQueue.removeAll()
//    URLQueue.shared.legitScore.score = 100
//    TLSCertificateAnalyzer.resetMemory()
//    hasManuallyStopped = false
//    hasFinalized = false
//}
