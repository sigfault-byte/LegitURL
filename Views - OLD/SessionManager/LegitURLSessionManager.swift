//
//  LegitURLSessionManager.swift
//  URLChecker
//
//  Created by Chief Hakka on 28/03/2025.
//
import Foundation

struct LegitSessionManager {
    static func reset() {
        URLQueue.shared.offlineQueue.removeAll()
        URLQueue.shared.onlineQueue.removeAll()
        URLQueue.shared.LegitScore = 100
        URLQueue.shared.isAnalysisComplete = false
    }
}
