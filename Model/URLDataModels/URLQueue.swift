//  URLDataModels.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import Foundation
import SwiftUI

/// **Holds all structured data models for URL processing**
class URLQueue: ObservableObject {
    @Published var offlineQueue: [URLInfo] = []
    @Published var onlineQueue: [OnlineURLInfo] = []
    @Published var legitScore = ScoreUpdateModel()
    
    //    seen cookies set to not double penalyze same cookie keys because we have a fresh get each time
    var cookiesSeenByRedirectChain: [UUID: Set<String>] = [:]
    
//    // i am sorry alan turing
//    @Published var activeAsyncCount: Int = 0
    
    
    /// Dynamically updates with all warnings from `offlineQueue`
    var allWarnings: [SecurityWarning] {
        offlineQueue.flatMap { $0.warnings }
    }
//
    var allWarningsDebug: String {
        offlineQueue
            .flatMap { $0.warnings }
            .map { "• [\($0.severity.rawValue.uppercased())] \($0.message)" }
            .joined(separator: "\n")
    }
  
    
    var criticalAndFetchErrorWarnings: [SecurityWarning] {
        allWarnings.filter { $0.severity == .critical || $0.severity == .fetchError }
    }
    
    static let shared = URLQueue() // ✅ Singleton to use it globally
}

final class ScoreUpdateModel: ObservableObject {
    @Published var score: Int
    @Published var analysisCompleted: Bool

    init(score: Int = 100, analysisCompleted: Bool = false) {
        self.score = score
        self.analysisCompleted = analysisCompleted
    }
}

extension URLQueue {
    // Ensure safe update from the background
    func addWarning(to urlID: UUID, warning: SecurityWarning) {
        if let index = self.offlineQueue.firstIndex(where: { $0.id == urlID }) {
            self.offlineQueue[index].warnings.append(warning)
        } else {
            print("❌ Could not find URLInfo with ID \(urlID) to add warning")
        }
    }
}
