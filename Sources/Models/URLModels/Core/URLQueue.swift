//  URLDataModels.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import Foundation
import SwiftUI

/// holds all structured data models for URL processing
class URLQueue: ObservableObject {
    @Published var offlineQueue: [URLInfo] = []
    @Published var onlineQueue: [OnlineURLInfo] = []
    @Published var legitScore = ScoreUpdateModel()
    @Published var groupedWarnings: [WarningDomainGroup] = []
    @Published var summary: String = ""
    
    var lastGeneratedHTML: String? = nil
    
    
    
    //    seen cookies set to not double penalyze same cookie keys because we have a fresh get each time
    var cookiesSeenByRedirectChain: [UUID: Set<String>] = [:]
    
    static let shared = URLQueue() // Singleton to use it globally
}

final class ScoreUpdateModel: ObservableObject {
    @Published var score: Int
    @Published var analysisCompleted: Bool
    @Published var specialFlag: SpecialFlags

    init(score: Int = 100, analysisCompleted: Bool = false) {
        self.score = score
        self.analysisCompleted = analysisCompleted
        self.specialFlag = []
    }
}

