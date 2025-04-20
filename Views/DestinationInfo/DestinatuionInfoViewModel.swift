//
//  DestinatuionInfoViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 02/04/2025.
//
import SwiftUI
class DestinationInfoViewModel: ObservableObject {
    
    @Published var inputDomain: String
    @Published var finalHost: String
    @Published var summaryMessage: String
    @Published var hopCount: Int = 0
    @Published var domainLabel: String
    @Published var tldLabel: String
    @Published var isAnalysisComplete: Bool = false
    
    var displayMessage: Bool {
        return self.isAnalysisComplete && self.summaryMessage.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    init(inputDomain: String,
         finalHost: String,
         summaryMessage: String,
         hopCount: Int,
         domainLabel: String,
         tldLabel: String,
         isAnalysisComplete: Bool = false)
    {
        self.inputDomain = inputDomain
        self.finalHost = finalHost
        self.summaryMessage = summaryMessage
        self.hopCount = hopCount
        self.domainLabel = domainLabel
        self.tldLabel = tldLabel
        self.isAnalysisComplete = isAnalysisComplete
    }
}
