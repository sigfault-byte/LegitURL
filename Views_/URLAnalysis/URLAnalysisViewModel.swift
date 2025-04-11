//
//  URLAnalysisViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

@MainActor
class URLAnalysisViewModel: ObservableObject {
    
    // Core Inputs:
    var urlInput: String
    var infoMessage: String
    
    // Analysis State:
    @Published var analysisStarted: Bool = false
    
    // UI State:
    @Published var showInfoMessage = true
    @Published var infoOpacity: Double = 1.0
    @Published var showingWarningsSheet : Bool = false
    
    // Data Models:
    @Published var warningsGroupedByURL: [URLWarningGroup] = []
    
    // Child ViewModels:
    @Published var scoreSummaryVM = ScoreSummaryViewModel(
        legitScore: URLQueue.shared.legitScore,
        errorMessage: nil
    )
    @Published var urlComponentsVM = URLComponentsViewModel(
        urlInfo: [URLInfo.placeholder],
        onlineInfo: [OnlineURLInfo(from: URLInfo.placeholder)],
        isAnalysisComplete: false
    )
    
    @Published var destinationInfoVM = DestinationInfoViewModel(
        inputDomain: "",
        finalHost: "",
        finalHostPunycode: "",
        hopCount: 0,
        domainLabel: "",
        tldLabel: ""
    )
    
    var urlQueue = URLQueue.shared
    
    var allSecurityWarningsCount: Int {
        warningsGroupedByURL.reduce(0) { $0 + $1.warnings.count }
    }

    // Timer for pooling
    private var timer: Timer?
    
    init(urlInput: String, infoMessage: String) {
        self.urlInput = urlInput
        self.infoMessage = infoMessage
        Task {
            await self.startAnalysis()
        }
    }
    
    func filterErrorMessageAndPopulateScoreSummaryVM() -> Void {
        let filteredWarnings = urlQueue.criticalAndFetchErrorWarnings
        self.scoreSummaryVM.errorMessage = filteredWarnings.map { $0.message }
    }
    
    func startAnalysis() async {
        if !analysisStarted {
            analysisStarted = true
            await URLAnalyzer.analyze(urlString: urlInput)
        }
        self.scoreSummaryVM.startFlicker()
        
        // Info banner delay animation
        try? await Task.sleep(nanoseconds: 3 * 1_000_000_000)
        withAnimation(.easeInOut(duration: 1)) {
            self.infoOpacity = 0.3
        }
        try? await Task.sleep(nanoseconds: 1 * 1_000_000_000)
        withAnimation(.easeInOut(duration: 1)) {
            self.showInfoMessage = false
        }

        // Final analysis update
        while !self.urlQueue.legitScore.analysisCompleted {
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            self.updateAnalysisState()
        }

        try? await Task.sleep(nanoseconds: 500_000_000) // final defer

        self.updateAnalysisState()
        self.populateDestinationVM()
         // Call startFlicker after initialization
    }
    
    //Assigning pooled data
    private func updateAnalysisState() {
        let structuredGroups = self.urlQueue.offlineQueue.map {
            URLWarningGroup(urlInfo: $0, warnings: $0.warnings)
        }
        self.warningsGroupedByURL = structuredGroups
        
        self.urlComponentsVM.isAnalysisComplete = self.urlQueue.legitScore.analysisCompleted
        self.urlComponentsVM.urlInfo = self.urlQueue.offlineQueue
        self.urlComponentsVM.onlineInfo = self.urlQueue.onlineQueue
        
    }
    
    func showWarningsSheet() -> Void {
        self.showingWarningsSheet = true
    }
    
    func populateDestinationVM() -> Void {
        self.destinationInfoVM.inputDomain = self.urlQueue.offlineQueue.first?.components.fullURL ?? ""
        self.destinationInfoVM.finalHost = self.urlQueue.offlineQueue.last?.components.coreURL ?? ""
        self.destinationInfoVM.finalHostPunycode = self.urlQueue.offlineQueue.last?.components.punycodeHostEncoded ?? ""
        self.destinationInfoVM.hopCount = self.urlQueue.offlineQueue.count
        self.destinationInfoVM.domainLabel = self.urlQueue.offlineQueue.last?.components.extractedDomain ?? ""
        self.destinationInfoVM.tldLabel = self.urlQueue.offlineQueue.last?.components.extractedTLD ?? ""
    }
}
