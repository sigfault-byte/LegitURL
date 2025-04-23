//
//  URLAnalysisViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

@MainActor
class URLAnalysisViewModel: ObservableObject {
    // core singleton
    var urlQueue = URLQueue.shared
    
    // Core Inputs:
    var urlInput: String
    var infoMessage: String
    
    // Analysis State:
    @Published var analysisStarted: Bool = false
    
    // UI State:
    @Published var showInfoMessage = true
    @Published var infoOpacity: Double = 1.0
    @Published var showingWarningsSheet : Bool = false
    
    // Child Comp:
    @Published var scoreSummaryVM = ScoreSummaryComponentModel(
        legitScore: URLQueue.shared.legitScore,
        isAnalysisComplete: false
    )
    @Published var urlComponentsVM = URLComponentsViewModel(
        urlInfo: [URLInfo.placeholder],
        onlineInfo: [OnlineURLInfo(from: URLInfo.placeholder)],
        isAnalysisComplete: false
    )
    
    @Published var destinationInfoVM = DestinationInfoComponentModel(
        inputDomain: "",
        finalHost: "",
        summaryMessage: "",
        hopCount: 0,
        domainLabel: "",
        tldLabel: "",
        isAnalysisComplete: false,
        score: 0
    )
    
    @Published var warningsVM = WarningsComponentModel(
        preGrouped: []
    )
    
    var isAnalysisComplete: Bool {
        return destinationInfoVM.isAnalysisComplete &&
               urlComponentsVM.isAnalysisComplete &&
               scoreSummaryVM.isAnalysisComplete &&
               !warningsVM.grouped.isEmpty
    }
    
    
    init(urlInput: String, infoMessage: String) {
        self.urlInput = urlInput
        self.infoMessage = infoMessage
        let scoreVM = ScoreSummaryComponentModel(
            legitScore: URLQueue.shared.legitScore,
            isAnalysisComplete: false
        )
        scoreVM.startFlicker()
        self.scoreSummaryVM = scoreVM
        Task {
            await self.startAnalysis()
        }
    }
    
    
    func startAnalysis() async {
        if !analysisStarted {
            analysisStarted = true
            await AnalysisEngine.analyze(urlString: urlInput)
        }
        self.updateAnalysisState()
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2 * 1_000_000_000)
            withAnimation(.easeInOut(duration: 1)) {
                self.infoOpacity = 0.3
            }
            try? await Task.sleep(nanoseconds: 1 * 500_000_000)
            withAnimation(.easeInOut(duration: 1)) {
                self.showInfoMessage = false
            }
        }
        
    }
    
    //Assigning pooled data
    private func updateAnalysisState() {
        self.warningsVM = WarningsComponentModel(preGrouped: self.urlQueue.groupedWarnings)
        populateDestinationVM()
        self.urlComponentsVM.urlInfo = self.urlQueue.offlineQueue
        self.urlComponentsVM.onlineInfo = self.urlQueue.onlineQueue
        self.urlComponentsVM.isAnalysisComplete = self.urlQueue.legitScore.analysisCompleted
        self.scoreSummaryVM.legitScore = self.urlQueue.legitScore
        self.scoreSummaryVM.isAnalysisComplete = self.urlQueue.legitScore.analysisCompleted
    }
    
    func showWarningsSheet() -> Void {
        self.showingWarningsSheet = true
    }
    
    func populateDestinationVM() -> Void {
        self.destinationInfoVM.inputDomain = self.urlQueue.offlineQueue.first?.components.fullURL ?? ""
        self.destinationInfoVM.finalHost = self.urlQueue.offlineQueue.last?.components.fullURL ?? ""
        self.destinationInfoVM.summaryMessage =  ""
        self.destinationInfoVM.hopCount = self.urlQueue.offlineQueue.count - 1
        self.destinationInfoVM.domainLabel = self.urlQueue.offlineQueue.last?.components.extractedDomain ?? ""
        self.destinationInfoVM.tldLabel = self.urlQueue.offlineQueue.last?.components.extractedTLD ?? ""
        self.destinationInfoVM.isAnalysisComplete = self.urlQueue.legitScore.analysisCompleted
        self.destinationInfoVM.score = self.urlQueue.legitScore.score
    }
}
