//
//  URLAnalysisViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

class URLAnalysisViewModel: ObservableObject {
    var urlQueue = URLQueue.shared
    @Published var analysisStarted: Bool = false
    @Published var isAnalysisComplete = URLQueue.shared.legitScore.analysisCompleted
    
    var allSecurityWarningsCount: Int {
        warningsGroupedByURL.reduce(0) { $0 + $1.warnings.count }
    }
    @Published var isSynchIsOver: Bool = false
    
    @Published var warningsGroupedByURL: [URLWarningGroup] = []
    
    var urlInput: String
    var infoMessage: String
    
    @Published var showInfoMessage = true
    @Published var infoOpacity: Double = 1.0
    @Published var liveLegitScore: Int = 0
    
    @Published var showingWarningsSheet : Bool = false
    
    //ModelViews to populate
    @Published var scoreSummaryVM = ScoreSummaryViewModel(
        score: 100,
        isSynchIsOver: false,
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
    
    func populateDestinationVM() -> Void {
        self.destinationInfoVM.inputDomain = self.urlQueue.offlineQueue.first?.components.host ?? ""
        self.destinationInfoVM.finalHost = self.urlQueue.offlineQueue.last?.components.host ?? ""
        self.destinationInfoVM.finalHostPunycode = self.urlQueue.offlineQueue.last?.components.punycodeHostEncoded ?? ""
        self.destinationInfoVM.hopCount = self.urlQueue.offlineQueue.count
        self.destinationInfoVM.domainLabel = self.urlQueue.offlineQueue.last?.components.extractedDomain ?? ""
        self.destinationInfoVM.tldLabel = self.urlQueue.offlineQueue.last?.components.extractedTLD ?? ""
    }
    
    // Timer for pooling
    private var timer: Timer?
    
    init(urlInput: String, infoMessage: String) {
        self.urlInput = urlInput
        self.infoMessage = infoMessage
        self.startAnalysis()
    }
    
    func filterErrorMessage() -> Void {
        let filteredWarnings = urlQueue.criticalAndFetchErrorWarnings
        self.scoreSummaryVM.errorMessage = filteredWarnings.map { $0.message }
    }
    
    func startAnalysis() {
        if !analysisStarted {
            analysisStarted = true
            URLAnalyzer.analyze(urlString: urlInput)
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            withAnimation(.easeInOut(duration: 1)) {
                self.infoOpacity = 0.3
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                withAnimation(.easeInOut(duration: 1)) {
                    self.showInfoMessage = false
                }
            }
        }
        
        // Pooling data, this is ugly but necessary before refactoring struct to class, there is a "lag" when pooling data, defering the stop is necessary
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.updateAnalysisState()
            
            if self.isAnalysisComplete {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    self.updateAnalysisState()
                    self.filterErrorMessage()
                    self.populateDestinationVM()
                    self.isSynchIsOver = true
                    self.stopAnalysis()
                }
            }
        }
    }
    
    //Assigning pooled data
    private func updateAnalysisState() {
        self.isAnalysisComplete = self.urlQueue.legitScore.analysisCompleted
        let structuredGroups = self.urlQueue.offlineQueue.map {
            URLWarningGroup(urlInfo: $0, warnings: $0.warnings)
        }
        self.warningsGroupedByURL = structuredGroups
        
        
        self.scoreSummaryVM.score = self.urlQueue.legitScore.score
        self.scoreSummaryVM.isSynchIsOver = self.urlQueue.legitScore.analysisCompleted
        
        self.urlComponentsVM.isAnalysisComplete = self.urlQueue.legitScore.analysisCompleted
        self.urlComponentsVM.urlInfo = self.urlQueue.offlineQueue
        self.urlComponentsVM.onlineInfo = self.urlQueue.onlineQueue
        print("Score in view: ",self.scoreSummaryVM.score)
        
    }
    
    func stopAnalysis() {
        self.timer?.invalidate()
        self.timer = nil
    }
    
    func showWarningsSheet() -> Void {
        self.showingWarningsSheet = true
    }
    
}
