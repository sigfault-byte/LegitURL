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
    @Published var score = URLQueue.shared.LegitScore
    @Published var isAnalysisComplete = false
    @Published var finalCompletionReached = URLQueue.shared.finalCompletionReached
    @Published var isSynchIsOver: Bool = false
    @Published var allSecurityWarnings: [SecurityWarning] = []
    
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
            
            if self.urlQueue.finalCompletionReached {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    self.updateAnalysisState()
                    self.allSecurityWarnings = self.urlQueue.allWarnings
                    self.filterErrorMessage()
                    self.populateDestinationVM()
                    self.isSynchIsOver = true
                    self.stopAnalysis()
                }
            }
        }
    }
//     TAsk is the real player, but this cascade into a will smith @mainactor movie
//            Task {
//                while !self.urlQueue.isAnalysisComplete {
//                    self.updateAnalysisState()
//                    try? await Task.sleep(nanoseconds: 400_000_000)
//                }
//    
//                // Final update and state sync
//                self.updateAnalysisState()
//                self.stopAnalysis()
//                self.populateDestinationVM()
//                self.filterErrorMessage()
//                self.isSynchIsOver = true
//            }
//        }
    
    
    //Assigning pooled data
    private func updateAnalysisState() {
        self.isAnalysisComplete = self.urlQueue.isAnalysisComplete
        self.allSecurityWarnings = self.urlQueue.allWarnings
        
        self.scoreSummaryVM.score = self.urlQueue.LegitScore
        self.scoreSummaryVM.isSynchIsOver = self.urlQueue.finalCompletionReached
        
        self.urlComponentsVM.isAnalysisComplete = self.urlQueue.finalCompletionReached
        self.urlComponentsVM.urlInfo = self.urlQueue.offlineQueue
        self.urlComponentsVM.onlineInfo = self.urlQueue.onlineQueue
        
        
    }
    
    func stopAnalysis() {
        self.timer?.invalidate()
        self.timer = nil
    }
    
    func showWarningsSheet() -> Void {
        self.showingWarningsSheet = true
    }
}
