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
    @Published var isAnalysisComplete: Bool = false
    @Published var isSynchIsOver: Bool = false
    @Published var allSecurityWarnings: [SecurityWarning] = []
    
    var urlInput: String
    var infoMessage: String
    @Published var showInfoMessage = true
    @Published var infoOpacity: Double = 1.0
    @Published var liveLegitScore: Int = 0

    //ModelViews to populate
    @Published var scoreSummaryVM = ScoreSummaryViewModel(
        score: 100,
        isSynchIsOver: false,
        errorMessage: []
    )
    @Published var urlComponentsVM = URLComponentsViewModel(
        urlInfo: [URLInfo.placeholder],
        onlineInfo: [OnlineURLInfo(from: URLInfo.placeholder)],
        isAnalysisComplete: false
    )
    
    // Timer for pooling
    private var timer: Timer?

    init(urlInput: String, infoMessage: String) {
        self.urlInput = urlInput
        self.infoMessage = infoMessage
        self.startAnalysis()
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
        timer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.updateAnalysisState()
            
            if self.urlQueue.isAnalysisComplete {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    self.stopAnalysis()
                    self.updateAnalysisState()
                    self.scoreSummaryVM.errorMessage = self.urlQueue.criticalAndFetchErrorWarnings
                    self.isSynchIsOver = true
                }
            }
        }
    }
    
    
    //Assigning pooled data
    private func updateAnalysisState() {
        self.isAnalysisComplete = self.urlQueue.isAnalysisComplete
        self.allSecurityWarnings = self.urlQueue.allWarnings
        
        self.scoreSummaryVM.score = self.urlQueue.LegitScore
        self.scoreSummaryVM.isSynchIsOver = self.urlQueue.isAnalysisComplete

        self.urlComponentsVM.isAnalysisComplete = self.urlQueue.isAnalysisComplete
        self.urlComponentsVM.urlInfo = self.urlQueue.offlineQueue
        self.urlComponentsVM.onlineInfo = self.urlQueue.onlineQueue
        
        
    }

    func stopAnalysis() {
        self.timer?.invalidate()
        self.timer = nil
    }
}
