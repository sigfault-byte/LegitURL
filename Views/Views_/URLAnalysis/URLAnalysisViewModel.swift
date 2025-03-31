//
//  URLAnalysisViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

class URLAnalysisViewModel: ObservableObject {
    @Published var urlQueue = URLQueue.shared
    @Published var analysisStarted: Bool = false
    var urlInput: String
    var infoMessage: String
    @Published var showInfoMessage = true
    @Published var infoOpacity: Double = 1.0

    //ModelViews to populate
    @Published var scoreSummaryVM = ScoreSummaryViewModel(
        score: 100,
        isAnalysisComplete: false,
        errorMessage: ""
    )
    @Published var URLComponentsVM = URLComponentsViewModel(
        urlInfo: [URLInfo.placeholder],
        onlineInfo: [OnlineURLInfo(from: URLInfo.placeholder)],
        isAnalysisComplete: false
    )
    
    // Timer for pooling
    private var timer: Timer?

    init(urlInput: String, infoMessage: String) {
        self.urlInput = urlInput
        self.infoMessage = infoMessage
        startAnalysis()
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

        // Pooling data
        timer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.updateAnalysisState()
            
            if self.urlQueue.isAnalysisComplete {
                self.stopAnalysis()
            }
        }
    }
    
    //Assigning pooled data
    private func updateAnalysisState() {
        scoreSummaryVM.score = urlQueue.LegitScore
        scoreSummaryVM.isAnalysisComplete = urlQueue.isAnalysisComplete
        scoreSummaryVM.errorMessage = "" //Place holder in the meantime
        
        URLComponentsVM.isAnalysisComplete = urlQueue.isAnalysisComplete
        URLComponentsVM.urlInfo = Array(urlQueue.offlineQueue)
        URLComponentsVM.onlineInfo = Array(urlQueue.onlineQueue)
    }

    func stopAnalysis() {
        timer?.invalidate()
        timer = nil
    }
}
