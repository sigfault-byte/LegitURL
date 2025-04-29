//
//  ScoreSummaryViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

class ScoreSummaryComponentModel: ObservableObject{
    
    @Published var legitScore: ScoreUpdateModel
    
    @Published var isAnalysisComplete: Bool = false
    
    @Published var labelText: String = "Legit Score"
    
    @Published var flickerScore: String = "00"
    @Published var flickerColor: Color = .gray
    private var flickerTimer: Timer?

    var scoreColor: Color {
        if legitScore.score >= 70 {
            return .green
        } else if legitScore.score > 40 {
            return .orange
        } else {
            return .red
        }
    }
    
    init(legitScore: ScoreUpdateModel, isAnalysisComplete: Bool = false) {
        self.legitScore = legitScore
        self.isAnalysisComplete = isAnalysisComplete
    }
    
    

    func startFlicker() {
        flickerTimer?.invalidate()
        flickerTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            if self.isAnalysisComplete {
                self.flickerTimer?.invalidate()
                return
            }
            let byte = Int.random(in: 0...255)
            self.flickerScore = String(format: "%02X", byte)
            self.flickerColor = Color(hue: Double.random(in: 0...1), saturation: 0.8, brightness: 0.9)
        }
    }
    
}
