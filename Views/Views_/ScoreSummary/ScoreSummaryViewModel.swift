//
//  ScoreSummaryViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

class ScoreSummaryViewModel: ObservableObject{
    
    @Published var score: Int = 100 {
        didSet {
            displayFlickerOrScore()
        }
    }
    
    @Published var isAnalysisComplete: Bool = false {
        didSet {
            displayFlickerOrScore()
            displayAnalysisSumamry()
        }
    }
    
    @Published var errorMessage: String? {
        didSet {
            displayAnalysisSumamry()
        }
    }
    var flickerText: String = "00"
    var flickerColor: Color = .gray
    var byteString: String = "00000000"
    
    @Published var displayScore: String = ""
    @Published var displayScoreText: String = ""
    
    var scoreColor: Color {
        if score >= 80 {
            return .green
        } else if score > 50 {
            return .orange
        } else {
            return .red
        }
    }
    
    var scoreText: String {
        switch (score, errorMessage) {
        case (_, let msg?) where !msg.isEmpty:
            return msg
            
        case (..<50, _):
            return "The URL might try to trick you."
        case (50..<60, _):
            return "The URL is suspicious."
        case (60..<80, _):
            return "The URL might be suspicious."
        case (80..., _):
            return "The URL looks safe."
            
        default:
            return "Analysis incomplete."
        }
    }

    init(score: Int, isAnalysisComplete: Bool, errorMessage: String? = nil) {
        self.score = score
        self.isAnalysisComplete = isAnalysisComplete
        self.errorMessage = errorMessage
        self.flickerTextLoop()
        self.byteStringLoop()
    }
    
    private func flickerTextLoop() -> Void {
        Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { timer in
            if !self.isAnalysisComplete {
                let hex = String(format: "%02X", Int.random(in: 0...255))
                self.flickerText = hex
                let colors: [Color] = [.gray, .cyan, .orange, .purple, .yellow, .blue]
                self.flickerColor = colors.randomElement() ?? .gray

            } else {
                timer.invalidate()
            }
        }
    }
    
    private func byteStringLoop() -> Void {
        Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { timer in
            if !self.isAnalysisComplete {
                let randomByte = Int.random(in: 0...255)
                let binary = String(randomByte, radix: 2)
                let padded = String(repeating: "0", count: 8 - binary.count) + binary
                self.byteString = padded
                
            } else {
                timer.invalidate()
            }
        }
    }
    
    private func displayFlickerOrScore() -> Void {
            if !self.isAnalysisComplete {
                self.displayScore = self.flickerText
            } else {
                self.displayScore = String(self.score)
            }
    }
    
    private func displayAnalysisSumamry() -> Void {
        if !self.isAnalysisComplete {
            self.displayScoreText = "Analysing... \n\(self.byteString)"
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        self.displayScoreText = self.scoreText
                    }
        }
    }
}
