//
//  ScoreSummaryViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

@MainActor
class ScoreSummaryViewModel: ObservableObject{
    
    @ObservedObject var legitScore: ScoreUpdateModel
    
    @Published var errorMessage: [String]? = nil {
        didSet {
            if self.legitScore.analysisCompleted && errorMessage != nil {
                displayFlickerOrScore()
            }
        }
    }
    
    @Published var shouldShowDivider: Bool = true
    
    var displayError: Bool = false
    
    @Published var labelText: String = "Legit Score"
    
    var flickerText: String = "00"
    var flickerColor: Color = .gray
    
    @Published var displayScore: String = ""
    @Published var displayScoreText: String = ""

    var scoreColor: Color {
        if legitScore.score >= 80 {
            return .green
        } else if legitScore.score > 50 {
            return .orange
        } else {
            return .red
        }
    }
    
    var scoreText: String {
        if self.errorMessage != [] {
            if let messages = self.errorMessage {
                self.shouldShowDivider = false
                return messages.joined(separator: "\n\n")
            }
        }
        
        switch legitScore.score {
        case ..<50:
            return "The URL might try to trick you."
        case 50..<60:
            return "The URL is suspicious."
        case 60..<80:
            return "The URL might be suspicious."
        case 80...:
            return "The URL looks safe."
        default:
            return "Analysis incomplete."
        }
    }
    
    init(legitScore: ScoreUpdateModel, errorMessage: [String]?) {
        self.legitScore = legitScore
        self.errorMessage = errorMessage
        
    }
    
    func startFlicker() {
        self.flickerTextLoop()
        Task {
            try await Task.sleep(nanoseconds: 800_000_000)
            self.displayFlickerOrScore()
        }
    }
    
    private func flickerTextLoop() {
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
            Task { @MainActor in
                if !self.legitScore.analysisCompleted {
                    let hex = String(format: "%02X", Int.random(in: 0...255))
                    self.flickerText = hex
                    let colors: [Color] = [.gray, .cyan, .orange, .purple, .yellow, .blue]
                    self.flickerColor = colors.randomElement() ?? .gray
                } else {
                    timer.invalidate()
                }
            }
        }
    }
    
    private func displayFlickerOrScore() -> Void {
        if !self.legitScore.analysisCompleted {
            self.displayScore = self.flickerText
        } else {
            withAnimation {
                self.labelText = "Legit Score"
                self.displayScore = String(self.legitScore.score)
            }
        }
    }
}
