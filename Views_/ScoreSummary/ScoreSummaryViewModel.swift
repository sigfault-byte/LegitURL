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
    
    @Published var isSynchIsOver: Bool = false {
        didSet {
            displayFlickerOrScore()
            displayAnalysisSumamry()
        }
    }
    
    @Published var errorMessage: [SecurityWarning] {
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
        if !errorMessage.isEmpty {
            let messages = errorMessage.compactMap { $0.message }
            return messages.joined(separator: "\n\n")
        }
        
        switch score {
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

    init(score: Int, isSynchIsOver: Bool, errorMessage: [SecurityWarning] = []) {
        self.score = score
        self.isSynchIsOver = isSynchIsOver
        self.errorMessage = errorMessage
        self.flickerTextLoop()
        self.byteStringLoop()
    }
    
    private func flickerTextLoop() -> Void {
        Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { timer in
            if !self.isSynchIsOver {
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
            if !self.isSynchIsOver {
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
        if !self.isSynchIsOver {
            self.displayScore = self.flickerText
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                if self.errorMessage.isEmpty {
                    self.displayScore = String(self.score)
                } else {
                    self.displayScore = "x00"
                    self.score = 0
                }
            }
        }
    }
    
    private func displayAnalysisSumamry() -> Void {
        if !self.isSynchIsOver {
            self.displayScoreText = "Analysing... \n\(self.byteString)"
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                self.displayScoreText = self.scoreText
            }
        }
    }
}
