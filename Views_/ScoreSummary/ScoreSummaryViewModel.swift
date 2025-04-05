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
            self.displayFlickerOrScore()
        }
    }
    
    @Published var isSynchIsOver: Bool = false {
        didSet {
            self.displayFlickerOrScore()
        }
    }
    
    @Published var errorMessage: [String]? = nil {
        didSet {
            if isSynchIsOver && errorMessage != nil {
                displayAnalysisSummary()
            }
        }
    }
    
    @Published var shouldShowDivider: Bool = true
    
    var displayError: Bool = false
    
    @Published var labelText: String = "0x"
    
    @Published var useTitleFont: Bool = false
    
    var flickerText: String = "00"
    var flickerColor: Color = .gray
    var byteString: String = "00101010"
    
    @Published var displayScore: String = ""
    @Published var displayScoreText: String = ""
    
    @Published var isInFlickerPhase: Bool = true
    
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
        if self.errorMessage != [] {
            if let messages = self.errorMessage {
                self.shouldShowDivider = false
                return messages.joined(separator: "\n\n")
            }
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
    
    init(score: Int, isSynchIsOver: Bool, errorMessage: [String]?) {
        self.score = score
        self.isSynchIsOver = isSynchIsOver
        self.errorMessage = nil
        
        // Run loops first
        self.flickerTextLoop()
        self.byteStringLoop()
        
        // Immediately generate initial values
        self.flickerText = String(format: "%02X", Int.random(in: 0...255))
        let randomByte = Int.random(in: 0...255)
        let binary = String(randomByte, radix: 2)
        self.byteString = String(repeating: "0", count: 8 - binary.count) + binary
        
        // Delay exiting flicker phase for visual consistency
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
            self.isInFlickerPhase = false
            self.displayFlickerOrScore()
            self.displayAnalysisSummary()
        }
    }
    
    private func flickerTextLoop() -> Void {
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
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
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
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
        if !self.isSynchIsOver || self.isInFlickerPhase {
            self.displayScore = self.flickerText
        } else {
            withAnimation {
                if  self.isSynchIsOver {
                    self.labelText = "Legit Score"
                    self.useTitleFont = true
                    self.displayScore = String(self.score)
                } else {
                    if self.score != 0 {
                        self.score = 0
                    }
                    self.displayScore = "00"
                }
            }
        }
    }
    
    private func displayAnalysisSummary() -> Void {
        if !self.isSynchIsOver || self.isInFlickerPhase {
            self.displayScoreText = "Analysing ... \n\(self.byteString)"
        } else {
            Timer.scheduledTimer(withTimeInterval: 1, repeats: false){_ in withAnimation {
                self.displayScoreText = self.scoreText
            }
            }
        }
    }
}
