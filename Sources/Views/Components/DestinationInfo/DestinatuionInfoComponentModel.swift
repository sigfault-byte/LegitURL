//
//  DestinatuionInfoViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 02/04/2025.
//
import SwiftUI

class DestinationInfoComponentModel: ObservableObject {
//    Placeholder to wait for the real deal
    @Published var loadingDots: String
    
    @Published var inputDomain: String
    @Published var finalHost: String {
        didSet {
            self.punycodeMissmatch = self.finalHost.contains("xn--")
        }
    }
    @Published var summaryMessage: String
    @Published var hopCount: Int = 0
    @Published var domainLabel: String
    @Published var tldLabel: String
    @Published var score: Int
    
    @Published var isAnalysisComplete: Bool = false
    
    var punycodeMissmatch: Bool = false
    var summaryTitle: String {
        if score >= 70 {
            return "The destination appears to be legit"
        } else if score > 40 {
            return "There are some potential issues, stay cautious"
        } else {
            return "The destination should not be trusted"
        }
    }
    
    var displayMessage: Bool {
        return self.isAnalysisComplete && !self.summaryMessage.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    init(
         inputDomain: String,
         finalHost: String,
         summaryMessage: String,
         hopCount: Int,
         domainLabel: String,
         tldLabel: String,
         isAnalysisComplete: Bool = false,
         score: Int)
    {
        self.loadingDots = "."
        self.inputDomain = ""
        self.finalHost = finalHost
        self.summaryMessage = summaryMessage
        self.hopCount = hopCount
        self.domainLabel = domainLabel
        self.tldLabel = tldLabel
        self.isAnalysisComplete = isAnalysisComplete
        self.score = score
        
        
        Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
            if self.isAnalysisComplete {
                timer.invalidate()
                return
            }

            if self.loadingDots.count >= 25 {
                self.loadingDots = "."
            } else {
                self.loadingDots += "."
            }
        }
    }
    
    var scoreColor: Color {
        switch self.score {
        case 80...100:
            return .green
        case 50..<80:
            return .orange
        default:
            return .red
        }
    }
}
