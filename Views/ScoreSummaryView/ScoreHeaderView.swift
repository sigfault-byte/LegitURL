//
//  ScoreHeaderView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct ScoreHeaderView: View {
    @Binding var score: Int
    @Binding var hasFinalScore: Bool
    @Binding var isFetchFailure: Bool
    @Binding var isAnalysisComplete: Bool
    
    var scoreColor: Color
    
    let scoreAnimationStarted: Bool
    let flickerText: String
    let flickerColor: Color
    let error: String?
    
    
    var scoreAssessmentText: Text {
            switch score {
            case 81...:
                return Text("This looks safe.")
            case 51...80:
                return Text("This is suspicious.")
            default:
                return Text("⚠️ This looks dangerous.")
            }
        }
    
    var shouldShowErrorMessage: Bool {
        if let error = error, !error.isEmpty {
            return true
        }
        return false
    }
    
    var body: some View {
        HStack{
            VStack{
                Text("Legitimacy Score")
                    .font(.title2)
                if hasFinalScore && !isFetchFailure && isAnalysisComplete {
                    scoreAssessmentText
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .transition(.scale(scale: 0.85, anchor: .center).combined(with: .opacity))
                    .animation(.easeInOut(duration: 0.5), value: hasFinalScore)
                } else if shouldShowErrorMessage && isAnalysisComplete {
                    AnalysisErrorMessageView(error: error!)
                }
            }
            ScoreValueView(
                scoreAnimationStarted: scoreAnimationStarted,
                isFetchFailure: isFetchFailure,
                hasFinalScore: hasFinalScore,
                score: score,
                flickerText: flickerText,
                scoreColor: scoreColor,
                flickerColor: flickerColor
            )
            
        }
        .padding(10)
        .border(.black)
    }
}


//#Preview {
//    ScoreHeaderView(
//        score: 80,
//        scoreColor: .green,
//        hasFinalScore: true,
//        isFetchFailure: false,
//        scoreAnimationStarted: false,
//        flickerText: "x00",
//        flickerColor: .gray
//    )
//}

struct ScoreValueView: View {
    let scoreAnimationStarted: Bool
    let isFetchFailure: Bool
    let hasFinalScore: Bool
    let score: Int
    let flickerText: String
    let scoreColor: Color
    let flickerColor: Color
    
    var body: some View {
        HStack{
            Text(scoreAnimationStarted ? (isFetchFailure ? "x00" : "\(score)") : flickerText)
                .font(.system(size: 80, weight: .black, design: .monospaced))
                .frame(minWidth: 0, maxWidth: .infinity)
                .foregroundColor(
                    scoreAnimationStarted
                    ? (isFetchFailure ? .gray : scoreColor)
                    : flickerColor
                )
                .shadow(color:
                            (scoreAnimationStarted
                             ? (isFetchFailure ? .gray : scoreColor)
                             : flickerColor
                            ).opacity(0.4),
                        radius: 10, x: 0, y: 0
                )
                .frame(minWidth: 80, minHeight: 80)
        }
    }
}

