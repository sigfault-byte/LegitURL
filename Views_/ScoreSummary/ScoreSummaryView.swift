//
//  ScoreSummaryView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct ScoreSummaryView: View {
    @ObservedObject var viewModel: ScoreSummaryViewModel
    @State private var localDisplayScore: String = "••"
    @State private var localDisplayScoreText: String = "Analysing ... \n00101010"
    
    var body: some View {
        Section {
            VStack(alignment: .center) {
                HStack(alignment: .center) {
                    Spacer()
                    VStack(alignment: .trailing) {
                        Text(viewModel.labelText)
                            .font(viewModel.useTitleFont ? .title : .system(size: 70, weight: .black, design: .monospaced))
                            .multilineTextAlignment(.trailing)
                    }
                    .frame(maxWidth: viewModel.shouldShowDivider ? .infinity : nil)
                    .animation(.easeOut(duration: 0.25), value: viewModel.shouldShowDivider)
                    
                    dividerView
                    
                    Text(viewModel.displayScore.isEmpty ? localDisplayScore : viewModel.displayScore)
                        .frame(maxWidth: viewModel.shouldShowDivider ? .infinity : nil)
                        .animation(.easeOut(duration: 0.25), value: viewModel.shouldShowDivider)
                        .font(.system(size: 70, weight: .black, design: .monospaced))
                        .foregroundColor(viewModel.isSynchIsOver ? viewModel.scoreColor : viewModel.flickerColor)
                Spacer()
                }
                
                Text(viewModel.displayScoreText.isEmpty ? localDisplayScoreText : viewModel.displayScoreText)
                    .font(.subheadline)
                    .multilineTextAlignment(.center)
                
            }
        }
    }
    
    @ViewBuilder
    private var dividerView: some View {
        if viewModel.shouldShowDivider {
            Rectangle()
                .frame(width: 1, height: 70)
                .foregroundColor(.gray)
                .transition(.opacity)
        }
    }
}


