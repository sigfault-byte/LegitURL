//
//  ScoreSummaryView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct ScoreSummaryView: View {
    @ObservedObject var viewModel: ScoreSummaryViewModel
    
    var body: some View {
        Section {
            VStack(alignment: .center) {
                HStack(alignment: .center) {
                    Spacer()
                    VStack(alignment: .trailing) {
                        Text(viewModel.labelText)
                            .font(.title)
                            .multilineTextAlignment(.trailing)
                    }
                    .frame(maxWidth: viewModel.shouldShowDivider ? .infinity : nil)
                    .animation(.easeOut(duration: 0.25), value: viewModel.shouldShowDivider)
                    
                    dividerView
                    
                    Text(viewModel.displayScore)
                        .frame(maxWidth: viewModel.shouldShowDivider ? .infinity : nil)
                        .animation(.easeOut(duration: 0.25), value: viewModel.shouldShowDivider)
                        .font(.system(size: 70, weight: .black, design: .monospaced))
                        .foregroundColor(viewModel.legitScore.analysisCompleted ? viewModel.scoreColor : viewModel.flickerColor)
                Spacer()
                }
                
                Text(viewModel.displayScoreText)
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
