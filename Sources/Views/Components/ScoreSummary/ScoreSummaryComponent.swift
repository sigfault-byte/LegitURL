//
//  ScoreSummaryView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct ScoreSummaryComponent: View {
    @ObservedObject var viewModel: ScoreSummaryComponentModel
    
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
                    
                    dividerView
                    
                    Text(viewModel.isAnalysisComplete ? "\(viewModel.legitScore.score)" : viewModel.flickerScore)
                        .frame(maxWidth: .infinity)
                        .font(.system(size: 70, weight: .black, design: .monospaced))
                        .foregroundColor(viewModel.isAnalysisComplete ? viewModel.scoreColor : viewModel.flickerColor)
                    Spacer()
                }
            }
        }
    }
    
    @ViewBuilder
    private var dividerView: some View {
            Rectangle()
                .frame(width: 1, height: 70)
                .foregroundColor(.gray)
                .transition(.opacity)
    }
}
