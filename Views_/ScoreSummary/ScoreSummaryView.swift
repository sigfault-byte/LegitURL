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
            VStack {
                HStack(alignment: .center) {
                    
                    VStack(alignment: .trailing) {
                        Text("Legit Score")
                            .font(.title)
                            .multilineTextAlignment(.trailing)
                    }
                    .frame(maxWidth: .infinity)
                    
                    Rectangle()
                        .frame(width: 1, height: 70)
                        .foregroundColor(.gray)
                    
                    Text(viewModel.displayScore)
                        .frame(maxWidth: .infinity)
                        .font(.system(size: 70, weight: .black, design: .monospaced))
                        .foregroundColor(viewModel.isSynchIsOver ? viewModel.scoreColor : viewModel.flickerColor)
                }
                Text(viewModel.displayScoreText)
                    .font(.subheadline)
                    .multilineTextAlignment(.center)
                
            }
        }
    }
}
