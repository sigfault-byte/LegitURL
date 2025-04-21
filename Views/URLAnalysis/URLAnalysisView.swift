//
//  URLAnalysisView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct URLAnalysisView: View {
    @StateObject private var viewModel: URLAnalysisViewModel
    @State private var showHelpPage = false
    
    let onExit: () -> Void
    
    init(urlInput: String, infoMessage: String, onExit: @escaping () -> Void) {
        self.onExit = onExit
        self._viewModel = StateObject(wrappedValue: URLAnalysisViewModel(urlInput: urlInput, infoMessage: infoMessage))
    }
    
    var body: some View {
        NavigationStack {
            List {
                if viewModel.showInfoMessage && !viewModel.infoMessage.isEmpty {
                    Section(header: Text("Info message")) {
                        Text("\(viewModel.infoMessage)")
                            .font(.footnote)
                            .foregroundColor(.gray)
                            .opacity(viewModel.infoOpacity)
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                }

                ScoreSummaryView(viewModel: viewModel.scoreSummaryVM)

                DestinationInfoView(viewModel: viewModel.destinationInfoVM)
                
                RedirectChainSection(viewModel: viewModel.urlComponentsVM)
                
            }
            .listStyle(.insetGrouped)
            .safeAreaInset(edge: .bottom) {
                WarningBannerComponent(viewModel: viewModel.warningsVM)
            }
            .toolbar {
                // Bottom bar for Home & Help
                ToolbarItemGroup(placement: .bottomBar) {
                    BottomToolbar(lButtonIcon: "🏠", lButtonText: "Home", lButtonAction: {onExit()},
                                  rButtonIcon: "❓", rButtonText: "Help", rButtonAction: {showHelpPage = true})
                }
            }
            .navigationDestination(isPresented: $showHelpPage) {
                HelpPageView(scrollTarget: nil)
            }
            
        }
    }
    
}
