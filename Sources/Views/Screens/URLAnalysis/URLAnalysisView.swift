//
//  URLAnalysisView.swift
//  LegitURL
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct URLAnalysisView: View {
    @StateObject private var viewModel: URLAnalysisViewModel
    @State private var showHelpPage = false
    @State private var showCopyJSONPage = false
    
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
                
                ScoreSummaryComponent(viewModel: viewModel.scoreSummaryVM)
                
                
                
                if viewModel.isAnalysisComplete {
                    
                    WarningSummaryComponent(viewModel: viewModel.warningsVM)

                    DestinationInfoComponent(viewModel: viewModel.destinationInfoVM)
                    
                    Section {
                        Button(action: {
                            showCopyJSONPage = true
                        }) {
                            HStack {
                                Spacer()
                                Text("Explain the score in your favorite AI")
                                    .foregroundColor(.blue)
                                Spacer()
                                Image(systemName: "square.and.arrow.up.on.square")
                                    .foregroundColor(.blue)
                            }
                            .padding(.vertical, 8)
                        }
                        .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 16))
                    }
                    
                    RedirectChainSection(viewModel: viewModel.urlComponentsVM)
                    
                    Section(header: Text("report")) {
                        if let html = viewModel.urlQueue.lastGeneratedHTML{
                            NavigationLink("View full Report") {
                                HTMLReportPreview(htmlContent: html, domain: viewModel.urlQueue.offlineQueue.last?.components.extractedDomain ?? "")
                            }
                        }
                    }
                    
                }
                else {
                    HStack {
                        Spacer()
                        VStack {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .gray))
                                .scaleEffect(2.0)
                                .padding()
                            Text("Analyzing…")
                                .foregroundColor(.gray)
                                .font(.footnote)
                        }
                        Spacer()
                    }
                }
                
                // Spacer for warning banner if needed no needed anymore, but let s test
                if !viewModel.warningsVM.grouped.isEmpty {
                    Section {
                        Color.clear
                            .frame(height: 80)
                            .listRowBackground(Color.clear)
                            .listRowInsets(EdgeInsets())
                    }
                }
            }
            .navigationBarHidden(true)
//            .listStyle(.insetGrouped)
//            .overlay(alignment: .bottom) {
//                WarningBannerComponent(viewModel: viewModel.warningsVM)
//                    .transition(.move(edge: .bottom).combined(with: .opacity))
//                    .zIndex(1)
//            }
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
            .navigationDestination(isPresented: $showCopyJSONPage) {
                CopyJSONInfoView()
            }
        }
    }
}
