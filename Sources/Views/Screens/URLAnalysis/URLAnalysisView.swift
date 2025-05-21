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
                    DestinationInfoComponent(viewModel: viewModel.destinationInfoVM)
                    
                    RedirectChainSection(viewModel: viewModel.urlComponentsVM)
                    
                    #if DEBUG
//                    if let html = viewModel.urlQueue.lastGeneratedHTML{
//                        NavigationLink("DEbugReport") {
//                            HTMLDebugPreview(htmlContent: html)
//                        }
//                    }
                    #endif
                    
                    if let html = viewModel.urlQueue.lastGeneratedHTML {
                        Button("Export to PDF") {
                            let generator = PDFReportGenerator()
                            generator.generatePDF(from: html) { data in
                                if let data = data {
                                    let tmpURL = FileManager.default.temporaryDirectory.appendingPathComponent("LegitURL_Report.pdf")
                                    do {
                                        try data.write(to: tmpURL)
                                        generator.sharePDF(url: tmpURL)
                                    } catch {
                                        print("Failed to write PDF: \(error)")
                                    }
                                } else {
                                    print("PDF generation failed.")
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)
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
                
                
                
                // Spacer for warning banner if needed
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
            .listStyle(.insetGrouped)
            .overlay(alignment: .bottom) {
                WarningBannerComponent(viewModel: viewModel.warningsVM)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .zIndex(1)
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
