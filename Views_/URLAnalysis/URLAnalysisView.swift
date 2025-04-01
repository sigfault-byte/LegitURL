//
//  URLAnalysisView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct URLAnalysisView: View {
    @StateObject private var viewModel: URLAnalysisViewModel
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

                
                RedirectChainSection(viewModel: viewModel.urlComponentsVM)
            }
            .safeAreaInset(edge: .bottom) {
                if viewModel.allSecurityWarnings.isEmpty {
                    HStack {
                        Text("Warnings (\(viewModel.allWarnings.count))")
                            .font(.headline)
                            .foregroundColor(.red)
                            .padding(.vertical, 12)
                            .onTapGesture {
                                showWarningsSheet.toggle()
                            }
                    }
                    .frame(maxWidth: .infinity)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(.ultraThinMaterial)
                            .shadow(color: Color.black.opacity(0.2), radius: 5, x: 0, y: 3)
                    )
                }
            }
            .sheet(isPresented: $showWarningsSheet) {
                SecurityWarningsDetailView(urlQueue: urlQueue)
            }
            .toolbar {
                // Bottom bar for Home & Help
                ToolbarItemGroup(placement: .bottomBar) {
                    HStack {
                        Spacer()
                        Button("🏠 Home from analysis") {
                            onExit()
                        }
                        Spacer()
                        Button("❓ Help") {
                            // TODO: Add help logic
                        }
                        Spacer()
                    }
                }
            }
            
        }
    }
    
}
