import SwiftUI

struct URLAnalysisResultView: View {
    var urlInput: String
    var infoMessage: String?
    @Binding var isAnalyzing: Bool
    
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var urlQueue = URLQueue.shared
    
    @State private var showInfoMessage = true
    @State private var showAnimated = false
    @State private var hasAnalyzed = false
    @State private var showWarningsSheet = false
    
    var body: some View {
        ZStack(alignment: .bottom) {
            // Main content in a NavigationView
            NavigationView {
                List {
                    // Info Message Section
                    if showInfoMessage, let message = infoMessage, !message.isEmpty {
                        Section {
                            Text("ℹ️ \(message)")
                                .font(.footnote)
                                .foregroundColor(.gray)
                        }
                    }
                    
                    // Analysis Summary Section
                    Section {
                        ScoreSummaryView(urlQueue: urlQueue, analysisStarted: $showAnimated)
                            .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 0, trailing: 0))
                    }
                    
                    // Hop List Section
                    Section(header: Text("Redirect chain")) {
                        ForEach(urlQueue.offlineQueue) { urlInfo in
                            NavigationLink(destination: URLDetailView(
                                urlInfo: urlInfo,
                                onlineInfo: urlQueue.onlineQueue.first(where: { $0.id == urlInfo.id })
                            )) {
                                // This label automatically gets the system row styling
                                Label(urlInfo.components.host ?? "Unknown Host", systemImage: "network")
                            }
                        }
                    }
                    
                    // Analysis Status Section
                    Section {
                        if !urlQueue.isAnalysisComplete {
                            Text("Analysis still in progress...")
                                .font(.footnote)
                                .foregroundColor(.gray)
                        } else {
                            Text("Analysis complete.")
                                .font(.footnote)
                                .foregroundColor(.green)
                        }
                    }
                }
                .listStyle(InsetGroupedListStyle())
                .navigationTitle("Analysis Result")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    // Bottom bar for Home & Help
                    ToolbarItemGroup(placement: .bottomBar) {
                        HStack {
                            Spacer()
                            Button("🏠 Home") {
                                LegitSessionManager.reset()
                                isAnalyzing = false
                                dismiss()
                            }
                            Spacer()
                            Button("❓ Help") {
                                // TODO: Add help logic
                            }
                            Spacer()
                        }
                    }
                }
                .onAppear {
                    if !hasAnalyzed {
                        hasAnalyzed = true
                        URLAnalyzer.analyze(urlString: urlInput)
                        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                            showInfoMessage = false
                        }
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                            showAnimated = true
                        }
                    }
                }
            }
            
            // "Mini-player" style bar above bottom toolbar
            if !urlQueue.allWarnings.isEmpty {
                HStack {
                    Text("⚠️ Security Warnings (\(urlQueue.allWarnings.count))")
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
                .padding(.horizontal)
                .padding(.bottom, 50)
                .transition(.move(edge: .bottom))
                .zIndex(1)
                .sheet(isPresented: $showWarningsSheet) {
                    SecurityWarningsDetailView(urlQueue: urlQueue)
                }
            }
        }
    }
}
