import SwiftUI

struct URLAnalysisResultView: View {
    let urlInput: String
    let infoMessage: String
    // Function to root to the other view
    let onExit: () -> Void
    
    @ObservedObject var urlQueue = URLQueue.shared
    
    @State private var showInfoMessage = true
    @State private var showWarningsSheet = false
    @State private var didStartAnalysis = false
    @State private var infoOpacity: Double = 1.0
    
    var body: some View {
        NavigationStack {
            List {
                if showInfoMessage && !infoMessage.isEmpty {
                    Section(header: Text("Info message")) {
                        Text("\(infoMessage)")
                            .font(.footnote)
                            .foregroundColor(.gray)
                            .opacity(infoOpacity)
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                }
                
                // Analysis Summary Section
                Section {
                    ScoreSummaryViewOLD()
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
            }
            .navigationTitle("Analysis Result")
            .navigationBarTitleDisplayMode(.inline)
            .listStyle(InsetGroupedListStyle())
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
            // Use safeAreaInset to insert the mini-player above the bottom toolbar
            .safeAreaInset(edge: .bottom) {
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
                }
            }
            .sheet(isPresented: $showWarningsSheet) {
                SecurityWarningsDetailView(urlQueue: urlQueue)
            }
        }
        .task {
            guard !didStartAnalysis else { return }
            didStartAnalysis = true
            
            URLAnalyzer.analyze(urlString: urlInput)
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                withAnimation(.easeInOut(duration: 1)) {
                    infoOpacity = 0.3
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    withAnimation(.easeInOut(duration: 1)) {
                        showInfoMessage = false
                    }
                }
            }
        }
    }
}
