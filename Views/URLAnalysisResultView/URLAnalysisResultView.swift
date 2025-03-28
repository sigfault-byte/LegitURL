//
//  URLAnalysisResultView.swift
//  URLChecker
//
//  Created by Chief Hakka on 28/03/2025.
//
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
        VStack(spacing: 0) {
            ScrollView {
                VStack {

                    if showInfoMessage, let message = infoMessage, !message.isEmpty {
                        Text("ℹ️ \(message)")
                            .font(.footnote)
                            .foregroundColor(.gray)
                    }
                    // Placeholder: Add ScoreSummaryView or other analysis components here
                    ScoreSummaryView(urlQueue: urlQueue, analysisStarted: $showAnimated)
                    // Example ScoreSummaryView
                    // ScoreSummaryView(score: someScore)

                    // Using the new HopListView
                    HopListView(urlQueue: urlQueue)
                    if !urlQueue.isAnalysisComplete {
                        Text("⏳ Full analysis still in progress...")
                            .font(.footnote)
                            .foregroundColor(.gray)
                            .padding(.bottom, 4)
                    } else {
                        Text("✅ Full analysis complete.")
                            .font(.footnote)
                            .foregroundColor(.green)
                            .padding(.bottom, 4)
                    }
                }
                .padding()
            }

            Spacer()
            Button(action: {
                showWarningsSheet.toggle()
            }) {
                Text("⚠️ Security Warnings (\(urlQueue.allWarnings.count))")
                    .font(.headline)
                    .foregroundColor(.red)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color(.systemGray6)))
                    .padding(.horizontal)
            }
            .sheet(isPresented: $showWarningsSheet) {
                SecurityWarningsDetailView(urlQueue: urlQueue)
            }
//----------------------------------MENU-------------------------------------------
            HStack {
                Spacer()
                Button("🏠 Home") {
                    LegitSessionManager.reset()           // Optional: reset your shared data
                    isAnalyzing = false
                    dismiss()
                }
                Spacer()
                Button("❓ Help") {
                    // TODO: Add help logic
                }
                Spacer()
            }
            .padding()
//            ---------------------END MENU--------------------------------------------
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
}


//struct URLAnalysisResultView_Preview: PreviewProvider {
//    static var previews: some View {
//        URLAnalysisResultView(urlInput: "https://test.com", infoMessage: nil, isAnalyzing: .constant(true))
//    }
//}
