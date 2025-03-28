//
//  URLAnalyzerView.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI
struct URLAnalyzerView: View {
    @State private var urlText: String = ""
    @State private var infoMessage: String? = nil
    @State private var analysisStarted: Bool = false
    @ObservedObject var urlQueue: URLQueue = .shared

    var body: some View {
        NavigationStack {  // ✅ Wrap everything in NavigationStack
            ScrollView {
                VStack(spacing: 16) {
                    URLInputView(urlText: $urlText, infoMessage: $infoMessage, analysisStared: $analysisStarted)

                    if let infoMessage = infoMessage {
                        Text(infoMessage)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .transition(.opacity)
                            .animation(.easeInOut(duration: 0.5), value: infoMessage)
                    }

                    Button("Check URL") {
                        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                        analysisStarted = true
                        URLAnalyzer.analyze(urlString: urlText, infoMessage: &infoMessage)
                    }
                    .buttonStyle(.borderedProminent)
                    
                    Divider()
                    
                    ScoreSummaryView(urlQueue: urlQueue, analysisStarted: $analysisStarted)

                    Spacer()
                    
                    if urlQueue.offlineQueue.count > 0 {
                        Divider()
                        URLComponentsListView(urlQueue: urlQueue)
                    }

                    Divider()
                    SecurityWarningsView(urlQueue: urlQueue)
                }
                .padding()
            }
            .dismissKeyboardOnTap()
        }
    }
}
