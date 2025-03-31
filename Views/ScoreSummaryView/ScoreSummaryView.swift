//
//  ScoreSummaryView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
//import SwiftUI
//
//struct ScoreSummaryView: View {
//    // Main object
//    @ObservedObject var urlQueue = URLQueue.shared
//    @State var score: Int? = 100
//    @State var hasFinalScore: Bool = false
//    
//    var body: some View {
//        VStack {
//            ScoreHeaderView(
//            )
//            Divider()
//            if urlQueue.isAnalysisComplete {
//                FinalDomainView(...)
//            }
//        }
//        .onAppear { startFlicker() }
//        .task { checkForWarnings() }
//        .task { triggerAnimationIfNeeded() }
//        .onChange(...) { ... }
//    }
    
//}
