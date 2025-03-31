//
//  AppRootView.swift
//  URLChecker
//
//  Created by Chief Hakka on 30/03/2025.
//
import SwiftUI

//Root view cases
enum RootScreen {
    case input
    case analysis(urlInput: String, infoMessage: String)
}

//Main rooter like struct
struct AppRootView: View {
    @State private var rootScreen: RootScreen = .input

    var body: some View {
        switch rootScreen {
        case .input:
            InputHomeView(onAnalyze: {urlInput, info in
                rootScreen = .analysis(urlInput: urlInput, infoMessage: info)
            })

        case .analysis(let urlInput, let infoMessage):
            URLAnalysisResultView(
                urlInput: urlInput,
                infoMessage: infoMessage,
                onExit: {
                    LegitSessionManager.reset()
                    rootScreen = .input
                }
            )
        }
    }
}
