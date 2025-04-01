//
//  AppCoordinatorView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

//Root view cases
enum RootViews {
    case input
    case analysis(urlInput: String, infoMessage: String)
}

//Main rooter like struct
struct AppCoordinatorView: View {
    @State private var rootScreen: RootScreen = .input

    var body: some View {
        switch rootScreen {
        case .input:
            URLInputView(onAnalyze: {urlInput, info in
                rootScreen = .analysis(urlInput: urlInput, infoMessage: info)
            })

        case .analysis(let urlInput, let infoMessage):
            URLAnalysisView(
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
