//
//  AppCoordinatorViewModel.swift
//  LegitURL
//
//  Created by Chief Hakka on 22/05/2025.
//

import Foundation

final class AppCoordinatorModel: ObservableObject {
    enum Screen {
        case input(URL?)
        case analysis(urlInput: String, infoMessage: String)
    }

    @Published var screen: Screen = .input(nil)

    func showInput(with url: URL?) {
        if case .input(let current) = screen, current == url {
            // Same screen and same URL → force refresh
            screen = .analysis(urlInput: "", infoMessage: "")
            DispatchQueue.main.async {
                self.screen = .input(url)
            }
        } else {
            screen = .input(url)
        }
    }

    func showAnalysis(from input: String, info: String) {
        screen = .analysis(urlInput: input, infoMessage: info)
    }

    func resetSharedURL(_ callback: () -> Void) {
        callback() // e.g. to call onResetURL
    }
}
