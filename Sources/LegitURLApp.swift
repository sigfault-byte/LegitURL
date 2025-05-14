//
//  URLCheckerApp.swift
//  LegitURL
//
//  Created by Chief Hakka on 16/03/2025.
//

import SwiftUI

@main
struct LegitURLApp: App {
    @State private var sharedURL: URL? = nil

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                if let url = sharedURL {
                    URLInputView(incomingURL: url) { urlInput, info in
                        // You can leave this blank or trigger further navigation here if needed
                    }
                } else {
                    AppCoordinatorView()
                }
            }
            .onOpenURL { url in
                sharedURL = url
            }
        }
    }
}
