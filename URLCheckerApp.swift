//
//  URLCheckerApp.swift
//  URLChecker
//
//  Created by Chief Hakka on 16/03/2025.
//

import SwiftUI

@main
struct URLCheckerApp: App {
    // Shared state to controll the rootView
    @State private var rootScreen: RootScreen = .input
    
    
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                AppRootView()
            }
        }
    }
}
