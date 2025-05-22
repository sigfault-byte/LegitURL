//
//  URLCheckerApp.swift
//  LegitURL
//
//  Created by Chief Hakka on 16/03/2025.
//

import SwiftUI

@main
struct LegitURLApp: App {
    @State private var sharedURL: URL?
    @Environment(\.scenePhase) private var scenePhase   // ← new
    @StateObject private var coordinatorModel = AppCoordinatorModel()

//    init() {
//        consumeHandoff()        // cold-launch pickup, trick does not work
//    }

    var body: some Scene {
        WindowGroup {
            AppCoordinatorView(model: coordinatorModel)
            .onOpenURL { url in                       // still handle legiturl:// scheme ... ! why ? Who fucking knows
                if url.scheme == "legiturl",
                   url.host == "analyze",
                   let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
                   let raw  = comps.queryItems?.first(where: { $0.name == "url" })?.value,
                   let decoded = URL(string: raw) {
                    sharedURL = decoded               // ← assign so UI updates
                }
            }
            //  pick up the hand-off every time
            .onChange(of: scenePhase) { phase, _ in
                if phase == .inactive || phase == .active {
                    //Race disk condition or whatever ?
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                        Task { await consumeHandoff() }
                    }
                }
            }
            .task {
                // Cold launch hook
                try? await Task.sleep(nanoseconds: 300_000_000)  // 0.3s delay ? you get 0.3 you get 0.3 everybody gets 0.3
                await consumeHandoff()
            }
        }
    }

    /// Reads & clears any URL left by the share extension.
    /// This needs mainActor and an async to be sure the race is in legiturl favor
    @MainActor
    private func consumeHandoff() async {
        let defaults = UserDefaults(suiteName: "group.IJTWTML.LegitURL.shared")

//        if let snapshot = defaults?.dictionaryRepresentation() {
//            let mine = snapshot.filter { $0.key.hasPrefix("Shared") || $0.key.hasPrefix("YourPrefix") }
//            print(" my keys:", mine)
//        }
        
        if let str = defaults?.string(forKey: "SharedURL"),
           let url = URL(string: str) {
            coordinatorModel.showInput(with: url)
            sharedURL = nil
            defaults?.removeObject(forKey: "SharedURL")
        }
    }
}
