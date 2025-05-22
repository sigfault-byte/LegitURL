//
//  URLCheckerApp.swift
//  LegitURL
//
//  Created by Chief Hakka on 16/03/2025.
//

import SwiftUI

//@main
//struct LegitURLApp: App {
//    @State private var sharedURL: URL? = nil
//
//    var body: some Scene {
//        WindowGroup {
//            NavigationStack {
//                AppCoordinatorView(initialURL: sharedURL,
//                                   onResetURL: { sharedURL = nil })}
//            .onOpenURL { url in
//                print("💡 Opened with URL: \(url)")
//                if url.scheme == "legiturl",
//                   let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
//                   components.host == "analyze",
//                   let query = components.queryItems?.first(where: { $0.name == "url" })?.value,
//                   let decoded = URL(string: query) {
//                    sharedURL = decoded
//                }
//            }
//        }
//    }
//}

@main
struct LegitURLApp: App {
    @State private var sharedURL: URL?
    @Environment(\.scenePhase) private var scenePhase   // ← new

//    init() {
//        consumeHandoff()        // cold-launch pickup, trick does not work
//    }

    var body: some Scene {
        WindowGroup {
            AppCoordinatorView(initialURL: sharedURL,
                               onResetURL: { sharedURL = nil })
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
                        consumeHandoff()
                    }
                }
            }
        }
    }

    /// Reads & clears any URL left by the share extension.
    private func consumeHandoff() {
        let defaults = UserDefaults(suiteName: "group.IJTWTML.LegitURL.shared")

//        if let snapshot = defaults?.dictionaryRepresentation() {
//            let mine = snapshot.filter { $0.key.hasPrefix("Shared") || $0.key.hasPrefix("YourPrefix") }
//            print(" my keys:", mine)
//        }
        
        if let str = defaults?.string(forKey: "SharedURL"),
           let url = URL(string: str) {
            sharedURL = url
            defaults?.removeObject(forKey: "SharedURL")
        }
    }
}
