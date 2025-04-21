import SwiftUI

struct SettingView: View {
    var body: some View {
        NavigationStack {
            List {
                Section(header: Text("Custom Detection")) {
                    NavigationLink("🛡️ Brand Watchlist") {
                        UserWatchlistView()
                    }
                    NavigationLink("🚨 Scam Word Watchlist") {
                        UserScamwordView()
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }
}
