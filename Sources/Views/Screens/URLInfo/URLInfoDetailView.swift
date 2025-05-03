//
//  URLInfoDetailView.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct URLInfoDetailView: View {
    var urlInfo: URLInfo
    var onlineInfo: OnlineURLInfo?

    private var onlineSection: some View {
        Group {
            if let online = onlineInfo, let responseCode = online.serverResponseCode, responseCode != 0 {
                URLOnlineDetailComponent(onlineInfo: online)
            } else {
                Text("No online data available")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
        }
    }

    var body: some View {
        List {
            Section(header: Text("URL")) {
                URLDetailURLComponent(fullURL: urlInfo.components.fullURL ?? "")
            }
            Section(header: Text("Offline details")) {
                URLOfflineDetailComponent(urlInfo: urlInfo)
            }
            Section(header: Text("Online Details")) {
                onlineSection
            }
            // LATER
//            if let recommendation = onlineInfo?.cspRecommendation {
//                Section(header: Text("Security Recommendations")) {
//                    NavigationLink(destination: CSPRecommendationView(recommendation: recommendation)) {
//                        Text("Exemple of script-src recommendation")
//                    }
//                }
//            }
        }
    }
}
