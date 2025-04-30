//  CookieListView.swift
//  URLChecker
//
//  Created by Chief Hakka on 08/04/2025.
//
import SwiftUI

struct CookieListView: View {
    var cookies: [CookieAnalysisResult?]
    @State private var expandedCookieIDs: Set<UUID> = []

    var body: some View {
        let viewModels = cookies.compactMap { $0.map(CookieViewModel.init) }

        List {
            ForEach(viewModels) { cookie in
                Section(header: Text(" Cookiey key :\(cookie.name)")) {
                    HStack {
                        Text("Severity")
                        Spacer()
                        Text(cookie.severity.rawValue)
                            .foregroundStyle(color(for: cookie.severity))
                    }
                    LabeledContent("Value Size", value: "\(cookie.value.count) bytes")
                    LabeledContent("Expires In", value: cookie.humanReadableExpiry)
                    LabeledContent("SameSite Policy", value: cookie.displayedSameSitePolicy)
                    LabeledContent("Secure", value: cookie.displayedSecureStatus)
                        .foregroundStyle(cookie.secureColor)
                    LabeledContent("HttpOnly", value: cookie.displayHttpOnly)
                        .foregroundStyle(cookie.httpOnlyColor)
                    LabeledContent("Path", value: cookie.path)
                    LabeledContent("Domain", value: cookie.displayedDomain)

                    LabeledContent("Value", value: expandedCookieIDs.contains(cookie.id) ? cookie.value : String(cookie.value.prefix(40)) + "…")
                        .onTapGesture {
                            if expandedCookieIDs.contains(cookie.id) {
                                expandedCookieIDs.remove(cookie.id)
                            } else {
                                expandedCookieIDs.insert(cookie.id)
                            }
                        }

                    if !cookie.readableFlags.isEmpty {
                        Section(header: Text("Flags")) {
                            ForEach(cookie.readableFlags, id: \.self) { reason in
                                Text("• \(reason)")
                                    .foregroundStyle(color(for: cookie.severity))
                            }
                        }
                    }
                }
            }
        }
        .listStyle(InsetGroupedListStyle())
        .navigationTitle("Cookies")
    }

    private func color(for severity: CookieSeverity) -> Color {
        switch severity {
        case .info: return .blue
        case .suspicious: return .orange
        case .tracking: return .purple
        case .dangerous: return .red
        case .scam: return .red
        case .critical: return .red.opacity(0.8)
        case .fetchError: return .black
        }
    }
}
