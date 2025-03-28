//
//  SecurityWarningView.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI

struct SecurityWarningsView: View {
    @ObservedObject var urlQueue: URLQueue
    @State private var showWarningsSheet: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if urlQueue.allWarnings.count >= 1 {
                Button(action: {
                    showWarningsSheet.toggle()
                }) {
                    Text("⚠️ Security Warnings (\(urlQueue.allWarnings.count))")
                        .font(.headline)
                        .foregroundColor(.red)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color(.systemGray6)))
                        .padding(.horizontal)
                }
                .sheet(isPresented: $showWarningsSheet) {
                    SecurityWarningsDetailView(urlQueue: urlQueue)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 0)
    }
}

struct SecurityWarningsDetailView: View {
    @ObservedObject var urlQueue: URLQueue
    @State private var expandedDomains: Set<String> = []
    @State private var expandedSections: Set<String> = []

    var groupedByDomain: [String: [SecurityWarning]] {
        Dictionary(grouping: urlQueue.allWarnings, by: { $0.url })
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(groupedByDomain.sorted(by: { $0.key < $1.key }), id: \.key) { (domain, warnings) in
                        DomainSecuritySection(domain: domain, warnings: warnings, expandedDomains: $expandedDomains, expandedSections: $expandedSections)
                    }
                }
                .padding()
            }
            .navigationTitle("Security Warnings")
            .navigationBarItems(trailing: Button("Close") {
                if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                   let window = scene.windows.first,
                   let rootVC = window.rootViewController {
                    rootVC.dismiss(animated: true)
                }
            })
        }
    }

    func sourceDescription(_ source: SecurityWarning.SourceType) -> String {
        switch source {
        case .offlineAnalysis:
            return "Offline"
        case .onlineAnalysis:
            return "Online"
        case .redirectedURL(let hop):
            return "Redirected (Hop \(hop + 1))"
        }
    }
}

struct DomainSecuritySection: View {
    let domain: String
    let warnings: [SecurityWarning]
    @Binding var expandedDomains: Set<String>
    @Binding var expandedSections: Set<String>

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(action: {
                if expandedDomains.contains(domain) {
                    expandedDomains.remove(domain)
                } else {
                    expandedDomains.insert(domain)
                }
            }) {
                HStack {
                    Text(domain)
                        .font(.headline)
                        .foregroundColor(.primary)
                    Spacer()
                    Image(systemName: expandedDomains.contains(domain) ? "chevron.down" : "chevron.right")
                        .foregroundColor(.gray)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(.systemGray6)))
            }

            if expandedDomains.contains(domain) {
                ForEach(SecurityWarning.SeverityLevel.allCases, id: \.self) { severity in
                    let severityWarnings = warnings.filter { $0.severity == severity }
                    if !severityWarnings.isEmpty {
                        let severityKey = "\(domain)_\(severity.rawValue)"
                        Button(action: {
                            if expandedSections.contains(severityKey) {
                                expandedSections.remove(severityKey)
                            } else {
                                expandedSections.insert(severityKey)
                            }
                        }) {
                            HStack {
                                Text("\(severity.icon) \(severity.rawValue.capitalized) (\(severityWarnings.count))")
                                    .font(.subheadline)
                                    .foregroundColor(severity.color)
                                Spacer()
                                Image(systemName: expandedSections.contains(severityKey) ? "chevron.down" : "chevron.right")
                                    .foregroundColor(severity.color)
                            }
                            .padding(.horizontal)
                        }

                        if expandedSections.contains(severityKey) {
                            let groupedBySource = Dictionary(grouping: severityWarnings, by: { $0.source })
                            ForEach(groupedBySource.keys.sorted(by: sortSourceTypes), id: \.self) { source in
                                Text(sourceDescription(source))
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .padding(.leading, 10)

                                ForEach(groupedBySource[source] ?? [], id: \.id) { warning in
                                    HStack(alignment: .top, spacing: 5) {
                                        Circle()
                                            .fill(warning.severity.color)
                                            .frame(width: 10, height: 10)
                                            .padding(.top, 4)

                                        Text(warning.message)
                                            .font(.footnote)
                                            .foregroundColor(.gray)
                                            .fixedSize(horizontal: false, vertical: true)
                                            .multilineTextAlignment(.leading)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding()
                                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(.systemGray6)))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    func sourceDescription(_ source: SecurityWarning.SourceType) -> String {
        switch source {
        case .offlineAnalysis:
            return "Offline"
        case .onlineAnalysis:
            return "Online"
        case .redirectedURL(let hop):
            return "Redirected (Hop \(hop + 1))"
        }
    }
}

// ✅ Update SeverityLevel to support sorting & icons
extension SecurityWarning.SeverityLevel: CaseIterable {
    var icon: String {
        switch self {
        case .info: return "ℹ️"
        case .tracking: return "📍"
        case .suspicious: return "⚠️"
        case .scam: return "🕵️‍♂️"
        case .dangerous: return "🚨"
        case .critical: return "❌"
        case .fetchError: return "‼️"
        }
    }

    static var allCases: [SecurityWarning.SeverityLevel] {
        return [.critical, .dangerous, .scam, .suspicious, .tracking, .info, .fetchError]
    }
}

func sortSourceTypes(_ lhs: SecurityWarning.SourceType, _ rhs: SecurityWarning.SourceType) -> Bool {
    switch (lhs, rhs) {
    case (.offlineAnalysis, .onlineAnalysis), (.offlineAnalysis, .redirectedURL):
        return true
    case (.onlineAnalysis, .redirectedURL):
        return true
    case (.redirectedURL(let lHop), .redirectedURL(let rHop)):
        return lHop < rHop
    default:
        return false
    }
}
