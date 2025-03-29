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
            List {
                ForEach(groupedByDomain.sorted(by: { $0.key < $1.key }), id: \.key) { (domain, warnings) in
                    Section(header: Text(domain)) {
                        DomainSecuritySection(domain: domain, warnings: warnings, expandedDomains: $expandedDomains, expandedSections: $expandedSections)
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                            .padding(.vertical, 4)
                    }
                    .listRowSeparator(.hidden)       // Hide the default row separator
                }
            }
            .listStyle(InsetGroupedListStyle())
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
        ForEach(SecurityWarning.SeverityLevel.allCases, id: \.self) { severity in
            let severityWarnings = warnings.filter { $0.severity == severity }
            if !severityWarnings.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("\(severity.rawValue.capitalized)")
                            .font(.headline)
                            .foregroundColor(severity.color)
                        Spacer()
                        Text("(\(severityWarnings.count))")
                            .font(.headline)
                            .foregroundColor(severity.color)
                        
                    }

                    let groupedBySource = Dictionary(grouping: severityWarnings, by: { $0.source })

                    ForEach(groupedBySource.keys.sorted(by: sortSourceTypes), id: \.self) { source in
                        HStack {
                            Spacer()
                            Text(sourceDescription(source))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(.trailing, 6)

                        ForEach(groupedBySource[source] ?? [], id: \.id) { warning in
                            HStack(alignment: .top, spacing: 5) {
                                Circle()
                                    .fill(warning.severity.color)
                                    .frame(width: 10, height: 10)
                                    .padding(.top, 4)

                                Text(warning.message)
                                    .font(.footnote)
                                    .foregroundColor(.primary)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .multilineTextAlignment(.leading)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
                .padding()
                .background(Color(.secondarySystemGroupedBackground))
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(.separator), lineWidth: 0.5)
                )
                .padding(.bottom, 8)
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
