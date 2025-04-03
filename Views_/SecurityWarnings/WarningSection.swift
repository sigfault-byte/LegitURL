//
//  WarningSection.swift
//  URLChecker
//
//  Created by Chief Hakka on 02/04/2025.
//
import SwiftUI

struct WarningSection: View {
    let domain: String
    let warnings: [SecurityWarning]
    @Binding var expandedDomains: Set<String>
    @Binding var expandedSections: Set<String>
    let sourceDescription: (SecurityWarning.SourceType) -> String
    let sortWarningSourceTypes: (SecurityWarning.SourceType, SecurityWarning.SourceType) -> Bool

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

                    ForEach(groupedBySource.keys.sorted(by: sortWarningSourceTypes), id: \.self) { source in
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
}
