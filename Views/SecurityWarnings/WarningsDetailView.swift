import SwiftUI

struct WarningsDetailView: View {
    @ObservedObject var viewModel: WarningsViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                // LegitURL chat contact banner :D
                HStack(spacing: 12) {
                    Image(systemName: "shield.lefthalf.fill")
                        .foregroundColor(.blue)
                        .imageScale(.large)

                    VStack(alignment: .leading, spacing: 2) {
                        Text("LegitURL")
                            .font(.headline)
                            .fontWeight(.semibold)
                        Text("Analysis complete")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    Spacer()
                }
                .padding()
                .background(.ultraThinMaterial)
                .cornerRadius(16)
                .padding(.horizontal)

                ForEach(Array(viewModel.grouped.enumerated()), id: \.element.id) { index, domainGroup in
                    // User message bubble
                    HStack {
                        Spacer()
                        Text(domainGroup.domain)
                            .font(.subheadline)
                            .padding(10)
                            .foregroundColor(.white)
                            .background(Color.blue)
                            .cornerRadius(12)
                            .multilineTextAlignment(.trailing)
                    }

                    LegitURLReplyView(domainGroup: domainGroup)
                }
            }
            .padding()
        }
        .navigationTitle("Security Warnings")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct LegitURLReplyView: View {
    let domainGroup: WarningDomainGroup

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(domainGroup.sources) { sourceGroup in
                ForEach(SecurityWarning.SeverityLevel.allWarnings, id: \.self) { severity in
                    if let warnings = sourceGroup.severityMap[severity], !warnings.isEmpty {
                        ForEach(warnings) { warning in
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: severity.iconName)
                                    .foregroundColor(severity.iconColor)
                                    .padding(.top, 2)

                                VStack(alignment: .leading, spacing: 4) {
                                    Text(warning.message)
                                        .font(.subheadline)
                                        .foregroundColor(.primary)
                                    Text(sourceGroup.source.displayLabel)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding(10)
                            .background(Color(uiColor: .secondarySystemBackground))
                            .cornerRadius(10)
                        }
                    }
                }
            }
        }
        .padding(.leading, 8)
    }
}
