import SwiftUI

struct WarningsDetailComponent: View {
    @ObservedObject var viewModel: WarningsComponentModel
    @State private var expandedWarningIDs: Set<UUID> = []
    @State private var showInfoWarnings: Bool = false
    var onDismissAndNavigate: ((String) -> Void)?

    var body: some View {
        ScrollView {
//            VStack(alignment: .center, spacing: 8) {
//                Capsule()
//                    .fill(Color.secondary.opacity(0.4))
//                    .frame(width: 40, height: 5)
//                    .padding(.top, 8)

                VStack(alignment: .leading, spacing: 24) {
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
                            Button(action: {
                                onDismissAndNavigate?("howItWorks")
                            }) {
                                Text("See glossary")
                                    .font(.caption)
                                    .fontWeight(.medium)
                                }
                                .foregroundColor(.blue)
                                .padding(.vertical, 4)
                            }
                        Spacer()
                        VStack(spacing: 4) {
                            Toggle("", isOn: $showInfoWarnings)
                                .labelsHidden()
                                .toggleStyle(.switch)
                            Text("INFO")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        .frame(width: 60)
                        .padding(.horizontal)
                    }
                    .padding()
                    .background(.ultraThinMaterial)
                    .cornerRadius(16)
                    .padding(.horizontal)

                    ForEach(Array(viewModel.grouped.enumerated()), id: \.element.id) { index, domainGroup in
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

                        LegitURLReplyView(
                            domainGroup: domainGroup,
                            expandedWarningIDs: expandedWarningIDs,
                            toggleExpandedWarningID: { warningID in
                                if expandedWarningIDs.contains(warningID) {
                                    expandedWarningIDs.remove(warningID)
                                } else {
                                    expandedWarningIDs.insert(warningID)
                                }
                            },
                            showInfoWarnings: showInfoWarnings,
                            onSourceTap: { tappedSource in
                                onDismissAndNavigate?(tappedSource)
                            }
                        )
                    }
                }
                .padding()
//            }
        }
        .navigationTitle("Security Warnings")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct LegitURLReplyView: View {
    let domainGroup: WarningDomainGroup
    let expandedWarningIDs: Set<UUID>
    let toggleExpandedWarningID: (UUID) -> Void
    let showInfoWarnings: Bool
    let onSourceTap: (String) -> Void
    let truncatedLimit: Int = 128

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            
            ForEach(domainGroup.sources) { sourceGroup in
                
                ForEach(SecurityWarning.SeverityLevel.allWarnings, id: \.self) { severity in
                    
                    if (severity != .info || showInfoWarnings),
                       let warnings = sourceGroup.severityMap[severity],
                       !warnings.isEmpty {
                        
                        ForEach(warnings) { warning in
                            
                            HStack(alignment: .top, spacing: 8) {
                                Rectangle()
                                    .fill(severity.iconColor)
                                    .frame(width: 4)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(sourceGroup.source.displayLabel)
                                        .font(.caption)
                                        .foregroundColor(severity.iconColor)
                                        .onTapGesture {
                                            toggleExpandedWarningID(warning.id)
                                        }
                                    Text(expandedWarningIDs.contains(warning.id) || warning.message.count <= truncatedLimit
                                         ? warning.message
                                         : String(warning.message.prefix(truncatedLimit)) + "[...]")
                                        .font(.subheadline)
                                        .foregroundColor(.primary)
                                        .onTapGesture {
                                            toggleExpandedWarningID(warning.id)
                                        }
//                                    if expandedWarningIDs.contains(warning.id) {
//                                        GlossaryBubbleView(source: sourceGroup.source)
//                                    }
                                }
                            }
                            .padding(10)
                            .background(Color(uiColor: .secondarySystemBackground))
                            .cornerRadius(10)
                            .transition(.opacity)
                        }
                    }
                }
            }
        }
        .padding(.leading, 8)
        .animation(.easeInOut, value: showInfoWarnings)
    }
}
