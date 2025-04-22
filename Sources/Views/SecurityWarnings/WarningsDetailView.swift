import SwiftUI

struct WarningsDetailView: View {
    @ObservedObject var viewModel: WarningsViewModel
    @State private var expandedWarningID: UUID?
    var onDismissAndNavigate: ((String) -> Void)?

    var body: some View {
        ScrollView {
            VStack(alignment: .center, spacing: 8) {
                Capsule()
                    .fill(Color.secondary.opacity(0.4))
                    .frame(width: 40, height: 5)
                    .padding(.top, 8)

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
                        }
                        Spacer()
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
                            expandedWarningID: expandedWarningID,
                            setExpandedWarningID: { expandedWarningID = $0 },
                            onSourceTap: { tappedSource in
                                onDismissAndNavigate?(tappedSource)
                            }
                        )
                    }
                }
                .padding()
            }
        }
        .navigationTitle("Security Warnings")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct LegitURLReplyView: View {
    let domainGroup: WarningDomainGroup
    let expandedWarningID: UUID?
    let setExpandedWarningID: (UUID?) -> Void
    let onSourceTap: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            
            ForEach(domainGroup.sources) { sourceGroup in
                
                ForEach(SecurityWarning.SeverityLevel.allWarnings, id: \.self) { severity in
                    
                    if let warnings = sourceGroup.severityMap[severity], !warnings.isEmpty {
                        
                        ForEach(warnings) { warning in
                            
                            HStack(alignment: .top, spacing: 8) {
                                Rectangle()
                                    .fill(severity.iconColor)
                                    .frame(width: 4)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(warning.message)
                                        .font(.subheadline)
                                        .foregroundColor(.primary)
                                    Text(sourceGroup.source.displayLabel)
                                        .font(.caption)
                                        .foregroundColor(.blue)
                                        .onTapGesture {
                                            if expandedWarningID == warning.id {
                                                setExpandedWarningID(nil)
                                            } else {
                                                setExpandedWarningID(warning.id)
                                            }
                                        }
                                    if expandedWarningID == warning.id {
                                        GlossaryBubbleView(source: sourceGroup.source)
                                    }
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
