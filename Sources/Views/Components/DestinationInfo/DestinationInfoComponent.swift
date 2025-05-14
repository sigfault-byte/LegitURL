import SwiftUI

struct DestinationInfoComponent: View {
    @ObservedObject var viewModel: DestinationInfoComponentModel
    
    @State private var showFullExplanation = false
    @State private var showFullDomain = false
    @State private var showFullDestination = false
    
    var body: some View {
        VStack(alignment: .center, spacing: 12) {
            if viewModel.displayMessage {
                VStack(alignment: .center, spacing: 6) {
                    Text(viewModel.summaryTitle)
                        .font(.callout)
                        .fontWeight(.semibold)
                        .foregroundColor(viewModel.scoreColor)
                        .multilineTextAlignment(.center)
                    
//                    Group {
//                        if showFullExplanation {
                            Text(viewModel.summaryMessage)
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                                .lineLimit(nil)
                                .fixedSize(horizontal: false, vertical: true)
                                .onTapGesture {
                                    showFullExplanation.toggle()
                                }
//                        }
//                            else {
//                            Text("Click to see a summary of the score.")
//                                .font(.footnote)
//                                .foregroundColor(.secondary)
//                                .multilineTextAlignment(.center)
//                                .onTapGesture {
//                                    showFullExplanation.toggle()
//                                }
//                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .center)
                    
//                }
                .padding()
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Entered URL")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Group {
                        if showFullDomain || viewModel.inputDomain.count <= 50 {
                            Text(viewModel.inputDomain)
                        } else {
                            Text(String(viewModel.inputDomain.prefix(50)) + "…")
                        }
                    }
                    .onTapGesture {
                            showFullDomain.toggle()
                    }
                        .font(.body)
                        .fontWeight(.semibold)
                        .monospacedDigit()
                        .foregroundColor(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding()
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(viewModel.hopCount > 0 ? "Redirected in \(viewModel.hopCount) steps to" : "Final destination")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Group {
                        if !viewModel.punycodeMissmatch {
                            let prefix = viewModel.finalHost.components(separatedBy: "\(viewModel.domainLabel).\(viewModel.tldLabel)").first ?? ""
                            let suffix = viewModel.finalHost.components(separatedBy: "\(viewModel.domainLabel).\(viewModel.tldLabel)").dropFirst().joined()
                            let composedText =
                                Text(prefix)
                                    .foregroundColor(.secondary) +
                                Text(viewModel.domainLabel)
                                    .foregroundColor(viewModel.scoreColor) +
                                Text(".")
                                    .foregroundColor(viewModel.scoreColor) +
                                Text(viewModel.tldLabel)
                                    .foregroundColor(viewModel.scoreColor) +
                                Text(suffix)
                                    .foregroundColor(.secondary)
                            
                            if showFullDestination || viewModel.finalHost.count <= 50 {
                                composedText
                            } else {
                                let keepCount = max(0, 50 - (viewModel.domainLabel.count + viewModel.tldLabel.count + 1))
                                let half = keepCount / 2

                                let prefixTrimmed = String(prefix.suffix(half))
                                let suffixTrimmed = String(suffix.prefix(keepCount - half))

                                Text(prefixTrimmed)
                                    .foregroundColor(.secondary) +
                                Text(viewModel.domainLabel)
                                    .foregroundColor(viewModel.scoreColor) +
                                Text(".")
                                    .foregroundColor(viewModel.scoreColor) +
                                Text(viewModel.tldLabel)
                                    .foregroundColor(viewModel.scoreColor) +
                                Text(suffixTrimmed + "…")
                                    .foregroundColor(.secondary)
                            }
                        } else {
                            if showFullDestination || viewModel.finalHost.count <= 50 {
                                Text(viewModel.finalHost)
                                    .foregroundColor(viewModel.scoreColor)
                            } else {
                                let truncated = String(viewModel.finalHost.prefix(50)) + "…"
                                Text(truncated)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                    .onTapGesture {
                            showFullDestination.toggle()
                    }
                    .font(.body)
                    .fontWeight(.semibold)
                    .monospacedDigit()
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding()
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            
            Divider()
            
            Text("Stay alert if the destination doesn't match your expectations.")
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, alignment: .center)
        }
        .padding(.vertical, 6)
    }
}
