import SwiftUI

struct DestinationInfoComponent: View {
    @ObservedObject var viewModel: DestinationInfoComponentModel
    
    @State private var showFullExplanation = false
    
    
    var body: some View {
        VStack(alignment: .center, spacing: 12) {
            if viewModel.displayMessage {
                VStack(alignment: .center, spacing: 6) {
                    Text("⚠️ Potential issue ⚠️\nwith the destination domain ")
                        .font(.callout)
                        .fontWeight(.semibold)
                        .foregroundColor(viewModel.scoreColor)
                        .multilineTextAlignment(.center)
                    
                    Group {
                        if showFullExplanation {
                            Text("We'll generate a personalized message that summarizes the score. For now, this is a placeholder. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book.")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                                .onTapGesture {
                                    withAnimation { showFullExplanation.toggle() }
                                }
                        } else {
                            Text("Click to see a sumamry of the score.")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                                .onTapGesture {
                                    withAnimation { showFullExplanation.toggle() }
                                }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .center)
                    
                }
                .padding()
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
            
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Entered URL")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Group {
                        if viewModel.isAnalysisComplete {
                            Text(viewModel.inputDomain)
                        } else {
                            Text("https://\(viewModel.loadingDots)")
                        }
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
                            
                            (
                                Text(prefix)
                                    .foregroundColor(.secondary)
                                + Text(viewModel.domainLabel)
                                    .foregroundColor(viewModel.scoreColor)
                                + Text(".")
                                    .foregroundColor(viewModel.scoreColor)
                                + Text(viewModel.tldLabel)
                                    .foregroundColor(viewModel.scoreColor)
                                + Text(suffix)
                                    .foregroundColor(.secondary)
                            )
                        } else {
                            Text(viewModel.finalHost)
                                .foregroundColor(viewModel.scoreColor)
                        }
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
        .animation(.easeOut(duration: 0.3), value: viewModel.displayMessage)
    }
}
