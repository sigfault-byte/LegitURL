import SwiftUI

struct DestinationInfoView: View {
    @ObservedObject var viewModel: DestinationInfoViewModel

    var body: some View {
        VStack(alignment: .center, spacing: 16) {
            HStack {
                Label("Final destination", systemImage: "location.fill")
                Spacer()
                Text(viewModel.finalHost)
                    .monospaced()
                    .foregroundStyle(.primary)
            }

            HStack {
                Label("Redirect hops", systemImage: "arrow.triangle.branch")
                Spacer()
                Text("\(viewModel.hopCount)")
            }

            if viewModel.punycodeWarning {
                VStack(alignment: .leading, spacing: 6) {
                    Text("⚠️ Domain uses encoded characters")
                        .font(.callout)
                        .fontWeight(.semibold)
                        .foregroundColor(.orange)

                    Text("You entered '\(viewModel.inputDomain)', but the actual destination is '\(viewModel.finalHostPunycode)'. This may be a lookalike domain.")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .transition(.opacity.combined(with: .move(edge: .top)))
            }

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text("You are being redirected to:")
                    .font(.footnote)
                Text("→ \(viewModel.domainLabel).\(viewModel.tldLabel)")
                    .font(.title3)
                    .fontWeight(.semibold)
                    .frame(maxWidth: .infinity, alignment: .center)
            }

            Text("Stay alert if the destination doesn't match your expectations.")
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, alignment: .center)
        }
        .padding(.vertical, 6)
        .animation(.easeOut(duration: 0.3), value: viewModel.punycodeWarning)
    }
}
