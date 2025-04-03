import SwiftUI
struct WarningsDetailView: View {
    @ObservedObject var viewModel: WarningsViewModel

    var body: some View {
            List {
                ForEach(viewModel.groupedByDomain.sorted(by: { $0.key < $1.key }), id: \.key) { (domain, warnings) in
                    Section(header: Text(domain)) {
                        WarningSection(
                            domain: domain,
                            warnings: warnings,
                            expandedDomains: $viewModel.expandedDomains,
                            expandedSections: $viewModel.expandedSections,
                            sourceDescription: viewModel.sourceDescription,
                            sortWarningSourceTypes: viewModel.sortWarningSourceTypes
                        )
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
