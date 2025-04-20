//import SwiftUI
//
//struct WarningsDetailView: View {
//    @ObservedObject var viewModel: WarningsViewModel
//
//    var body: some View {
//        List {
//            ForEach(viewModel.groupedWarnings) { grouped in
//                Section(header: Text(grouped.url)) {
//                    ForEach(grouped.sources) { sourceGroup in
//                        WarningSection(sourceGroup: sourceGroup, sourceDescription: viewModel.sourceDescription)
//                    }
//                }
//            }
//        }
//        .listStyle(InsetGroupedListStyle())
//        .navigationTitle("Security Warnings")
//        .navigationBarItems(trailing: Button("Close") {
//            if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
//               let window = scene.windows.first,
//               let rootVC = window.rootViewController {
//                rootVC.dismiss(animated: true)
//            }
//        })
//    }
//}
