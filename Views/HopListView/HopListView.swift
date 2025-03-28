import SwiftUI

struct HopListView: View {
    @ObservedObject var urlQueue: URLQueue

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Redirect Chain")
                .frame(maxWidth: .infinity, alignment: .center)
                .font(.headline)
                .padding(.bottom, 4)

            ForEach(Array(urlQueue.offlineQueue.enumerated()), id: \.element.id) { index, urlInfo in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Image(systemName: "network")
                            .foregroundColor(.blue)

                        Text(urlInfo.components.host ?? "Unknown Host")
                            .font(.body)
                            .bold()

                        Spacer()

                        NavigationLink(destination: URLDetailView(
                            urlInfo: urlInfo,
                            onlineInfo: urlQueue.onlineQueue.first(where: { $0.id == urlInfo.id })
                        )) {
                            Text("Details")
                                .font(.footnote)
                                .foregroundColor(.blue)
                                .padding(6)
                                .background(Color(.systemGray5))
                                .cornerRadius(6)
                        }
                    }

                    if index < urlQueue.offlineQueue.count - 1 {
                        HStack {
                            Spacer()
                            Image(systemName: "arrow.down")
                                .font(.caption)
                                .foregroundColor(.gray)
                            Spacer()
                        }
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(.top)
    }
}
