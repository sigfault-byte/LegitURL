//  RedirectChainSection.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct RedirectChainSection: View {
    @ObservedObject var viewModel: URLComponentsViewModel
    
    var body: some View {
        Section(header: Text("Encoutered URLs")) {
            ForEach(viewModel.urlInfo) {url in

                NavigationLink(
                    destination: URLInfoDetailView(
                        urlInfo: url,
                        onlineInfo: viewModel.onlineInfo.first(where: { $0.id == url.id })
                    )
                ) {
                    Label(url.components.coreURL ?? "Unknown Host", systemImage: "network")
                }
            }
        }
    }
}
