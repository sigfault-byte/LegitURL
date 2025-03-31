//
//  URLComponentsView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct URLComponentsView: View {
    @ObservedObject var viewModel: URLComponentsViewModel
    
    var body: some View {
        VStack {
            Section(header: Text("Url entered")) {
                Text(viewModel.urlEntered)
            }
            Section(header: Text("offline Information")) {
                Text(viewModel.urlInfo.first?.components.scheme ?? "")
            }
            if let onlineInfo = viewModel.onlineInfo.first {
                Text("onlineInfo")
            }
        }
    }
}
