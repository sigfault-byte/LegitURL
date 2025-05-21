//
//  htmlReportView.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/05/2025.
//

import SwiftUI
import WebKit

struct HTMLWebView: UIViewRepresentable {
    let html: String

    func makeUIView(context: Context) -> WKWebView {
        return WKWebView()
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        uiView.loadHTMLString(html, baseURL: nil)
    }
}

struct HTMLDebugPreview: View {
    let htmlContent: String

    var body: some View {
        HTMLWebView(html: htmlContent)
            .navigationTitle("Report Preview")
            .navigationBarTitleDisplayMode(.inline)
    }
}
