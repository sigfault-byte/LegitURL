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
        uiView.loadHTMLString(html, baseURL: URL(string: "about:blank"))
    }
}

struct HTMLReportPreview: View {
    let htmlContent: String
    let domain: String

    var body: some View {
        HTMLWebView(html: htmlContent)
            .navigationTitle("Report Preview")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Export to PDF") {
                        let generator = PDFReportGenerator()
                        generator.generatePDF(from: htmlContent) { data in
                            if let data = data {
                                let date = Date()
                                let isoFormatter = ISO8601DateFormatter()
                                isoFormatter.formatOptions = [.withInternetDateTime, .withDashSeparatorInDate, .withColonSeparatorInTime]
                                let timestamp = isoFormatter.string(from: date)
                                let name = "legitURL_Report_\(timestamp)-\(domain).pdf"
                                let tmpURL = FileManager.default.temporaryDirectory.appendingPathComponent(name)
                                do {
                                    try data.write(to: tmpURL)
                                    generator.sharePDF(url: tmpURL)
                                } catch {
                                    print("Failed to write PDF: \(error)")
                                }
                            } else {
                                print("PDF generation failed.")
                            }
                        }
                    }
                }
            }
    }
}
