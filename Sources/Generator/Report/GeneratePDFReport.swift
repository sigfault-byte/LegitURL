//
//  GeneratePDFReport.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/05/2025.
//

import SwiftUI
import WebKit
import PDFKit

class PDFReportGenerator: NSObject, WKNavigationDelegate {
    private var webView: WKWebView!
    private var completion: ((Data?) -> Void)?

    func generatePDF(from html: String, completion: @escaping (Data?) -> Void) {
        self.completion = completion

        let config = WKWebViewConfiguration()
        let a4Size = CGSize(width: 595, height: 842)
        webView = WKWebView(frame: CGRect(origin: .zero, size: a4Size), configuration: config)
        webView.navigationDelegate = self
        webView.loadHTMLString(html, baseURL: nil)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let config = WKPDFConfiguration()
        webView.createPDF(configuration: config) { result in
            switch result {
            case .success(let data):
                self.completion?(data)
            case .failure:
                self.completion?(nil)
            }
            self.cleanup()
        }
    }

    private func cleanup() {
        webView.navigationDelegate = nil
        webView = nil
        completion = nil
    }
    
    func sharePDF(url: URL) {
        let activityVC = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let root = scene.windows.first?.rootViewController {
            root.present(activityVC, animated: true)
        }
    }
}


//TODO: let finalDoc = PDFDocument()

//for (index, data) in pdfSections.enumerated() {
//    if let doc = PDFDocument(data: data) {
//        for i in 0..<doc.pageCount {
//            if let page = doc.page(at: i) {
//                finalDoc.insert(page, at: finalDoc.pageCount)
//            }
//        }
//    }
//}
