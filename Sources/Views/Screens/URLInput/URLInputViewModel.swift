//
//  URLInputViewModel.swift
//  LegitURL
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI


class URLInputViewModel: ObservableObject{
    @Published var errorMessage: String = ""
    @Published var showQRScanner: Bool = false
    @Published var isInputValid: Bool = false
    @Published var pasteAvailable = false

    var infoMessage: String = ""
    init() {
        pasteAvailable = UIPasteboard.general.hasStrings
    }

    var urlInput: String = "" {
        didSet {
            isInputValid = !urlInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    func analyzeURL() -> Bool {
        let (finalURL, message) = CommonTools.sanitizeInputURL(urlInput)

        if let finalURL = finalURL {
            urlInput = finalURL
            infoMessage = message ?? ""
            errorMessage = ""
            return true
        } else {
            errorMessage = message ?? "Invalid URL"
            infoMessage = ""
            return false
        }
    }
    
    func pasteURLFromClipboard() {
        DispatchQueue.main.async {
            self.urlInput = UIPasteboard.general.string ?? ""
        }
    }
}
