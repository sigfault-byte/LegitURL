//
//  URLInputView.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI
struct URLInputView: View {
    @Binding var urlText: String
    @Binding var infoMessage: String?
    @Binding var analysisStared: Bool
    
    var body: some View {
        HStack {
            TextField("Enter a URL", text: $urlText)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .disableAutocorrection(true)
                .keyboardType(.URL)
            
            Button(action: {
                urlText = ""
                URLAnalyzer.resetQueue()
                analysisStared = false
                
            }) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.gray)
            }
        }
        .padding()
    }
}
