//
//  CopyJSONInfoView.swift
//  LegitURL
//
//  Created by Chief Hakka on 28/05/2025.
//
import SwiftUI

struct CopyJSONInfoView: View {
    @State private var didCopy = false

    var body: some View {
        let (byte, token) = URLQueue.shared.jsonLenTokenEstimate ?? (0, 0)
        
        VStack(spacing: 20) {
            Text("You can copy a structured security report in JSON format to your clipboard. Then, paste it into your favorite AI (like ChatGPT, Google Gemini, Claude, DeepSeek, Grok, etc.) to get a detailed explanation.")
                .font(.body)
                .foregroundColor(.primary)
                .font(.caption)
                .padding()
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Color(.systemGray6))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(Color(.separator), lineWidth: 0.5)
                )
            Text("The current report is \(byte) Bytes, this is around \(token) tokens.")
                .font(.caption)
            Button {
                UIPasteboard.general.string = URLQueue.shared.jsonDataForUserModel
                didCopy = true
            } label: {
                Label("Copy JSON to Clipboard", systemImage: "doc.on.doc")
                    .padding()
                    .background(Color.accentColor)
                    .foregroundColor(.white)
                    .cornerRadius(10)
            }

            if didCopy {
                Text("Copied!")
                    .font(.footnote)
                    .foregroundColor(.green)
            }

            Spacer()
        }
        .padding()
        .navigationTitle("Export to Clipboard")
        .navigationBarTitleDisplayMode(.inline)
    }
}
