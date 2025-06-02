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
        let (byte, token) = URLQueue.shared.jsonLenTokenEstimateLLModel ?? (0, 0)
        let (byteBrief, tokenBrief) = URLQueue.shared.jsonLenTokenEstimateLLModelBrief ?? (0, 0)
        let jsonOk = URLQueue.shared.internalErrorMessages.isEmpty
        let errors = URLQueue.shared.internalErrorMessages
        
        if jsonOk {
            VStack {
                Spacer(minLength: 40)

                VStack(spacing: 20) {
                    Text("Copy a structured JSON security report to your clipboard, then drop it into ChatGPT, Gemini, Claude—or any AI you like.\nQuick Summary gives you the essentials;\nFull Report includes every technical detail so the model can dig deeper.")
                        .font(.body)
                        .foregroundColor(.primary)
                        .font(.caption)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading) 
                        .background(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .fill(Color(.systemGray6))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(Color(.separator), lineWidth: 0.5)
                        )

                    HStack(spacing: 12) {
                        VStack {
                            Button {
                                UIPasteboard.general.string = URLQueue.shared.jsonDataForUserLLModelBrief
                                didCopy = true
                            } label: {
                                Label("Quick Summary", systemImage: "doc.on.doc")
                                    .padding()
                                    .frame(maxWidth: .infinity)
                                    .background(Color.accentColor)
                                    .foregroundColor(.white)
                                    .cornerRadius(10)
                            }
                            Text("\(byteBrief) bytes ≈ \(tokenBrief) tokens")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }

                        VStack {
                            Button {
                                UIPasteboard.general.string = URLQueue.shared.jsonDataForUserLLModel
                                didCopy = true
                            } label: {
                                Label("Full Report", systemImage: "doc.on.doc.fill")
                                    .padding()
                                    .frame(maxWidth: .infinity)
                                    .background(Color.accentColor)
                                    .foregroundColor(.white)
                                    .cornerRadius(10)
                            }
                            Text("\(byte) bytes ≈ \(token) tokens")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }

                    if didCopy {
                        Text("Copied!")
                            .font(.footnote)
                            .foregroundColor(.green)
                    }

                    Spacer()
                }
            }
            .padding()
            .navigationTitle("Export to Clipboard")
            .navigationBarTitleDisplayMode(.inline)
        } else {
            VStack(spacing: 12) {
                ForEach(errors.indices, id: \.self) { index in
                    Text("There was an error generating the JSON, please try again or report this issue: \(errors[index])")
                        .foregroundColor(.red)
                        .font(.caption)
                }
            }
        }
    }
}
