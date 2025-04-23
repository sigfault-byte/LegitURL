//
//  HotDogWaterView.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//
import SwiftUI
struct HotDogWaterView: View {
    let previews: [ScriptPreview]
    @State private var copiedIndex: Int? = nil
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Extracted Scripts")
                    .font(.title2)
                    .bold()
                    .padding(.bottom, 8)
                
                ForEach(previews.indices, id: \.self) { index in
                    let preview = previews[index]
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text("\(preview.origin?.rawValue.capitalized ?? "Unknown")")
                                .font(.headline)
                            
                            if let context = preview.context {
                                Text("\(context.rawValue)")
                                    .font(.caption)
                                    .foregroundColor(.blue)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.blue.opacity(0.1))
                                    .cornerRadius(5)
                            }
                            Spacer()
                            Button(action: {
                                let generator = UIImpactFeedbackGenerator(style: .light)
                                generator.impactOccurred()
                                UIPasteboard.general.string = preview.contentPreview
                                copiedIndex = index
                                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                    if copiedIndex == index { copiedIndex = nil }
                                }
                            }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "doc.on.doc")
                                        .foregroundColor(.blue)
                                    if copiedIndex == index {
                                        Text("Copied!")
                                            .font(.caption)
                                            .foregroundColor(.green)
                                    }
                                }
                            }
                            .buttonStyle(.plain)
                        }
                        
                        if let findings = preview.findings, !findings.isEmpty {
                            let summarized = summarizeFindings(findings)
                            HStack {
                                ForEach(summarized.indices, id: \.self) { index in
                                    let item = summarized[index]
                                    Text("⚠️ \(item.message) x\(item.count)")
                                        .font(.subheadline)
                                        .foregroundColor(item.color)
                                }
                            }
                        }
                        Divider()
                        ScrollView(.horizontal, showsIndicators: false) {
                            Text(preview.contentPreview)
                                .font(.system(.body, design: .monospaced))
                                .padding(6)
                                .background(Color(.systemGray6))
                                .cornerRadius(6)
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(10)
                }
            }
            .padding()
        }
    }
}
