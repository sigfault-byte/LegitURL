//
//  HotDogWaterView.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//
import SwiftUI
struct HotDogWaterView: View {
    let previews: [ScriptPreview]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
            Text("🧠 Inline Scripts")
                .font(.title2)
                .bold()
                .padding(.bottom, 8)

            ForEach(previews.indices, id: \.self) { i in
                let preview = previews[i]
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("📦 \(preview.origin?.rawValue.capitalized ?? "Unknown")")
                            .font(.headline)

                        if preview.isInline {
                            Text("inline")
                                .font(.caption)
                                .foregroundColor(.blue)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.blue.opacity(0.1))
                                .cornerRadius(5)
                        }

                        if let context = preview.context {
                            Text("🧭 \(context.rawValue)")
                                .font(.caption2)
                                .foregroundColor(.gray)
                        }
                    }

                    if let findings = preview.findings, !findings.isEmpty {
                        ForEach(findings.indices, id: \.self) { j in
                            Text("⚠️ \(findings[j].message)")
                                .font(.subheadline)
                                .foregroundColor(.orange)
                        }
                    }

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
