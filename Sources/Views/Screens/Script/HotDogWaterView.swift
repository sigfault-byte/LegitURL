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
    @State private var expandedScript: ScriptPreview? = nil
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Extracted Scripts")
                    .font(.title2)
                    .bold()
                    .padding(.bottom, 8)

                let originCounts = Dictionary(grouping: previews.map { $0.origin?.rawValue.capitalized ?? "Unknown" }) { $0 }
                    .mapValues { $0.count }

                ScriptOriginBarView(data: originCounts)
                    .padding(.bottom, 8)
                
                ForEach(previews.indices, id: \.self) { index in
                    let preview = previews[index]
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text("\(preview.origin?.rawValue ?? "Unknown")")
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
                            if preview.isInline {
                                Text("size: \(preview.size)B")
                                    .font(.caption)
                                    .foregroundColor(preview.size > 50000 ? .red : .blue)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.black.opacity(0.1))
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
                            Button(action: {
                                expandedScript = preview
                            }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "arrow.up.left.and.arrow.down.right")
                                        .foregroundColor(.blue)
                                }
                            }
                            .buttonStyle(.plain)
                        }
                        
                        if let src = preview.extractedSrc, !src.isEmpty {
                            Divider()
                            Text("Source:\n'\(src)'")
                                .font(.subheadline)
                        }
                        if let nonce = preview.nonce, !nonce.isEmpty {
                            Divider()
                            Text("Secured by nonce:\n'\(nonce)'")
                                .font(.subheadline)
                        }
                        if let sha = preview.integrity, !sha.isEmpty {
                            Divider()
                            Text("Protected by a hash ( not yet verified by LegitURL ):\n'\(sha)'")
                                .font(.subheadline)
                        }
                        if let findings = preview.findings, !findings.isEmpty {
                            let summarized = summarizeFindings(findings)
//                            Doestn work when there are many eement. Need  a custom component....
//                            HStack {
                                ForEach(summarized.indices, id: \.self) { index in
                                    let item = summarized[index]
                                    Text(item.count > 1 ? "\(item.message) x\(item.count)" : item.message)
                                        .font(.subheadline)
                                        .foregroundColor(item.color)
                                }
//                            }
                        }
                        
                        
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(10)
                }
            }
            .padding()
            .sheet(item: $expandedScript) { script in
                ScrollView {
                    Text(script.contentPreview)
                        .font(.system(.body, design: .monospaced))
                        .padding()
                }
            }
        }
    }
}
