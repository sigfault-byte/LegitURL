//
//  LamaiTreeViewComponent.swift
//  URLChecker
//
//  Created by Chief Hakka on 25/03/2025.
//
import SwiftUI
import Foundation

struct LamaiTreeViewComponent: View {
    let lamaiTrees: [URLComponentsInfo.LamaiComponent: DecodedNode]
    
    var body: some View {
        List {
            ForEach(lamaiTrees.sorted(by: { $0.key.rawValue < $1.key.rawValue }), id: \.key) { key, node in
                Section(header: Text("🔍 \(key.rawValue.capitalized)")) {
                    LamaiNodeRow(node: node, indent: 0)
                }
            }
        }
        .navigationTitle("Lamai Decoding Tree")
    }
}


struct LamaiNodeRow: View {
    let node: DecodedNode
    let indent: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(String(repeating: "  ", count: indent))↳ [\(node.method ?? "raw")] \(node.value)")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundColor(.primary)

            ForEach(node.findings, id: \.self) { finding in
                Text("🔸 \(finding.shortLabel): \(node.value)")
                    .font(.system(size: 11, weight: .regular, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            ForEach(node.children, id: \.id) { child in
                LamaiNodeRow(node: child, indent: indent + 1)
            }
        }
        .padding(.vertical, 4)
    }
}
