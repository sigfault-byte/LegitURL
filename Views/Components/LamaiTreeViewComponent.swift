//
//  LamaiTreeViewComponent.swift
//  URLChecker
//
//  Created by Chief Hakka on 25/03/2025.
//
import SwiftUI
import Foundation

struct LamaiTreeViewComponent: View {
    let lamaiTrees: [URLComponentsInfo.TreeType: [DecodedNode]]
    
    var body: some View {
        List {
            ForEach(lamaiTrees.sorted(by: { $0.key.rawValue < $1.key.rawValue }), id: \.key) { key, nodes in
                Section(header: Text("🔍 \(key.rawValue.capitalized)")) {
                    ForEach(nodes, id: \.id) { node in
                        LamaiNodeRow(node: node, indent: 0)
                    }
                }
            }
        }
        .navigationTitle("Lamai Decoding Tree")
    }
}


struct LamaiNodeRow: View {
    let node: DecodedNode
    let indent: Int
    @State private var isExpanded: Bool = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(node.findings, id: \.self) { finding in
                    Text("🔸 \(finding.shortLabel): \(node.value)")
                        .font(.system(size: 11, weight: .regular, design: .monospaced))
                        .foregroundColor(.orange)
                }

                ForEach(node.children, id: \.id) { child in
                    LamaiNodeRow(node: child, indent: indent + 1)
                }
            }
            .padding(.vertical, 4)
        } label: {
            Text("\(String(repeating: "  ", count: indent))↳ [\(node.method ?? "raw")] \(node.value)")
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundColor(node.method != "raw" ? .blue : .primary)
        }
    }
}
