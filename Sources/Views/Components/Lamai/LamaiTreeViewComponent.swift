//
//  LamaiTreeViewComponent.swift
//  LegitURL
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
                Section(header: Text("\(key.rawValue.capitalized)")) {
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
    @State private var isExpanded: Bool = true

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 6) {
                if !node.findings.isEmpty {
                    ForEach(node.findings, id: \.self) { finding in
                        HStack(alignment: .center) {
                            Text("\(finding.shortLabel): \(node.value)")
                                .font(.footnote.bold())
                                .foregroundColor(.primary)
                            Spacer()
                            Image(systemName: "exclamationmark.circle.fill")
                                .foregroundColor(.red)
                        }
                    }
                }

                ForEach(node.children, id: \.id) { child in
                    LamaiNodeRow(node: child, indent: indent + 1)
                }
            }
            .padding(.leading, 8)
            .padding(.vertical, 2)
        } label: {
            (
                Text("[")
                + Text(node.method ?? "raw")
                    .foregroundColor((node.method ?? "raw") == "raw" ? .gray : .primary)
                + Text("] \(node.value)")
            )
            .font(.system(size: 12, weight: .medium, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.tail)
            .padding(.leading, CGFloat(indent * 12))
        }
    }
}
