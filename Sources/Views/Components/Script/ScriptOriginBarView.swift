//
//  ScriptOriginBarView.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/05/2025.
//
import SwiftUI
struct ScriptOriginBarView: View {
    let data: [String: Int]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(data.sorted(by: { $0.value > $1.value }), id: \.key) { key, value in
                HStack {
                    Text(key)
                        .font(.caption)
                        .frame(width: 100, alignment: .leading)
                    GeometryReader { geo in
                        Rectangle()
                            .fill(Color.blue.opacity(0.6))
                            .frame(width: CGFloat(value) / CGFloat(maxCount) * geo.size.width)
                            .cornerRadius(4)
                    }
                    .frame(height: 8)
                    Text("\(value)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    var maxCount: Int {
        data.values.max() ?? 1
    }
}
