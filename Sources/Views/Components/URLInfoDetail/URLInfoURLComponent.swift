//
//  URLInfoDetailHeaderView.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct URLDetailURLComponent: View {
    var fullURL: String

    @State private var isExpanded: Bool = false

    var body: some View {
        Text(isExpanded ? fullURL : truncated(fullURL))
            .font(.callout)
            .foregroundColor(.secondary)
            .lineLimit(isExpanded ? nil : 1)
            .truncationMode(.tail)
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation {
                    isExpanded.toggle()
                }
            }
    }

    private func truncated(_ url: String) -> String {
        url.count > 60 ? String(url.prefix(60)) + "…" : url
    }
}
