//
//  HelpGlossaryBubbleView.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
import SwiftUI
import Foundation

struct GlossaryBubbleView: View {
    let source: SecurityWarning.SourceType

    var body: some View {
        Text(HelpGlossaryData.lookup(id: source.glossaryID))
            .font(.footnote)
            .foregroundColor(.secondary)
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color(.systemGray6))
            )
            .padding(.horizontal)
    }
}
