//
//  HelpGlossary.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
import SwiftUI

struct HelpGlossaryEntry: View {
    let term: String
    let description: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(term)
                .font(.title3)
                .fontWeight(.semibold)
                .foregroundColor(.primary)
            Divider()
            Text(description)
                .font(.body)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(Color(uiColor: .secondarySystemBackground))
        )
    }
}

struct HelpPageView: View {
    var scrollTarget: String?

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    ForEach(HelpGlossaryData.terms) { entry in
                        HelpGlossaryEntry(term: entry.term, description: entry.description)
                            .id(entry.id)
                    }
                }
                .padding()
            }
            .onAppear {
                if let keyword = scrollTarget {
                    withAnimation {
                        proxy.scrollTo(keyword, anchor: .top)
                    }
                }
            }
        }
        .navigationTitle("Help & Glossary")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#Preview {
    NavigationView {
        HelpPageView(scrollTarget: nil) // or .some("tls") to test scrolling
    }
}
