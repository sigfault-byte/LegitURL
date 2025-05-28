//
//  HelpGlossary.swift
//  LegitURL
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

struct HowItWorksExplanation: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image("AppIconAsset")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 64, height: 64)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                Text("How LegitURL Works")
                    .font(.title2)
                    .fontWeight(.bold)
            }

            Text("""
Paste, type, or scan a link → tap Check.

🟥 Red – Unsafe: Treat as hostile unless you trust the sender.

🟧 Orange – Suspicious: Mixed signals. May be okay for big brands, but be cautious with unknown sites.

🟩 Green – Safe: Clean redirects, strong headers, trusted cert. Not bulletproof, but shows effort.
""")
            .font(.body)

            VStack(alignment: .leading, spacing: 8) {
                Text("Findings Legend")
                    .font(.headline)

                Label("Informational", systemImage: "info.circle").foregroundColor(.blue)
                Label("Good / Safe", systemImage: "checkmark.circle").foregroundColor(.green)
                Label("Tracking Detected", systemImage: "dot.radiowaves.left.and.right").foregroundColor(.purple)
                Label("Suspicious", systemImage: "exclamationmark.circle").foregroundColor(.orange)
                Label("Scam Detected", systemImage: "xmark.octagon").foregroundColor(Color(red: 0.6, green: 0, blue: 0.2))
                Label("Dangerous", systemImage: "exclamationmark.triangle").foregroundColor(.red)
                Label("Critical Risk", systemImage: "exclamationmark.triangle.fill").foregroundColor(Color(red: 0.4, green: 0, blue: 0))
                Label("Fetch Error / Unknown", systemImage: "questionmark.circle").foregroundColor(.black)
            }
            .font(.body)
            
            Text("""
After scanning you can inspect:
• Parsed URL components
• All findings
• Full HTTP headers & CSP view
• Cookies summary
• HTML body (up to 1.2 MB)
• Each &lt;script&gt; block (up to 3 KB)

You can also export the report as a PDF to your files, or load a custom prompt into your favorite AI to get an explanation.
""")
                .font(.body)
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(Color(uiColor: .secondarySystemBackground))
        )
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct HelpPageView: View {
    var scrollTarget: String?

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    HowItWorksExplanation()
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
