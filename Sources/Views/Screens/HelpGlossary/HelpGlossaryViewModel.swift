//
//  HelpGlossaryViewModel.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/04/2025.
//
import Foundation

struct GlossaryTerm: Identifiable, Codable {
    let id: String        // used for scrollTo
    let term: String
    let description: String
}

struct HelpGlossaryData {
    static let terms: [GlossaryTerm] = {
        guard let url = Bundle.main.url(forResource: "glossary", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode([GlossaryTerm].self, from: data) else {
            #if DEBUG
            print("Glossary failed to load. Make sure jason is included in the main bundle.")
            #endif
            return []
        }
        return decoded
    }()

    static func lookup(id: String) -> String {
        terms.first(where: { $0.id == id })?.description ?? "No description available."
    }
}
