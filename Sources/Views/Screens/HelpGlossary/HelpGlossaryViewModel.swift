//
//  HelpGlossaryViewModel.swift
//  URLChecker
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
            //DEBUG
            print("failed to load glossary jason")
            return []
        }
        return decoded
    }()

    static func lookup(id: String) -> String {
        terms.first(where: { $0.id == id })?.description ?? "No description available."
    }
}
