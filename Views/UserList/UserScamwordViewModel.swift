//
//  UserScamwordViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
import SwiftUI
import Combine

class UserScamwordViewModel: ObservableObject {
    @Published var scamwords: [UserScamword] = []

    init() {
        self.scamwords = UserScamwordManager.load()
    }

    func add(_ word: String, description: String? = nil) {
        let trimmed = word.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        let newItem = UserScamword(word: trimmed, description: description)
        guard !scamwords.contains(newItem) else { return }

        scamwords.append(newItem)
        save()
    }

    func remove(_ item: UserScamword) {
        scamwords.removeAll { $0.id == item.id }
        save()
    }

    func save() {
        UserScamwordManager.save(scamwords)
    }

    func reload() {
        self.scamwords = UserScamwordManager.load()
    }
}
