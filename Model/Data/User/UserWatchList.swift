//
//  UserWatchDefinitions.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
import Foundation

struct UserWatchlist: Identifiable, Codable, Equatable {
    var id = UUID()
    var brand: String
    var description: String?
    var realWebsite: URL?

    var normalizedBrand: String {
        brand.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}

struct UserScamword: Identifiable, Codable, Equatable {
    var id = UUID()
    var word: String
    var description: String?

    var normalized: String {
        word.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}

class UserWatchlistManager {
    private static let storageKey = "userWatchlist"
    
    static func load() -> [UserWatchlist] {
        guard let data = UserDefaults.standard.data(forKey: storageKey),
              let decoded = try? JSONDecoder().decode([UserWatchlist].self, from: data) else {
            return []
        }
        return decoded
    }
    
    static func save(_ list: [UserWatchlist]) {
        if let encoded = try? JSONEncoder().encode(list) {
            UserDefaults.standard.set(encoded, forKey: storageKey)
        }
    }
}

class UserScamwordManager {
    private static let storageKey = "userScamwords"

    static func load() -> [UserScamword] {
        guard let data = UserDefaults.standard.data(forKey: storageKey),
              let decoded = try? JSONDecoder().decode([UserScamword].self, from: data) else {
            return []
        }
        return decoded
    }

    static func save(_ list: [UserScamword]) {
        if let encoded = try? JSONEncoder().encode(list) {
            UserDefaults.standard.set(encoded, forKey: storageKey)
        }
    }
}
