//
//  UserWatchListViewModel.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/04/2025.
//
import SwiftUI
import Combine

class UserWatchlistViewModel: ObservableObject {
    @Published var watchlist: [UserWatchlist] = []

    init() {
        self.watchlist = UserWatchlistManager.load()
    }

    func add(_ brand: String, description: String? = nil, realWebsite: URL? = nil) {
        let trimmed = brand.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        let newItem = UserWatchlist(brand: trimmed, description: description, realWebsite: realWebsite)
        guard !watchlist.contains(newItem) else { return }

        watchlist.append(newItem)
        
        save()
    }

    func remove(_ item: UserWatchlist) {
        watchlist.removeAll { $0.id == item.id }
        save()
    }

    func save() {
        UserWatchlistManager.save(watchlist)
    }

    func reload() {
        self.watchlist = UserWatchlistManager.load()
    }
}

