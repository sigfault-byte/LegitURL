//
//  UserWatchListView.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/04/2025.
//

import SwiftUI
struct UserWatchlistView: View {
    @StateObject private var viewModel = UserWatchlistViewModel()

    @State private var brand = ""
    @State private var description = ""
    @State private var website = ""
    @State private var showDeleteConfirmation = false
    @State private var indexSetToDelete: IndexSet?

    var body: some View {
        VStack {
            Form {
                Section(header: Text("Add Brand")) {
                    TextField("Brand name (required)", text: $brand)
                    TextField("Description (optional)", text: $description)
                    TextField("Real Website (optional)", text: $website)

                    Button("Add to Watchlist") {
                        guard !brand.trimmingCharacters(in: .whitespaces).isEmpty else { return }

                        let cleanedWebsite = website.trimmingCharacters(in: .whitespaces)
                        let url = URL(string: cleanedWebsite.contains("://") ? cleanedWebsite : "https://\(cleanedWebsite)")
                        viewModel.add(brand, description: description.isEmpty ? nil : description, realWebsite: url)
                        brand = ""
                        description = ""
                        website = ""
                    }
                }

                Section(header: Text("Current Watchlist")) {
                    ForEach(viewModel.watchlist) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.brand.capitalized).bold()
                            if let desc = entry.description {
                                Text(desc).font(.caption).foregroundColor(.secondary)
                            }
                            if let site = entry.realWebsite {
                                Text(site.absoluteString)
                                    .font(.caption2)
                                    .foregroundColor(.blue)
                            }
                        }
                    }
                    .onDelete { indexSet in
                        indexSetToDelete = indexSet
                        showDeleteConfirmation = true
                    }
                }
            }
        }
        .navigationTitle("🛡️ Brand Watchlist")
        .confirmationDialog("Are you sure you want to delete this brand?", isPresented: $showDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if let indexSet = indexSetToDelete {
                    indexSet.map { viewModel.watchlist[$0] }.forEach(viewModel.remove)
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }
}
