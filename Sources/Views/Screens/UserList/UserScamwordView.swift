//
//  UserScamwordView.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/04/2025.
//
import SwiftUI

struct UserScamwordView: View {
    @StateObject private var viewModel = UserScamwordViewModel()

    @State private var word = ""
    @State private var description = ""
    @State private var showDeleteConfirmation = false
    @State private var indexSetToDelete: IndexSet?

    var body: some View {
        VStack {
            Form {
                Section(header: Text("Add Scam Word")) {
                    TextField("Scam word (required)", text: $word)
                    TextField("Description (optional)", text: $description)

                    Button("Add to Scam Watchlist") {
                        guard !word.trimmingCharacters(in: .whitespaces).isEmpty else { return }

                        viewModel.add(word, description: description.isEmpty ? nil : description)
                        word = ""
                        description = ""
                    }
                }

                Section(header: Text("Current Scam Words")) {
                    ForEach(viewModel.scamwords) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.word.capitalized).bold()
                            if let desc = entry.description {
                                Text(desc).font(.caption).foregroundColor(.secondary)
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
        .navigationTitle("🚨 Scam Word Watchlist")
        .confirmationDialog("Are you sure you want to delete this scam word?", isPresented: $showDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if let indexSet = indexSetToDelete {
                    indexSet.map { viewModel.scamwords[$0] }.forEach(viewModel.remove)
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }
}
