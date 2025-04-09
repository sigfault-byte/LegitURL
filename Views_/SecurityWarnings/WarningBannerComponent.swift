//
//  WarningBannerComponent.swift
//  URLChecker
//
//  Created by Chief Hakka on 02/04/2025.
//
import SwiftUI

struct WarningBannerComponent: View {
    @ObservedObject var viewModel: URLAnalysisViewModel

    var body: some View {
        if viewModel.allSecurityWarningsCount > 0 {
            HStack {
                Text("⚠️ Warnings (\(viewModel.allSecurityWarningsCount))")
                    .font(.headline)
                    .foregroundColor(.red)
                    .padding(.vertical, 12)
                    .onTapGesture {
                        viewModel.showWarningsSheet()
                    }
            }
            .frame(maxWidth: .infinity)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .shadow(color: Color.black.opacity(0.2), radius: 5, x: 0, y: 3)
            )
            .sheet(isPresented: $viewModel.showingWarningsSheet) {
                WarningsDetailView(
                    viewModel: WarningsViewModel(groupedByURL: viewModel.warningsGroupedByURL)
                )
            }
        }
    }
}
