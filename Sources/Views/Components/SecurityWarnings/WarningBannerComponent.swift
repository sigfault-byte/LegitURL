//
//  WarningBannerComponent.swift
//  URLChecker
//
//  Created by Chief Hakka on 02/04/2025.
//
import SwiftUI

struct WarningBannerComponent: View {
    @ObservedObject var viewModel: WarningsComponentModel

    var body: some View {
        let severityCounts = viewModel.severityCounts

        if !severityCounts.isEmpty {
            VStack {
                Spacer()
                HStack(spacing: 8) {
                    Text("Findings:")
                        .fontWeight(.medium)
                    ForEach(SecurityWarning.SeverityLevel.allWarnings, id: \.self) { severity in
                        if let count = severityCounts[severity], count > 0 {
                            HStack(spacing: 4) {
                                Image(systemName: severity.iconName)
                                    .foregroundColor(severity.iconColor)
                                Text("\(count)")
                                    .foregroundColor(.primary)
                            }
                        }
                    }
                }
                .padding(.vertical, 12)
                .padding(.horizontal)
                .frame(maxWidth: .infinity)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(.ultraThinMaterial)
                        .shadow(color: Color.black.opacity(0.2), radius: 5, x: 0, y: 3)
                )
                .onTapGesture {
                    viewModel.showingWarningsSheet = true
                }
                .ignoresSafeArea(edges: .bottom)
            }
            .sheet(isPresented: $viewModel.showingWarningsSheet) {
                WarningsDetailComponent(
                    viewModel: WarningsComponentModel(preGrouped: viewModel.grouped)
                )
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
            }
        }
    }
}
