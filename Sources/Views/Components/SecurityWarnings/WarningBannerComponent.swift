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
                // ZStack to push the chevron without pushing the icons
                ZStack {
                    HStack(spacing: 8) {
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
                    HStack {
                        Spacer()
                        Image(systemName: "chevron.up")
                            .font(.footnote)
                            .foregroundColor(.secondary)
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
                    withAnimation(.easeInOut(duration: 0.15)) {
                        viewModel.showingWarningsSheet = true
                    }
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
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
