//
//  WarningSummaryComponent.swift
//  LegitURL
//
//  Created by Chief Hakka on 28/05/2025.
//

import SwiftUI

struct WarningSummaryComponent: View {
    @ObservedObject var viewModel: WarningsComponentModel

    var body: some View {
        let severityCounts = viewModel.severityCounts
        
        if !viewModel.grouped.isEmpty {
            Section {
                NavigationLink(destination: WarningsDetailComponent(viewModel: viewModel)) {
                    HStack {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Security Warnings")
                                .font(.callout)
                                .bold()
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
                            Text("Tap to see full list")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(6)
                }
            }
        }
    }
}
