////
////  WarningBannerComponent.swift
////  URLChecker
////
////  Created by Chief Hakka on 02/04/2025.
////
//import SwiftUI
//MARK: OLD SCAR NOT READY TO DELETE YET
//struct WarningBannerComponent: View {
//    @ObservedObject var viewModel: WarningsComponentModel
//    @State private var navToGlossary = false
//    
//    var body: some View {
//        let severityCounts = viewModel.severityCounts
//        
//        if !severityCounts.isEmpty {
//            VStack(spacing: 6) {
//                Text("Warnings:")
//                    .font(.callout)
//                    .fontWeight(.semibold)
//
//                HStack(spacing: 8) {
//                    ForEach(SecurityWarning.SeverityLevel.allWarnings, id: \.self) { severity in
//                        if let count = severityCounts[severity], count > 0 {
//                            HStack(spacing: 4) {
//                                Image(systemName: severity.iconName)
//                                    .foregroundColor(severity.iconColor)
//                                Text("\(count)")
//                                    .foregroundColor(.primary)
//                            }
//                        }
//                    }
//                }
//
//                Text("Click to see details")
//                    .font(.footnote)
//                    .underline(true, color: .secondary)
//                    .foregroundColor(.secondary)
//    
//            }
//            .padding(.vertical, 12)
//            .padding(.horizontal)
//            .frame(maxWidth: .infinity)
//            .background(
//                RoundedRectangle(cornerRadius: 12, style: .continuous)
//                    .fill(.ultraThinMaterial)
//                    .shadow(color: Color.black.opacity(0.2), radius: 5, x: 0, y: 3)
//            )
//            .onTapGesture {
//                withAnimation(.easeInOut(duration: 0.15)) {
//                    viewModel.showingWarningsSheet = true
//                }
//                UIImpactFeedbackGenerator(style: .light).impactOccurred()
//            }
//            .ignoresSafeArea(edges: .bottom)
//        }
//    }
//}
