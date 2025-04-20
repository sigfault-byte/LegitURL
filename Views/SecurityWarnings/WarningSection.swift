////
////  WarningSection.swift
////  URLChecker
////
////  Created by Chief Hakka on 02/04/2025.
////
//import SwiftUI
//
//struct WarningSection: View {
//    let sourceGroup: GroupedWarningViewModel.SourceGroup
//    let sourceDescription: (SecurityWarning.SourceType) -> String
//
//    var body: some View {
//        VStack(alignment: .leading, spacing: 4) {
//            Text(sourceDescription(sourceGroup.source))
//                .font(.subheadline)
//                .bold()
//                .padding(.bottom, 2)
//
//            ForEach(sourceGroup.severities) { severityGroup in
//                SeverityGroupView(severityGroup: severityGroup)
//            }
//        }
//        .padding(.vertical, 6)
//    }
//}
//
//struct SeverityGroupView: View {
//    let severityGroup: GroupedWarningViewModel.SeverityGroup
//
//    var body: some View {
//        ForEach(Array(severityGroup.warnings), id: \.id) { (warning: SecurityWarning) in
//            HStack(alignment: .top) {
//                Image(systemName: warning.severity.iconName)
//                    .foregroundColor(warning.severity.iconColor)
//                    .frame(width: 20)
//                Text(warning.message)
//                    .font(.body)
//                    .multilineTextAlignment(.leading)
//            }
//            .padding(.bottom, 4)
//        }
//    }
//}
