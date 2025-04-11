//
//  ToolBarComponent.swift
//  URLChecker
//
//  Created by Chief Hakka on 10/04/2025.
//
import SwiftUI

struct BottomToolbar: View {
    var lButtonIcon: String
    var lButtonText: String
    var lButtonAction: () -> Void
    
    var rButtonIcon: String
    var rButtonText: String
    var rButtonAction: () -> Void

    var body: some View {
        HStack {
            Spacer()
            Button("\(lButtonIcon) \(lButtonText)", action: lButtonAction)
            Spacer()
            Button("\(rButtonIcon) \(rButtonText)", action: rButtonAction)
            Spacer()
        }
    }
}
