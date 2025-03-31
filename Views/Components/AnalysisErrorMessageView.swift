//
//  AnalysisErrorMessageView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct AnalysisErrorMessageView: View{
    let error: String

    var body: some View{
        Text(error)
            .foregroundColor(.red)
    }
}
