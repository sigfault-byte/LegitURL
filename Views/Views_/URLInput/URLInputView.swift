//
//  URLInputView.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct URLInputView: View {
    @StateObject  private var viewModel = URLInputViewModel()
    var onAnalyze: (_ urlInput: String, _ infoMessage: String) -> Void
    
    var body: some View {
        VStack {
            // Big Title (1/3 screen height)
            VStack {
                Text("URLChecker")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    .padding(.top, 40)
            }
            .frame(maxHeight: .infinity, alignment: .center)
            .frame(height: UIScreen.main.bounds.height / 3)
            
            // Input & Button Section
            VStack(spacing: 16) {
                TextField("Enter URL", text: $viewModel.urlInput)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .padding(12)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color(uiColor: .systemGray6))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(uiColor: .separator), lineWidth: 1)
                    )
                    .padding(.horizontal)
                
                Button(action: {
                    if viewModel.analyzeURL() {
                        onAnalyze(viewModel.urlInput, viewModel.infoMessage)
                    }
                }) {
                    Text("Check URL")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .padding(.horizontal)
                .disabled(!viewModel.isInputValid)
                
                if !viewModel.errorMessage.isEmpty {
                    Text(viewModel.errorMessage)
                        .foregroundColor(.red)
                        .padding(.horizontal)
                }
            }
            .padding(.vertical)
            
            Spacer()
        }
        .background(Color(uiColor: .systemBackground))
        .toolbar {
            ToolbarItemGroup(placement: .bottomBar) {
                HStack {
                    Spacer()
                    Button("⚙️ Settings") {
                        // Add settings action
                    }
                    Spacer()
                    Button("❓ Help") {
                        // Add help action
                    }
                    Spacer()
                }
            }
        }
    }
}
