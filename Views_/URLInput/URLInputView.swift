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
            // 1/3 screen height
            AppHeaderView()
            .frame(maxHeight: .infinity, alignment: .center)
            .frame(height: UIScreen.main.bounds.height / 3)
            
            // input & Button Section
            URLInputForm(viewModel: viewModel) {
                    onAnalyze(viewModel.urlInput, viewModel.infoMessage)
                }
            .padding(.vertical)
            
            Spacer()
        }
        .background(Color(uiColor: .systemBackground))
        .toolbar {
            ToolbarItemGroup(placement: .bottomBar) {
                BottomToolbar(
                    lButtonIcon: "⚙️",
                    lButtonText: "Settings",
                    lButtonAction: {
                        // settings action
                    },
                    rButtonIcon: "❓",
                    rButtonText: "Help",
                    rButtonAction: {
                        // help action
                    }
                )
            }
        }
    }
}

struct AppHeaderView: View {
    var body: some View {
        Text("URLChecker")
            .font(.largeTitle)
            .fontWeight(.bold)
            .padding(.top, 40)
    }
}

struct URLInputForm: View {
    @ObservedObject var viewModel: URLInputViewModel
    var onAnalyze: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            TextField("Enter URL", text: $viewModel.urlInput)
                .keyboardType(.URL)
                .submitLabel(.go)
                .onSubmit {
                    if viewModel.analyzeURL() {
                        onAnalyze()
                    }
                }
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
                    onAnalyze()
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
    }
}
