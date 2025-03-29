//
//  InputHomeView.swift
//  URLChecker
//
//  Created by Chief Hakka on 28/03/2025.
//

import SwiftUI

struct InputHomeView: View {
    @State private var urlInput: String = ""
    @State private var isAnalyzing: Bool = false
    @State private var errorMessage: String = ""
    @State private var infoMessage: String = ""
    @State private var didStartAnalysis = false
    
    var body: some View {
        NavigationView {
            VStack {
                // Big Title occupying 1/3 of the screen height
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
                    TextField("Enter URL", text: $urlInput)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .padding(12)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(Color(UIColor.systemGray6))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(UIColor.separator), lineWidth: 1)
                        )
                        .padding(.horizontal)
                        .onChange(of: urlInput) { _,_ in
                            errorMessage = ""
                        }
                    
                    Button(action: {
                        let (cleanedURL, message) = LegitURLTools.userInputCheck(urlInput)
                        if let finalURL = cleanedURL {
                            errorMessage = ""
                            infoMessage = message ?? ""
                            urlInput = finalURL
                            isAnalyzing = true
                        } else if let error = message {
                            errorMessage = error
                        }
                    }) {
                        Text("Check URL")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .padding(.horizontal)
                    
                    if !errorMessage.isEmpty {
                        Text(errorMessage)
                            .foregroundColor(.red)
                            .padding(.horizontal)
                    }
                }
                .padding(.vertical)
                
                Spacer()
            }
            .background(Color(UIColor.systemBackground))
            .toolbar {
                // Bottom toolbar for Home & Help
                ToolbarItemGroup(placement: .bottomBar) {
                    HStack {
                        Spacer()
                        Button("🏠 Home") {
                            LegitSessionManager.reset()
                            isAnalyzing = false
                        }
                        Spacer()
                        Button("❓ Help") {
                            // TODO: Add help logic
                        }
                        Spacer()
                    }
                }
            }
            .navigationDestination(isPresented: $isAnalyzing) {
                URLAnalysisResultView(urlInput: urlInput, infoMessage: infoMessage, isAnalyzing: $isAnalyzing)
            }
            .onAppear {
                UITextField.appearance().clearButtonMode = .whileEditing
                errorMessage = ""
            }
        }
    }
}
