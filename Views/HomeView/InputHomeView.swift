//
//  InputHomeView.swift
//  URLChecker
//
//  Created by Chief Hakka on 28/03/2025.
//

import SwiftUI

struct InputHomeView: View {
    var onAnalyze: (_ urlInput: String, _ infoMessage: String) -> Void
    
    @State private var urlInput: String = ""
    @State private var errorMessage: String = ""
    @State private var infoMessage: String = ""
    
    var body: some View {
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
                        let (cleanedURL, message) = LegitURLTools.sanitizeInputURL(urlInput)
                        if let finalURL = cleanedURL {
                            errorMessage = ""
                            infoMessage = message ?? ""
                            urlInput = finalURL
                            onAnalyze(urlInput, infoMessage)
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
                        Button("⚙️ Settings") {
                        }
                        Spacer()
                        Button("❓ Help") {
                            // TODO: Add help logic
                        }
                        Spacer()
                    }
                }
            }
    }
}
