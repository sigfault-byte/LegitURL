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
    
    var body: some View {
        VStack {
            VStack {
                Text("URLChecker")
                    .font(.largeTitle)
                    .bold()
                    .padding(.top, 40)
            }
            .frame(maxHeight: .infinity, alignment: .center)
            .frame(height: UIScreen.main.bounds.height / 3)
            
            VStack {
                TextField("Enter URL", text: $urlInput)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .autocorrectionDisabled(true)
                    .textInputAutocapitalization(.never)
                    .padding()
                    .onChange(of: urlInput) { _, _ in
                        errorMessage = ""
                    }
                
                Button(action: {
                    let (cleanedURL, message) = LegitURLTools.userInputCheck(urlInput)
                    
                    if let finalURL = cleanedURL {
                        errorMessage = ""
                        infoMessage = message ?? ""   // ✅ populate info message here
                        urlInput = finalURL
                        isAnalyzing = true
                    } else if let error = message {
                        errorMessage = error
                    }
                }) {
                    Text("Check URL")
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(8)
                }
                .padding()
                
                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .foregroundColor(.red)
                        .padding()
                }
                
                Spacer()
                
                //----------------------------------MENU-------------------------------------------
                HStack {
                    Spacer()
                    Button("🏠 Home") {
                        LegitSessionManager.reset()           // Optional: reset your shared data
                        isAnalyzing = false
                    }
                    Spacer()
                    Button("❓ Help") {
                        // TODO: Add help logic
                    }
                    Spacer()
                }
                .padding()
                //            ---------------------END MENU--------------------------------------------
            }
            .border(Color.gray)
            .frame(maxHeight: .infinity)
        }
        .navigationDestination(isPresented: $isAnalyzing) {
            URLAnalysisResultView(urlInput: urlInput, infoMessage: infoMessage, isAnalyzing: $isAnalyzing)
        }
        .onAppear {
            UITextField.appearance().clearButtonMode = .whileEditing
            errorMessage = ""
        }
    }
    
    private func isValidURL(_ url: String) -> Bool {
        guard let url = URL(string: url) else { return false }
        return UIApplication.shared.canOpenURL(url)
    }
}

//struct InputHomeView_Previews: PreviewProvider {
//    static var previews: some View {
//        InputHomeView()
//    }
//}
