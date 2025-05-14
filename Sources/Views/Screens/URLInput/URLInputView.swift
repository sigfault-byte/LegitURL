//
//  URLInputView.swift
//  LegitURL
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct URLInputView: View {
    let incomingURL: URL?
    @StateObject  private var viewModel = URLInputViewModel()
    @State private var showSettings = false
    @State private var showHelpPage = false
    
    var onAnalyze: (_ urlInput: String, _ infoMessage: String) -> Void
    
    var body: some View {
        NavigationStack {
            ZStack {
                Color.clear
                    .contentShape(Rectangle())
                    .onTapGesture {
                        hideKeyboard()
                    }
                
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
                .sheet(isPresented: $viewModel.showQRScanner) {
                    QRScannerComponent { scannedURL in
                        viewModel.urlInput = scannedURL
                        viewModel.showQRScanner = false
                        
                        // Trigger layout refresh
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                            viewModel.objectWillChange.send()
                        }
                    }
                }
                .buttonStyle(.bordered)
                .padding(.bottom)
                
            Spacer()
                }
            }
        .background(Color(uiColor: .systemBackground))
            .toolbar {
                ToolbarItemGroup(placement: .bottomBar) {
                    BottomToolbar(
                        lButtonIcon: "⚙️",
                        lButtonText: "Settings",
                        lButtonAction: { showSettings = true}
                        ,
                        rButtonIcon: "❓",
                        rButtonText: "Help",
                        rButtonAction: {showHelpPage = true})
                }
            }
            .navigationDestination(isPresented: $showSettings) {
                SettingView()
            }
            .onAppear {
                if let url = incomingURL {
                    viewModel.urlInput = url.absoluteString
                    if viewModel.analyzeURL() {
                        onAnalyze(viewModel.urlInput, viewModel.infoMessage)
                    }
                }
            }
        }
    }
}

extension View {
    func hideKeyboard() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    }
}

struct AppHeaderView: View {
    var body: some View {
        Text("LegitURL")
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
            HStack(spacing: 0) {
                Button(action: {
                    viewModel.pasteURLFromClipboard()
                }) {
                    Image(systemName: "doc.on.clipboard")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 20, height: 20)
                        .padding(12)
                        .foregroundColor(.white)
                        .background(Color.blue)
                }
                .frame(width: 44, height: 44)
                .clipShape(CustomCorner(radius: 8, corners: [.topLeft, .bottomLeft]))
                
                Button(action: {
                    viewModel.showQRScanner = true
                }) {
                    Image(systemName: "qrcode.viewfinder")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 20, height: 20)
                        .padding(12)
                        .foregroundColor(.white)
                        .background(Color.blue)
                }
                .frame(width: 44, height: 44)
                .clipShape(CustomCorner(radius: 0, corners: []))
                .overlay(
                    Rectangle()
                        .fill(Color.white)
                        .frame(width: 1),
                    alignment: .leading
                )
                
                TextField("Enter URL", text: $viewModel.urlInput)
                    .padding(.leading, 5)
                    .keyboardType(.URL)
                    .submitLabel(.go)
                    .onSubmit {
                        if viewModel.analyzeURL() {
                            onAnalyze()
                        }
                    }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .padding(.vertical, 10)
                    .frame(height: 44)
                    .background(
                        Color(uiColor: .systemGray6)
                            .clipShape(CustomCorner(radius: 8, corners: [.topRight, .bottomRight]))
                    )
                    .overlay(
                        CustomCorner(radius: 8, corners: [.topRight, .bottomRight])
                            .stroke(Color(uiColor: .separator), lineWidth: 1)
                    )
                    .overlay(
                        HStack {
                            Spacer()
                            if !viewModel.urlInput.isEmpty {
                                Button(action: {
                                    viewModel.urlInput = ""
                                }) {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundColor(.gray)
                                        .padding(.trailing, 8)
                                }
                                .buttonStyle(.plain)
                                .background(Color.clear)
                            }
                        }
                    )
            }
            .frame(height: 44)
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

struct CustomCorner: Shape {
    var radius: CGFloat = 8
    var corners: UIRectCorner = .allCorners
    
    func path(in rect: CGRect) -> Path {
        let path = UIBezierPath(roundedRect: rect, byRoundingCorners: corners, cornerRadii: CGSize(width: radius, height: radius))
        return Path(path.cgPath)
    }
}
