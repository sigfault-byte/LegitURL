//
//  SecurityWarningView.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI

struct SecurityWarningsView: View {
    @ObservedObject var urlQueue: URLQueue
    @State private var showWarningsSheet: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if urlQueue.allWarnings.count >= 1 {
                Button(action: {
                    showWarningsSheet.toggle()
                }) {
                    HStack {
                        Text("⚠️ Security Warnings (\(urlQueue.allWarnings.count))")
                            .font(.headline)
                            .foregroundColor(.red)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.red)
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(.systemGray6)))
                }
                .sheet(isPresented: $showWarningsSheet) {
                    SecurityWarningsDetailView(urlQueue: urlQueue)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 0)
    }
}

struct SecurityWarningsDetailView: View {
    @ObservedObject var urlQueue: URLQueue

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(urlQueue.allWarnings, id: \.id) { warning in
                        HStack(alignment: .top, spacing: 5) {
                            Circle()
                                .fill(warning.severity.color)
                                .frame(width: 10, height: 10)
                                .padding(.top, 4)

                            Text("\(warning.message)")
                                .font(.footnote)
                                .foregroundColor(.gray)
                                .fixedSize(horizontal: false, vertical: true)
                                .multilineTextAlignment(.leading)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color(.systemGray6)))
                    }
                }
                .padding()
            }
            .navigationTitle("Security Warnings")
            .navigationBarItems(trailing: Button("Close") {
                if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                   let window = scene.windows.first,
                   let rootVC = window.rootViewController {
                    rootVC.dismiss(animated: true)
                }
            })
        }
    }
}





//struct SecurityWarningsView: View {
//    @ObservedObject var urlQueue: URLQueue
//
//    var body: some View {
//        VStack(alignment: .leading, spacing: 10) {
//            if urlQueue.allWarnings.count >= 1{
//                Text("⚠️ Security Warnings:")
//                    .font(.headline)
//                    .foregroundColor(.red)
//            }
//
//            ForEach(urlQueue.allWarnings, id: \.id) { warning in
//                HStack(alignment: .top, spacing: 5) {
//                    Circle()
//                        .fill(warning.severity.color)
//                        .frame(width: 10, height: 10)
//                        .padding(.top, 4)
//
//                    Text("\(warning.message)")
//                        .font(.footnote)
//                        .foregroundColor(.gray)
//                        .fixedSize(horizontal: false, vertical: true)
//                        .multilineTextAlignment(.leading)
//                        .frame(maxWidth: .infinity, alignment: .leading)
//                }
//                .frame(maxWidth: .infinity, alignment: .leading)
//            }
//        }
//        .frame(maxWidth: .infinity, alignment: .leading) // ✅ Ensures entire VStack is aligned
//        .padding(.horizontal, 0) // ✅ Remove any unexpected extra padding
//    }
//}
