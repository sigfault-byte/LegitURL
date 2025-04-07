//
//  FinalAnalysisSnapshot.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//
import Foundation
class FinalAnalysisSnapshot: ObservableObject {
    @Published var id = UUID()
    @Published var url: String = ""
    @Published var domain: String = ""
    @Published var tld: String = ""
    @Published var finalScore: Int = 100
    @Published var allWarnings: [SecurityWarning] = []
    @Published var headers: ParsedHeaders?
    @Published var cert: ParsedCertificate?
    @Published var cookies: [String: String] = [:]
    @Published var statusCode: Int?
    @Published var bodySnippet: String?
    
    func populate(from info: URLInfo) {
        self.id = info.id
        self.url = info.components.fullURL ?? "n/a"
        self.domain = info.domain ?? "n/a"
        self.tld = info.tld ?? "n/a"
        self.allWarnings = info.warnings
        self.finalScore = URLQueue.shared.LegitScore
        
        if let online = info.onlineInfo {
            self.headers = online.parsedHeaders
            self.cert = online.parsedCertificate
            self.cookies = online.cookies
            self.statusCode = online.serverResponseCode
            self.bodySnippet = online.humanReadableBody
        }
    }
}
