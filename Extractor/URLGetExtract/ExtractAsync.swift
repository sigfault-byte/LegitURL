//  ExtractAsync.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//
import Foundation

// New async version of the extract function
struct URLGetExtract {
    static func extractAsync(urlInfo: URLInfo) async throws -> OnlineURLInfo {
        try await withCheckedThrowingContinuation { continuation in
            HTTPResponseExtract.extract(urlInfo: urlInfo) { onlineInfo, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let info = onlineInfo {
                    continuation.resume(returning: info)
                } else {
                    let unknownError = NSError(domain: "URLGetExtract", code: -999, userInfo: [NSLocalizedDescriptionKey: "Unknown error occurred during extract."])
                    continuation.resume(throwing: unknownError)
                }
            }
        }
    }
}
