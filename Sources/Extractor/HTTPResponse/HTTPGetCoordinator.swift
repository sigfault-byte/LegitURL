//  ExtractAsync.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/04/2025.
//
import Foundation

// New async version of the extract function
struct HTTPGetCoordinator {
    static func extractAsync(urlInfo: URLInfo) async throws -> OnlineURLInfo {
        try await withCheckedThrowingContinuation { continuation in
            HTTPResponseExtractor.extract(urlInfo: urlInfo) { onlineInfo, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let info = onlineInfo {
                    continuation.resume(returning: info)
                } else {
                    let unknownError = NSError(domain: "HTTPGetCoordinator", code: -999, userInfo: [NSLocalizedDescriptionKey: "Unknown error occurred during extract."])
                    continuation.resume(throwing: unknownError)
                }
            }
        }
    }
}
