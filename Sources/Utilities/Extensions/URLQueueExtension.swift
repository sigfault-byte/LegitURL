//
//  URLQueue.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//
import Foundation
extension URLQueue {
    static func updateOnlineInfo(_ info: OnlineURLInfo) {
        if let index = shared.onlineQueue.firstIndex(where: { $0.id == info.id }) {
            shared.onlineQueue[index] = info
        }
    }
    
    // Ensure safe update from the background ???
    func addWarning(to urlID: UUID, warning: SecurityWarning) {
        if let index = self.offlineQueue.firstIndex(where: { $0.id == urlID }) {
            self.offlineQueue[index].warnings.append(warning)
        } else {
    #if DEBUG
            print(" Could not find URLInfo with ID \(urlID) to add warning")
    #endif
        }
    }
    
    func allWarnings() -> [SecurityWarning] {
        return offlineQueue.flatMap { $0.warnings }
    }
    
    func hasWarning(withFlag flag: WarningFlags) -> Bool {
        return allWarnings().contains { $0.bitFlags.contains(flag) }
    }
    
    func countWarnings(withFlag flag: WarningFlags) -> Int {
        return allWarnings().filter { $0.bitFlags.contains(flag) }.count
    }
    
    func generateAndStoreHTMLReport() -> Void {
        let html = generateHTML(from: self)
        self.lastGeneratedHTML = html
    }
}

