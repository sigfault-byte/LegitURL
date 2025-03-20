//
//  URLAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import Foundation

struct URLAnalyzer {
    static func analyze(urlString: String, infoMessage: inout String?) {
        resetQueue()
        infoMessage = nil
        
        
        //NEED update to check wether there is at least a . and if the structure looks ok.
        let (cleanURL, message) = sanitizeAndValidate(urlString, &infoMessage)
        infoMessage = message
        
        
        guard let cleanedURL = cleanURL else { return }
        
        let extractedInfo = extractComponents(from: cleanedURL)
        
        URLQueue.shared.offlineQueue.append(extractedInfo)
        
        if shouldStopAnalysis(extractedInfo) { return }
        
        processQueue()
        
        return
    }
    
    private static func processQueue() {
        var iterations = 0
        var newURL: String?
        
        while iterations < 5 {
            // ✅ Find the first unprocessed URL
            guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processed }) else {
                print("✅ All URLs processed or queue is empty.")
                break
            }
            
            var currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
            URLQueue.shared.offlineQueue[currentIndex] = currentURLInfo
            if shouldStopAnalysis(currentURLInfo) { return }
            
            // ✅ Run offline analysis
            currentURLInfo = HostAnalyzer.analyze(urlInfo: currentURLInfo)
            URLQueue.shared.offlineQueue[currentIndex] = currentURLInfo
            if shouldStopAnalysis(currentURLInfo) { return }
            
            (currentURLInfo, newURL) = PQFAnalyzer.analyze(urlInfo: currentURLInfo)
            URLQueue.shared.offlineQueue[currentIndex] = currentURLInfo
            if shouldStopAnalysis(currentURLInfo) { return }
            
            // ✅ Handle loopback URLs
            if let newURL = newURL {
                var infoMessage: String? = ""
                let (cleanURL, _) = sanitizeAndValidate(newURL, &infoMessage)
                guard let cleanedURL = cleanURL else { return }
                let newExtractedInfo = extractComponents(from: cleanedURL)
                URLQueue.shared.offlineQueue.append(newExtractedInfo)
            }
            
            // ✅ Mark this URL as processed
            URLQueue.shared.offlineQueue[currentIndex].processed = true
            iterations += 1
        }
        
        print("✅ Offline queue complete. Starting online analysis...")
        
        processOnlineQueue()
    }
    
    private static var onlineQueueIterations = 0
    private static let maxOnlineIterations = 5 // ✅ Set a reasonable limit
    
    private static func processOnlineQueue() {
        guard onlineQueueIterations < maxOnlineIterations else {
            print("⛔ Online queue recursion limit reached. Stopping further analysis.")
            return
        }
        
        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processedOnline }) else {
            print("✅ All online checks complete.")
            return
        }
        
        let currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
        
//        if !URLQueue.shared.onlineQueue.contains(where: { $0.id == currentURLInfo.id }) {
//            URLQueue.shared.onlineQueue.append(OnlineURLInfo(from: currentURLInfo))
//        }
        
        if currentURLInfo.onlineInfo == nil {
              URLQueue.shared.onlineQueue.append(OnlineURLInfo(from: currentURLInfo))
          }
        
        onlineQueueIterations += 1 // ✅ Increment recursion counter
        
        URLGetExtract.extract(urlInfo: currentURLInfo) { onlineInfo, error in
            DispatchQueue.main.async {
                if let error = error {
                    let warning = SecurityWarning(message: error.localizedDescription, severity: .urlGetFail)
                    URLQueue.shared.addWarning(to: currentURLInfo.id, warning: warning)
                    print("❌ Error handled:", error.localizedDescription)

                    // ✅ Ensure URLInfo is updated with the warning
                    if let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == currentURLInfo.id }) {
                        var failedURLInfo = URLQueue.shared.offlineQueue[index]
                        failedURLInfo.processedOnline = true
                        URLQueue.shared.offlineQueue[index] = failedURLInfo
                    }
                    return
                }

                guard let onlineInfo = onlineInfo else {
                    print("❌ Unexpected state: no error, but also no OnlineURLInfo!")

                    // ✅ Handle missing OnlineURLInfo as an error
                    let warning = SecurityWarning(message: "Failed to retrieve online information.", severity: .urlGetFail)
                    URLQueue.shared.addWarning(to: currentURLInfo.id, warning: warning);
                    
                    if let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == currentURLInfo.id }) {
                        var failedURLInfo = URLQueue.shared.offlineQueue[index]
                        failedURLInfo.processedOnline = true
                        URLQueue.shared.offlineQueue[index] = failedURLInfo
                    }
                    return
                }

                // ✅ Process onlineInfo normally
                if let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == currentURLInfo.id }) {
                    var updatedURLInfo = URLQueue.shared.offlineQueue[index]
                    updatedURLInfo.onlineInfo = onlineInfo
                    URLGetAnalyzer.analyze(urlInfo: &updatedURLInfo)
                    URLQueue.shared.offlineQueue[index] = updatedURLInfo
                    URLQueue.shared.offlineQueue[index].processedOnline = true
                }

                processOnlineQueue()
            }
        }
    }
    
    //    //////////////////////////Utility functions/////////////////////
    
    public static func resetQueue() {
        URLQueue.shared.offlineQueue.removeAll()
        URLQueue.shared.LegitScore = 100
    }
    
    private static func sanitizeAndValidate(_ urlString: String, _ infoMessage: inout String?) -> (String?, String?) {
        return LegitURLTools.userInputCheck(urlString)
    }
    
    private static func extractComponents(from url: String) -> URLInfo {
        return URLExtractComponents.extract(url: url)
    }
    
    private static func shouldStopAnalysis(_ urlInfo: URLInfo) -> Bool {
        if urlInfo.warnings.contains(where: { $0.severity == .critical }) {
            print("❌ Critical warning found. Stopping analysis.")
            return true
        }
        else if urlInfo.warnings.contains(where: { $0.severity == .urlGetFail}){
            print(" ⚠️ URL GET request failed. Stopping analysis.")
            return true
        }
        return false
    }
}
