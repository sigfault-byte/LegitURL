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
        
        if shouldStopAnalysis(extractedInfo, atIndex: 0) { return }
        
        processQueue()
        
        return
    }
    
    private static func processQueue() {
        if URLQueue.shared.offlineQueue.count >= 5 {
            print("⛔ Offline queue limit reached. Stopping further analysis.")
            return
        }

        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processed }) else {
            print("✅ All URLs processed in OfflineQueue. Now processing OnlineQueue...")
            processOnlineQueue()
            return
        }

        let currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
        URLQueue.shared.offlineQueue[currentIndex] = currentURLInfo
        if shouldStopAnalysis(currentURLInfo, atIndex: currentIndex) { return }

        // ✅ Run offline analysis
        var urlToAnalyze = currentURLInfo
        HostAnalysis.analyze(urlObject: &urlToAnalyze)
        URLQueue.shared.offlineQueue[currentIndex] = urlToAnalyze
        if shouldStopAnalysis(currentURLInfo, atIndex: currentIndex) { return }

        var newURL: String?
        newURL = PQFAnalyzer.analyze(urlInfo: &urlToAnalyze)
        URLQueue.shared.offlineQueue[currentIndex] = urlToAnalyze
        if shouldStopAnalysis(currentURLInfo, atIndex: currentIndex) { return }

//         ✅ Handle loopback URLs
        if let newURL = newURL {
            var infoMessage: String? = ""
            let (cleanURL, _) = sanitizeAndValidate(newURL, &infoMessage)
            guard let cleanedURL = cleanURL else { return }
            let newExtractedInfo = extractComponents(from: cleanedURL)
            URLQueue.shared.offlineQueue.append(newExtractedInfo)
        }

        // ✅ Mark this URL as processed
        URLQueue.shared.offlineQueue[currentIndex].processed = true

        // ✅ Recursively process next item
        processQueue()
    }
    
    private static func processOnlineQueue() {
        if URLQueue.shared.onlineQueue.count >= 5 {
            print("⛔ Online queue limit reached. Stopping further analysis.")
            return
        }
        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processedOnline }) else {
            print("✅ All online checks complete.")
            return
        }
        
        let currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
        
        if currentURLInfo.onlineInfo == nil {
              URLQueue.shared.onlineQueue.append(OnlineURLInfo(from: currentURLInfo))
          }
        
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
                    
                    // ✅ Check for a redirect and enqueue it
                    if let finalRedirect = onlineInfo.finalRedirectURL {
                        handleFinalRedirect(from: currentURLInfo, finalRedirect: finalRedirect)
                    }
                }

                processOnlineQueue()
            }
        }
    }
    
    //    //////////////////////////Utility functions/////////////////////
    
    public static func resetQueue() {
        URLQueue.shared.offlineQueue.removeAll()
        URLQueue.shared.onlineQueue.removeAll()
        URLQueue.shared.LegitScore = 100
    }
    
    private static func sanitizeAndValidate(_ urlString: String, _ infoMessage: inout String?) -> (String?, String?) {
        return LegitURLTools.userInputCheck(urlString)
    }
    
    private static func extractComponents(from url: String) -> URLInfo {
        return URLExtractComponents.extract(url: url)
    }
    
    private static func shouldStopAnalysis(_ urlInfo: URLInfo, atIndex: Int) -> Bool {
        if urlInfo.warnings.contains(where: { $0.severity == .critical }) {
            URLQueue.shared.offlineQueue[atIndex].processed = true
            print("❌ Critical warning found. Stopping analysis.")
            return true
        }
        else if urlInfo.warnings.contains(where: { $0.severity == .urlGetFail}){
            URLQueue.shared.offlineQueue[atIndex].processed = true
            print(" ⚠️ URL GET request failed. Stopping analysis.")
            return true
        }
        return false
    }

    private static func handleFinalRedirect(from currentURLInfo: URLInfo, finalRedirect: String) {
        guard let originalURL = currentURLInfo.components.fullURL else { return }

        if finalRedirect.lowercased() == originalURL.lowercased() { return }

        let alreadyQueued = URLQueue.shared.offlineQueue.contains {
            $0.components.fullURL?.lowercased() == finalRedirect.lowercased()
        }

        guard !alreadyQueued, URLQueue.shared.offlineQueue.count < 5 else { return }

        var dummy: String? = ""
        let (cleanedRedirectURL, _) = sanitizeAndValidate(finalRedirect, &dummy)

        guard let cleanedRedirectURL = cleanedRedirectURL else { return }

        var newURLInfo = extractComponents(from: cleanedRedirectURL)

        RedirectAnalyzer.analyzeRedirect(fromInfo: currentURLInfo, toInfo: &newURLInfo)

        print("🔁 Adding redirect URL to offline queue:", cleanedRedirectURL)
        URLQueue.shared.offlineQueue.append(newURLInfo)

        DispatchQueue.main.async {
            processQueue()
        }
    }
}
