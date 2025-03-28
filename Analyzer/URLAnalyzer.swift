//
//  URLAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//

import Foundation

struct URLAnalyzer {
    
    // MARK: - Public Entry Point
    public static func analyze(urlString: String) {
        resetQueue()
        
        let extractedInfo = extractComponents(from: urlString)
        URLQueue.shared.offlineQueue.append(extractedInfo)
        
        if shouldStopAnalysis(extractedInfo, atIndex: 0) { return }
        
        processQueue()
    }
    
    // MARK: - Offline Queue Processing
    
    private static func processQueue() {
        // Check if the offline queue limit is reached
        guard URLQueue.shared.offlineQueue.count < 5 else {
            print("⛔ Offline queue limit reached. Stopping further analysis.")
            return
        }
        
        // Find the first unprocessed URLInfo
        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processed }) else {
            print("✅ All URLs processed in OfflineQueue. Now processing OnlineQueue...")
            processOnlineQueue()
            return
        }
        
        // Process the current URLInfo and then recursively process the next one
        if processOfflineURL(at: currentIndex) {
            processQueue()
        }
    }
    
    private static func processOfflineURL(at index: Int) -> Bool {
        var urlInfo = URLQueue.shared.offlineQueue[index]
        
        // Check for early exit conditions before processing
        if shouldStopAnalysis(urlInfo, atIndex: index) { return false }
        
        // Run offline analysis: Host analysis
        HostAnalysis.analyze(urlObject: &urlInfo)
        URLQueue.shared.offlineQueue[index] = urlInfo
        if shouldStopAnalysis(urlInfo, atIndex: index) { return false }
        
        // Run PQF analysis and capture any new URL generated
        let newURL = PQFAnalyzer.analyze(urlInfo: &urlInfo)
        URLQueue.shared.offlineQueue[index] = urlInfo
        if shouldStopAnalysis(urlInfo, atIndex: index) { return false }
        
        // Handle loopback/redirect URLs
        if let newURL = newURL {
            var infoMessage: String? = ""
            let (cleanURL, _) = sanitizeAndValidate(newURL, &infoMessage)
            if let cleanedURL = cleanURL {
                let newExtractedInfo = extractComponents(from: cleanedURL)
                URLQueue.shared.offlineQueue.append(newExtractedInfo)
            }
        }
        
        // Mark this URLInfo as processed
        URLQueue.shared.offlineQueue[index].processed = true
        return true
    }
    
    // MARK: - Online Queue Processing
    
    private static func processOnlineQueue() {
        // Check if the online queue limit is reached
        guard URLQueue.shared.onlineQueue.count < 5 else {
            print("⛔ Online queue limit reached. Stopping further analysis.")
            return
        }
        
        // Find the first URLInfo that hasn't been processed online
        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processedOnline && !$0.processingNow }) else {
            print("✅ All online checks complete.")
            DispatchQueue.main.async {
                URLQueue.shared.isAnalysisComplete = true
            }
            return
        }
        
        let currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
        URLQueue.shared.offlineQueue[currentIndex].processingNow = true
        
        // If there's no online info, add a placeholder to the online queue
        if currentURLInfo.onlineInfo == nil {
            URLQueue.shared.onlineQueue.append(OnlineURLInfo(from: currentURLInfo))
        }
        
        // Asynchronously extract online information
        URLGetExtract.extract(urlInfo: currentURLInfo) { onlineInfo, error in
            DispatchQueue.main.async {
                // Handle error if present
                if let error = error {
                    let warning = SecurityWarning(message: error.localizedDescription,
                                                  severity: .fetchError,
                                                  url: currentURLInfo.components.host ?? "",
                                                  source: .onlineAnalysis)
                    URLQueue.shared.addWarning(to: currentURLInfo.id, warning: warning)
                    print("❌ Error handled:", error.localizedDescription)
                    markURLInfoOnlineProcessed(for: currentURLInfo)
                    return
                }
                
                // Handle unexpected nil onlineInfo
                guard let onlineInfo = onlineInfo else {
                    print("❌ Unexpected state: no error, but also no OnlineURLInfo!")
                    let warning = SecurityWarning(message: "Failed to retrieve online information.",
                                                  severity: .fetchError,
                                                  url: currentURLInfo.components.host ?? "",
                                                  source: .onlineAnalysis)
                    URLQueue.shared.addWarning(to: currentURLInfo.id, warning: warning)
                    markURLInfoOnlineProcessed(for: currentURLInfo)
                    return
                }
                
                // Process online info normally
                if let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == currentURLInfo.id }) {
                    var updatedURLInfo = URLQueue.shared.offlineQueue[index]
                    updatedURLInfo.onlineInfo = onlineInfo
                    URLGetAnalyzer.analyze(urlInfo: &updatedURLInfo)
                    URLQueue.shared.offlineQueue[index] = updatedURLInfo
                    URLQueue.shared.offlineQueue[index].processedOnline = true
                    
                    // Check for a redirect and enqueue it if present
                    if let finalRedirect = onlineInfo.finalRedirectURL {
                        handleFinalRedirect(from: currentURLInfo, finalRedirect: finalRedirect)
                    }
                }
                
                processOnlineQueue()
            }
        }
    }
    
    private static func markURLInfoOnlineProcessed(for urlInfo: URLInfo) {
        if let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == urlInfo.id }) {
            var updated = URLQueue.shared.offlineQueue[index]
            updated.processedOnline = true
            updated.processingNow = false
            URLQueue.shared.offlineQueue[index] = updated
        }
    }
    
    // MARK: - Utility Functions
    
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
        } else if urlInfo.warnings.contains(where: { $0.severity == .fetchError}) {
            URLQueue.shared.offlineQueue[atIndex].processed = true
            print("⚠️ URL GET request failed. Stopping analysis.")
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
