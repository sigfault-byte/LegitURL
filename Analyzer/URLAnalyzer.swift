//  URLAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//

import Foundation

struct URLAnalyzer {
    private static var analysisStartTime: Date?
   
    public static var hasManuallyStopped = false
    public static var hasFinalized = false
    
    // MARK: - Public Entry Point
    public static func analyze(urlString: String) async {
        self.analysisStartTime = Date()
        AnalysisContextManager.reset()
        
        let extractedInfo = extractComponents(from: urlString)
        
        if extractedInfo.warnings.contains(where: { $0.severity == .critical }) {
            URLQueue.shared.offlineQueue.append(extractedInfo)
            return
        }
        
        URLQueue.shared.offlineQueue.append(extractedInfo)
        
        if shouldStopAnalysis(atIndex: 0) { return }
        
        await processQueue()
    }
    
    // MARK: - Offline Queue Processing
    
    private static func processQueue() async {
        guard !hasManuallyStopped else {
            return
        }
        
        // Check if the offline queue limit is reached
        guard URLQueue.shared.offlineQueue.count < 5 else {
            return
        }
        
        // Find the first unprocessed URLInfo
        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processed }) else {
            if hasManuallyStopped {
                return
            }
            await processOnlineQueue()
            return
        }
        
        // Process the current URLInfo and then recursively process the next one
        if processOfflineURL(at: currentIndex) {
            await processQueue()
        }
    }
    
    private static func processOfflineURL(at index: Int) -> Bool {
        
        var urlInfo = URLQueue.shared.offlineQueue[index]
        guard hasManuallyStopped == false else { return false}
        
        // Check for early exit conditions before processing
        //        if shouldStopAnalysis(atIndex: index) { return false }
        
        // Run offline analysis: Host analysis
        HostAnalysis.analyze(urlObject: &urlInfo)
        URLQueue.shared.offlineQueue[index] = urlInfo
        //        if shouldStopAnalysis(atIndex: index) { return false }
        
        // Run PQF analysis and capture any new URL generated
        let newURL = PQFAnalyzer.analyze(urlInfo: &urlInfo)
        URLQueue.shared.offlineQueue[index] = urlInfo
        if shouldStopAnalysis(atIndex: index) { return false }
        
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
    
    private static func processOnlineQueue() async {
//        let remaining = URLQueue.shared.offlineQueue.filter { !$0.processedOnline && !$0.processingNow }
//        print("Remaining URLs: \(remaining.map { $0.components.fullURL ?? "unknown" })")
        
        guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { !$0.processedOnline && !$0.processingNow }) else {
//            print("✅ All online checks complete.")
            if !hasFinalized {
                hasFinalized = true
                URLAnalyzerUtils.finalizeAnalysis()
                if let start = analysisStartTime {
                    let duration = Date().timeIntervalSince(start)
                    print("🌐 Full analyze() duration: \(String(format: "%.3f", duration)) seconds")
                }
            }
            return
        }

        if shouldStopAnalysis(atIndex: currentIndex) { return }

        let currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
        URLQueue.shared.offlineQueue[currentIndex].processingNow = true
//        print("🚀 Starting online analysis for URL:", currentURLInfo.components.fullURL ?? "unknown")
        
        if !URLQueue.shared.onlineQueue.contains(where: { $0.id == currentURLInfo.id }) {
            URLQueue.shared.onlineQueue.append(OnlineURLInfo(from: currentURLInfo))
        }

        do {
            let onlineInfo = try await URLGetExtract.extractAsync(urlInfo: currentURLInfo)
//            print("✅ Finished GET extract for:", currentURLInfo.components.fullURL ?? "unknown")
            
            
            guard let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == currentURLInfo.id }) else {
//                print("ould not find URLInfo to attach onlineInfo")
                return
            }

            let updatedURLInfo = URLQueue.shared.offlineQueue[index]
            
            //  Sync the latest onlineInfo into the onlineQueue:
            // - If this URL was already added to the onlineQueue, update its entry.
            // - If it's the first time we're processing this URL online, append it.
            // This ensures onlineQueue always contains the latest async GET results
            // without duplication or outdated versions.
            
            let onlineIndex = URLQueue.shared.onlineQueue.firstIndex(where: { $0.id == currentURLInfo.id })
            if let onlineIndex = onlineIndex {
                URLQueue.shared.onlineQueue[onlineIndex] = onlineInfo
            } else {
                URLQueue.shared.onlineQueue.append(onlineInfo)
            }
            
            URLQueue.shared.offlineQueue[index] = updatedURLInfo

            
            
            let OnlineAnalysisURLInfo = await URLGetAnalyzer.analyze(urlInfo: updatedURLInfo)
            URLQueue.shared.offlineQueue[index] = OnlineAnalysisURLInfo
//            print("✅ Online analysis complete for:", OnlineAnalysisURLInfo.components.fullURL ?? "unknown")
            URLQueue.shared.offlineQueue[index].processedOnline = true
            
            // Check if any critical finding where found
            if shouldStopAnalysis(atIndex: index) {
                return
            }

            if let finalRedirect = OnlineAnalysisURLInfo.onlineInfo?.finalRedirectURL {
                await handleFinalRedirect(from: currentURLInfo, finalRedirect: finalRedirect, responseCode: currentURLInfo.onlineInfo?.serverResponseCode ?? 0)
            }

        } catch {
//            print(" GET request failed for:", currentURLInfo.components.fullURL ?? "unknown")
            let warning = SecurityWarning(
                message: error.localizedDescription + "\nAnalysis is incomplete.",
                severity: .fetchError,
                penalty: PenaltySystem.Penalty.critical,
                url: currentURLInfo.components.coreURL ?? "",
                source: .getError
            )
            URLQueue.shared.addWarning(to: currentURLInfo.id, warning: warning)
            markURLInfoOnlineProcessed(for: currentURLInfo)
        }

        if !hasFinalized {
//            print(" Re-entering processOnlineQueue more work...")
            await processOnlineQueue()
        }
    }
    
    
    
    
    // MARK: - Utility Functions --
    
    private static func markURLInfoOnlineProcessed(for urlInfo: URLInfo) {
        if let index = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == urlInfo.id }) {
            var updated = URLQueue.shared.offlineQueue[index]
            updated.processedOnline = true
            updated.processingNow = false
            URLQueue.shared.offlineQueue[index] = updated
        }
    }
    
    private static func sanitizeAndValidate(_ urlString: String, _ infoMessage: inout String?) -> (String?, String?) {
        return LegitURLTools.sanitizeInputURL(urlString)
    }
    
    private static func extractComponents(from url: String) -> URLInfo {
        return URLExtractComponents.extract(url: url)
    }
    
    private static func shouldStopAnalysis(atIndex index: Int) -> Bool {
        let urlInfo = URLQueue.shared.offlineQueue[index]
        
        if urlInfo.warnings.contains(where: { $0.severity == .critical }) {
            URLQueue.shared.offlineQueue[index].processed = true
            URLAnalyzerUtils.finalizeAnalysis()
            hasManuallyStopped = true
            return true
            
        } else if urlInfo.warnings.contains(where: { $0.severity == .fetchError }) {
            URLQueue.shared.offlineQueue[index].processed = true
            URLAnalyzerUtils.finalizeAnalysis()
            hasManuallyStopped = true
            return true
        }
        return false
    }
    
    private static func handleFinalRedirect(from currentURLInfo: URLInfo, finalRedirect: String, responseCode: Int) async {
        guard let originalURL = currentURLInfo.components.fullURL else { return }
        if finalRedirect.lowercased() == originalURL.lowercased() { return }
        
        let alreadyQueued = URLQueue.shared.offlineQueue.contains {
            $0.components.coreURL?.lowercased() == finalRedirect.lowercased()
        }
        guard !alreadyQueued, URLQueue.shared.offlineQueue.count < 5 else { return }
        
        var dummy: String? = ""
        let (cleanedRedirectURL, _) = sanitizeAndValidate(finalRedirect, &dummy)
        guard let cleanedRedirectURL = cleanedRedirectURL else { return }
        
        var newURLInfo = extractComponents(from: cleanedRedirectURL)
//        RedirectAnalyzer.analyzeRedirect(fromInfo: currentURLInfo, toInfo: &newURLInfo, responseCode: responseCode)
        
//        print("🔁 Adding redirect URL to offline queue:", cleanedRedirectURL)
        URLQueue.shared.offlineQueue.append(newURLInfo)
        
        await processQueue()
    }
}
