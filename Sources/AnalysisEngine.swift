//  URLAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//

import Foundation

struct AnalysisEngine {
    private static var analysisStartTime: Date?
    
    public static var hasManuallyStopped = false
    public static var hasFinalized = false
    
    // MARK: - Public Entry Point
    public static func analyze(urlString: String) async {
        #if DEBUG
        self.analysisStartTime = Date()
        #endif
        AnalysisStateReset.reset()
        //        load user singletn + statics
        UserHeuristicsCache.load()
        
        let extractedInfo = extractComponents(from: urlString)
        
        if extractedInfo.warnings.contains(where: { $0.severity == .critical }) {
            URLQueue.shared.offlineQueue.append(extractedInfo)
            Finalyzer.finalizeAnalysis()
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
        HostAnalyser.analyze(urlObject: &urlInfo)
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
            if !hasFinalized {
                hasFinalized = true
                //flush singleton
                UserHeuristicsCache.flush()
                #if DEBUG
                if let beforeFinalyzing = analysisStartTime {
                    let duration = Date().timeIntervalSince(beforeFinalyzing)
                    print("----> Analysis> Before finalizing: \(String(format: "%.3f", duration)) seconds")
                }
                #endif
                Finalyzer.finalizeAnalysis()
                #if DEBUG
                if let start = analysisStartTime {
                    let duration = Date().timeIntervalSince(start)
                    print("----> Analysis> End of the pipeline, after generating HTML report, JSON exports, sorting findings, calculating score, computing possible bitFlag\nDuration: \(String(format: "%.3f", duration)) seconds")
                }
                #endif
            }
            return
        }
        
        if shouldStopAnalysis(atIndex: currentIndex) { return }
        
        let currentURLInfo = URLQueue.shared.offlineQueue[currentIndex]
        URLQueue.shared.offlineQueue[currentIndex].processingNow = true
        //        print(" Starting online analysis for URL:", currentURLInfo.components.fullURL ?? "unknown")
        
        if !URLQueue.shared.onlineQueue.contains(where: { $0.id == currentURLInfo.id }) {
            URLQueue.shared.onlineQueue.append(OnlineURLInfo(from: currentURLInfo))
        }
        
        do {
            let getSendTime = Date()
            #if DEBUG
            print("----> Analysis> Get Sent to \(currentURLInfo.components.fullURL ?? "unknown")")
            #endif
            
            let onlineInfo = try await HTTPGetCoordinator.extractAsync(urlInfo: currentURLInfo)
            
            #if DEBUG
            let htmlReceiveTime = Date()
            let duration2 = htmlReceiveTime.timeIntervalSince(getSendTime)
            print("----> Analysis> HttpGet time: \(String(format: "%.2f", duration2 * 1000)) ms")
            print("----> Analysis> Http Respond received starting analysis of the body.")
            #endif
            //            print("Finished GET extract for:", currentURLInfo.components.fullURL ?? "unknown")
            
            
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
            
            
            
            let OnlineAnalysisURLInfo = await HTTPRespAnalyzer.analyze(urlInfo: updatedURLInfo)
            URLQueue.shared.offlineQueue[index] = OnlineAnalysisURLInfo
            //            print("Online analysis complete for:", OnlineAnalysisURLInfo.components.fullURL ?? "unknown")
            URLQueue.shared.offlineQueue[index].processedOnline = true
            
            #if DEBUG
            let duration = Date().timeIntervalSince(htmlReceiveTime)
            if let html = onlineInfo.rawBody {
                let byteCount = html.count
                let sizeInKB = Double(byteCount) / 1024
                let sizeInMB = sizeInKB / 1024
                let scriptExtracted = OnlineAnalysisURLInfo.onlineInfo?.script4daUI.count
                let inline = OnlineAnalysisURLInfo.onlineInfo?.script4daUI.filter { $0.isInline }.count
                let totalInlineScriptSize = OnlineAnalysisURLInfo.onlineInfo?.script4daUI
                    .filter { $0.isInline }
                    .map { $0.size }
                    .reduce(0, +)
                let ext = onlineInfo.script4daUI.filter { !$0.isInline }.count
                print("----> Extracted and analyzed Scripts: \(scriptExtracted ?? 0)", "==>Inline: \(inline ?? 0) total: \(totalInlineScriptSize ?? 0) bytes,\n==>External \(ext)")
                print("----> Analysis> Extracted and analyzed Cookies: \(OnlineAnalysisURLInfo.onlineInfo?.cookiesForUI.count ?? 0)")
                print("----> Analysis> HTML body size: \(String(format: "%.2f", sizeInMB)) MB")
                
                print("----> Analysis> HTML analysis duration: \(String(format: "%.2f", duration * 1000)) ms")
            }
            #endif
            
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
                source: .getError,
                bitFlags: WarningFlags.FETCH_FAILED_TO_CONNECT
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
        return CommonTools.sanitizeInputURL(urlString)
    }
    
    public static func extractComponents(from url: String) -> URLInfo {
        return URLComponentExtractor.extract(url: url)
    }
    
    public static func shouldStopAnalysis(atIndex index: Int) -> Bool {
        let urlInfo = URLQueue.shared.offlineQueue[index]
        
        if urlInfo.warnings.contains(where: { $0.severity == .critical }) {
            URLQueue.shared.offlineQueue[index].processed = true
            Finalyzer.finalizeAnalysis()
            hasManuallyStopped = true
            return true
            
        } else if urlInfo.warnings.contains(where: { $0.severity == .fetchError }) {
            URLQueue.shared.offlineQueue[index].processed = true
            Finalyzer.finalizeAnalysis()
            hasManuallyStopped = true
            return true
        } /*else if urlInfo.onlineInfo?.serverResponseCode == 200 {*/
        //            return true
        //        }
        return false
    }
    
    private static func handleFinalRedirect(from currentURLInfo: URLInfo, finalRedirect: String, responseCode: Int) async {
        guard let originalURL = currentURLInfo.components.fullURL else { return }
        if finalRedirect.lowercased() == originalURL.lowercased() {
            
            return }
        
        let alreadyQueued = URLQueue.shared.offlineQueue.contains {
            $0.components.coreURL?.lowercased() == finalRedirect.lowercased()
        }
        guard !alreadyQueued, URLQueue.shared.offlineQueue.count < 5 else { return }
        
        var dummy: String? = ""
        let (cleanedRedirectURL, _) = sanitizeAndValidate(finalRedirect, &dummy)
        guard let cleanedRedirectURL = cleanedRedirectURL else { return }
        
        let newURLInfo = extractComponents(from: cleanedRedirectURL)
        
        //        print("Adding redirect URL to offline queue:", cleanedRedirectURL)
        URLQueue.shared.offlineQueue.append(newURLInfo)
        
        await processQueue()
    }
}
