struct Finalyzer {
    static func computeFinalScore(for urlInfos: [URLInfo]) -> Int {
        let warnings = urlInfos.flatMap { $0.warnings }
        
        let totalPenalty = warnings.map { $0.penalty }.reduce(0, +)
        #if DEBUG
        let penaltyDetails = warnings.map { "Source: \($0.source) - Penalty: \($0.penalty) - Message: \($0.message)" }
        penaltyDetails.forEach { print($0) }
        #endif
        let currentScore = URLQueue.shared.legitScore.score
        var newScore = currentScore + totalPenalty
        if newScore < 0 {
            newScore = 0
        } else if newScore > 100 {
            newScore = 100
        }
        let score = newScore
        return score
    }

    static func finalizeAnalysis() {
        // Check for critical warnings first
        let criticalWarnings = URLQueue.shared.offlineQueue
            .flatMap { $0.warnings }
            .filter { $0.severity == .critical || $0.severity == .fetchError }
        var specialFlags: SpecialFlags = []

        if let firstCritical = criticalWarnings.first {
            URLQueue.shared.summary = firstCritical.message
            if firstCritical.bitFlags.contains(.FETCH_FAILED_TO_CONNECT) {
                specialFlags.insert(.fetchFailure)
            }
        } else {
            let (combo, flags) = ComboAlert.computeBitFlagAndInfer(from: URLQueue.shared.offlineQueue)
            specialFlags = flags
            if let message = combo.message, message != "" {
                URLQueue.shared.summary = message
            }
        }

        URLQueue.shared.legitScore.specialFlag = specialFlags
        
        let finalScore = computeFinalScore(for: URLQueue.shared.offlineQueue)
        URLQueue.shared.legitScore.score = finalScore
        
        let grouped = groupWarningsByDomainAndSource(from: URLQueue.shared.offlineQueue.flatMap { $0.warnings })
        URLQueue.shared.groupedWarnings = grouped
        URLQueue.shared.legitScore.analysisCompleted = true
        let _ = URLQueue.shared.generateAndStoreHTMLReport()
        do {
            let jsonData = try generateLLMJson(from: URLQueue.shared)
            // You can print, store, or debug it here
            for json in jsonData {
                
                if let jsonString = String(data: json, encoding: .utf8) {
                    print(jsonString)
                } else {
                    print("Failed to decode JSON data to string")
                }
                print("JSON SIZE: \(json.count) bytes (approx. \(json.count / 4) tokens)")
            }
        } catch {
            print("error generating compact JSON: \(error)")
        }
    }
    
    
    
    
    
    //MARK: PReparung the warning grouping for the view
    static func groupWarningsByDomainAndSource(from warnings: [SecurityWarning]) -> [WarningDomainGroup] {
        var domainGroups: [String: [SecurityWarning]] = [:]
        var domainOrder: [String] = []

        for warning in warnings {
            let domain = warning.url
            if domainGroups[domain] == nil {
                domainOrder.append(domain)
            }
            domainGroups[domain, default: []].append(warning)
        }

        return domainOrder.compactMap { domain in
            guard let warnings = domainGroups[domain] else { return nil }

            let groupedBySource = Dictionary(grouping: warnings, by: { $0.source })

//            Order for the view display
            let preferredSourceOrder: [SecurityWarning.SourceType] = [
                .host, .path, .query, .fragment, .responseCode, .cookie, .body, .tls, .header, .redirect , .getError
            ]
            
            let sourceGroups: [WarningSourceGroup] = preferredSourceOrder.compactMap { preferred in
                let matchingSources = groupedBySource.keys.filter { $0.normalizedType == preferred }

                let warningsForThisGroup = matchingSources.flatMap { groupedBySource[$0] ?? [] }
                guard !warningsForThisGroup.isEmpty else { return nil }

                let groupedBySeverity = Dictionary(grouping: warningsForThisGroup, by: { $0.severity })
                return WarningSourceGroup(source: preferred, severityMap: groupedBySeverity)
            }

            return WarningDomainGroup(domain: domain, sources: sourceGroups)
        }
    }
}
