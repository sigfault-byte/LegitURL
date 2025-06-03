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
        
        //generate HTML report
        URLQueue.shared.generateAndStoreHTMLReport()
        
        
        do {
            //change logic !
            let jsonDataBrief = try generateLLMJson(from: URLQueue.shared, brief: true)
            // jason
            let jsdonFullReport = try generateLLMJson(from: URLQueue.shared, brief: false)
            
            for json in jsonDataBrief {
                
                if let jsonDataBrief = String(data: json, encoding: .utf8) {
//                    print("size: ", jsonString)
                    URLQueue.shared.jsonDataForUserLLModelBrief = jsonDataBrief
                    URLQueue.shared.jsonLenTokenEstimateLLModelBrief = (json.count, json.count / 4)
                } else {
//                    print("flied to decode JSON data to string : ((( ")
                    URLQueue.shared.internalErrorMessages.append("Failed to convert JSON data to UTF-8 string.")
                }
            }
            
            for json in jsdonFullReport {
                
                if let jsonDataBrief = String(data: json, encoding: .utf8) {
//                    print("size: ", jsonString)
                    URLQueue.shared.jsonDataForUserLLModel = jsonDataBrief
                    URLQueue.shared.jsonLenTokenEstimateLLModel = (json.count, json.count / 4)
                } else {
//                    print("flied to decode JSON data to string : ((( ")
                    URLQueue.shared.internalErrorMessages.append("Failed to convert JSON data to UTF-8 string.")

                }
            }
            
        } catch {
            let errorMessage = "Internal error during JSON generation: \(error.localizedDescription)"
//            print(errorMessage)
            URLQueue.shared.internalErrorMessages.append(errorMessage)
            // global
            URLQueue.shared.legitScore.analysisCompleted = true
        }
        
        //global
        URLQueue.shared.legitScore.analysisCompleted = true
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
