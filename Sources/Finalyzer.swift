struct Finalyzer {
    static func computeFinalScore(for urlInfos: [URLInfo]) -> Int {
        let warnings = urlInfos.flatMap { $0.warnings }
        // let penaltyDetails = warnings.map { "Source: \($0.source) - Penalty: \($0.penalty)" }

        let totalPenalty = warnings.map { $0.penalty }.reduce(0, +)
//        let penaltyDetails = warnings.map { "Source: \($0.source) - Penalty: \($0.penalty)" }
//        penaltyDetails.forEach { print($0) }
        var newScore = 100 + totalPenalty
        if newScore < 0 {
            newScore = 0
        } else if newScore > 100 {
            newScore = 100
        }
        let score = newScore
        return score
    }

    static func finalizeAnalysis() {
        let finalScore = computeFinalScore(for: URLQueue.shared.offlineQueue)
        URLQueue.shared.legitScore.score = finalScore
        
        let grouped = groupWarningsByDomainAndSource(from: URLQueue.shared.offlineQueue.flatMap { $0.warnings })
        URLQueue.shared.groupedWarnings = grouped
        URLQueue.shared.legitScore.analysisCompleted = true
    }
    
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

            let preferredSourceOrder: [SecurityWarning.SourceType] = [
                .host, .path, .query, .fragment, .responseCode, .redirect, .cookie, .body, .tls, .header, .getError
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
