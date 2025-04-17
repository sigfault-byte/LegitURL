struct AnalyzeTLD {
    static func analyze(_ tld: String, urlInfo: inout URLInfo) -> Void {
        let suspiciousTLD = "." + tld.lowercased()
        
        
        if let penalty = PenaltySystem.suspiciousTLDs[suspiciousTLD] {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ The TLD '\(suspiciousTLD)' is commonly associated with suspicious domains.",
                severity: .suspicious,
                penalty: penalty,
                url: urlInfo.components.coreURL ?? "",
                source: .host
            ))
        }
    }
}
